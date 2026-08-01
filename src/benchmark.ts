import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { initWorkspace, runAudit } from "./core.js";
import { ModelRegistry } from "./models.js";
import { executeWorkerTask } from "./worker-runner.js";
import { mergeWorkerResult } from "./workers.js";
import { applyValidationResult, createValidationRequest } from "./validator.js";
import { runValidationRequest } from "./validation-runner.js";
import type { AuditModelConfig, AuditRun, Finding, ValidationResult } from "./types.js";

export interface BenchmarkExpected {
  vulnerable?: boolean;
  ruleId?: string;
  obligationKind?: string;
  minimumReportableEvidence?: string;
  mustNotClaimSafeFromNoMatch?: boolean;
}

export interface BenchmarkCase {
  schemaVersion: 1;
  caseId: string;
  split: string;
  language: string;
  file?: string;
  code?: string;
  files?: Array<{ path: string; code: string }>;
  source?: {
    kind: "CHECKOUT";
    path: string;
    repository?: string;
    commit?: string;
  };
  validation?: {
    findingRuleId?: string;
    reproducerCommand: string;
    negativeControlCommand: string;
    timeoutMs?: number;
    image?: string;
  };
  property: string;
  expected: BenchmarkExpected;
  negativeControls?: string[];
  notes?: string[];
}

export interface BenchmarkCaseResult {
  caseId: string;
  split: string;
  expectedVulnerable: boolean;
  expectedRuleId?: string;
  candidateFound: boolean;
  matchingCandidate: boolean;
  falsePositive: boolean;
  reportableFinding: boolean;
  unsupportedClaim: boolean;
  findings: Array<Pick<Finding, "ruleId" | "status" | "evidenceTier" | "locations">>;
  coverageUnknown: boolean;
  tokenTotal: number;
  durationMs: number;
  sourceKind: "INLINE" | "CHECKOUT";
  sourceRevision?: string;
  sourceTreeDigest: string;
  validationOutcome?: ValidationResult["outcome"];
  runId: string;
}

export interface BenchmarkAcceptancePolicy {
  minCandidateRecall?: number;
  minCandidatePrecision?: number;
  maxFalsePositiveRate?: number;
  maxUnknownCoverageRate?: number;
  minReportableRecall?: number;
  maxUnsupportedClaimRate?: number;
}

export interface BenchmarkAcceptance {
  accepted: boolean;
  policy: BenchmarkAcceptancePolicy;
  failures: string[];
}

export interface BenchmarkOptions {
  model?: string;
  modelConfig?: AuditModelConfig;
  maxModelTasks?: number;
  manifestPath?: string;
  validate?: boolean;
}

export interface BenchmarkManifest {
  schemaVersion: 1;
  benchmarkVersion: string;
  cases: Array<{ file: string; caseId: string; split: string; sha256: string }>;
  notes?: string[];
}

export interface BenchmarkReport {
  schemaVersion: 1;
  generatedAt: string;
  split: string | "ALL";
  cases: BenchmarkCaseResult[];
  metrics: {
    cases: number;
    expectedVulnerable: number;
    candidateRecall: number;
    candidatePrecision: number;
    falsePositiveRate: number;
    matchingCandidateRecall: number;
    reportableRecall: number;
    validatedFindingRate: number;
    unsupportedClaimRate: number;
    unknownCoverageRate: number;
    tokensPerCase: number;
    tokensPerValidatedFinding: number | null;
    durationMsPerCase: number;
  };
  notes: string[];
}

function expectedVulnerable(expected: BenchmarkExpected): boolean {
  return expected.vulnerable !== false;
}

function sourceFileFor(item: BenchmarkCase): string {
  if (item.file) return item.file;
  if (/typescript|tsx/i.test(item.language)) return "src/entry.ts";
  return "src/entry.js";
}

async function loadCases(directory: string): Promise<BenchmarkCase[]> {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const cases: BenchmarkCase[] = [];
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const parsed = JSON.parse(await fs.readFile(path.join(directory, entry.name), "utf8")) as BenchmarkCase;
    const hasInlineSource = typeof parsed.code === "string" || (Array.isArray(parsed.files) && parsed.files.length > 0);
    const hasCheckoutSource = parsed.source?.kind === "CHECKOUT" && typeof parsed.source.path === "string" && typeof parsed.source.commit === "string" && /^[a-f0-9]{40,64}$/i.test(parsed.source.commit);
    if (parsed.schemaVersion !== 1 || !parsed.caseId || (!hasInlineSource && !hasCheckoutSource) || !parsed.expected) throw new Error(`Invalid benchmark case: ${entry.name}`);
    cases.push(parsed);
  }
  return cases.sort((left, right) => left.caseId.localeCompare(right.caseId));
}

async function verifyBenchmarkManifest(casesDirectory: string, cases: BenchmarkCase[], manifestPath: string): Promise<void> {
  const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8")) as BenchmarkManifest;
  if (manifest.schemaVersion !== 1 || !manifest.benchmarkVersion || !Array.isArray(manifest.cases)) throw new Error(`Invalid benchmark manifest: ${manifestPath}`);
  if (manifest.cases.length !== cases.length) throw new Error(`Benchmark manifest case count does not match ${casesDirectory}.`);
  const manifestDir = path.dirname(path.resolve(manifestPath));
  const seen = new Set<string>();
  for (const entry of manifest.cases) {
    if (!entry.file || !entry.caseId || !entry.split || !/^[a-f0-9]{64}$/i.test(entry.sha256)) throw new Error(`Invalid benchmark manifest entry for ${entry.caseId ?? "unknown"}.`);
    if (seen.has(entry.caseId)) throw new Error(`Duplicate benchmark manifest case: ${entry.caseId}`);
    seen.add(entry.caseId);
    const file = path.resolve(manifestDir, entry.file);
    if (file !== manifestDir && !file.startsWith(`${manifestDir}${path.sep}`)) throw new Error(`Benchmark manifest escapes its directory: ${entry.file}`);
    const parsed = JSON.parse(await fs.readFile(file, "utf8")) as BenchmarkCase;
    const actual = createHash("sha256").update(await fs.readFile(file)).digest("hex");
    if (actual.toLowerCase() !== entry.sha256.toLowerCase()) throw new Error(`Benchmark case hash mismatch: ${entry.file}`);
    if (parsed.caseId !== entry.caseId || parsed.split !== entry.split) throw new Error(`Benchmark manifest metadata mismatch: ${entry.file}`);
    if (!cases.some((item) => item.caseId === entry.caseId)) throw new Error(`Benchmark manifest references an unselected case: ${entry.caseId}`);
  }
}

function safeRelative(value: string): string {
  const normalized = value.split(path.sep).join("/").replace(/^\.\//, "");
  if (!normalized || normalized.startsWith("../") || normalized.includes("/../") || path.posix.isAbsolute(normalized)) throw new Error(`Benchmark source path escapes the case root: ${value}`);
  return normalized;
}

async function copyCheckout(sourceRoot: string, targetRoot: string): Promise<void> {
  const ignoredDirectories = new Set([".git", "node_modules", "dist", "build", "coverage", "audit-runs"]);
  const ignoredFiles = new Set(["audit.config.json", "audit.playbook.json", "audit.models.json", "audit.threat.json"]);
  const walk = async (current: string, relativeRoot: string): Promise<void> => {
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      if (ignoredFiles.has(entry.name)) continue;
      const relative = relativeRoot ? path.join(relativeRoot, entry.name) : entry.name;
      if (entry.isDirectory()) {
        if (ignoredDirectories.has(entry.name)) continue;
        await walk(path.join(current, entry.name), relative);
        continue;
      }
      const destination = path.join(targetRoot, relative);
      await fs.mkdir(path.dirname(destination), { recursive: true });
      await fs.copyFile(path.join(current, entry.name), destination);
    }
  };
  await walk(sourceRoot, "");
}

function checkoutRevision(sourceRoot: string, expected?: string): string | undefined {
  if (!expected) return undefined;
  let actual: string;
  try {
    actual = execFileSync("git", ["-C", sourceRoot, "rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    throw new Error(`Benchmark checkout is not a readable git worktree: ${sourceRoot}`);
  }
  if (actual !== expected) throw new Error(`Benchmark checkout revision mismatch: expected ${expected}, got ${actual}.`);
  return actual;
}

async function materializeCase(root: string, item: BenchmarkCase, casesDirectory: string): Promise<string | undefined> {
  if (item.source?.kind === "CHECKOUT") {
    const sourceRoot = path.resolve(casesDirectory, item.source.path);
    const revision = checkoutRevision(sourceRoot, item.source.commit);
    await copyCheckout(sourceRoot, root);
    return revision;
  }
  if (item.files && item.files.length > 0) {
    for (const file of item.files) {
      const relative = safeRelative(file.path);
      const target = path.join(root, relative);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, file.code, "utf8");
    }
    return undefined;
  }
  const sourceFile = sourceFileFor(item);
  await fs.mkdir(path.dirname(path.join(root, sourceFile)), { recursive: true });
  await fs.writeFile(path.join(root, sourceFile), item.code ?? "", "utf8");
  return undefined;
}

async function runCase(item: BenchmarkCase, casesDirectory: string, options: BenchmarkOptions = {}): Promise<BenchmarkCaseResult> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "evo-audit-benchmark-"));
  try {
    const sourceRevision = await materializeCase(root, item, casesDirectory);
    await initWorkspace(root);
    const startedAt = Date.now();
    const initial = await runAudit(root, { output: path.join(root, "runs") });
    let run = initial.run;
    if (options.model) {
      if (!options.modelConfig) throw new Error("A model config is required for model-backed benchmark runs.");
      const registry = new ModelRegistry(options.modelConfig);
      const cacheDirectory = path.join(root, "runs", "worker-cache");
      const limit = Math.max(1, Math.min(64, Math.floor(options.maxModelTasks ?? 32)));
      const tasks = (run.plan?.tasks ?? [])
        .filter((task) => ["HUNT", "INVESTIGATE"].includes(task.phase) && task.status === "PENDING")
        .sort((left, right) => right.priority - left.priority || left.id.localeCompare(right.id))
        .slice(0, limit);
      for (const task of tasks) {
        const result = await executeWorkerTask(run, task, registry, options.model, { cacheDirectory });
        run = mergeWorkerResult(run, result);
      }
    }
    let validationOutcome: ValidationResult["outcome"] | undefined;
    if (options.validate && item.validation) {
      const finding = run.findings.find((candidate) => !item.validation?.findingRuleId || candidate.ruleId === item.validation.findingRuleId);
      if (finding) {
        const request = createValidationRequest(run, finding, {
          reproducerCommand: item.validation.reproducerCommand,
          negativeControlCommand: item.validation.negativeControlCommand,
          timeoutMs: item.validation.timeoutMs,
        });
        const validation = await runValidationRequest(run, { ...request, image: item.validation.image }, "evo-audit-benchmark-validator");
        run = applyValidationResult(run, validation).run;
        validationOutcome = validation.outcome;
      }
    }
    const durationMs = Math.max(0, Date.now() - startedAt);
    const vulnerable = expectedVulnerable(item.expected);
    const candidateFound = run.findings.length > 0;
    const matchingCandidate = item.expected.ruleId
      ? run.findings.some((finding) => finding.ruleId === item.expected.ruleId)
      : candidateFound;
    const reportableIds = new Set(run.reportableFindingIds ?? []);
    const reportableFinding = run.findings.some((finding) => reportableIds.has(finding.id) && (!item.expected.ruleId || finding.ruleId === item.expected.ruleId));
    const unsupportedClaim = run.findings.some((finding) => finding.status === "VERIFIED" && finding.evidenceTier !== "T2_REPRODUCIBLE");
    return {
      caseId: item.caseId,
      split: item.split,
      expectedVulnerable: vulnerable,
      expectedRuleId: item.expected.ruleId,
      candidateFound,
      matchingCandidate,
      falsePositive: !vulnerable && candidateFound,
      reportableFinding,
      unsupportedClaim,
      findings: run.findings.map(({ ruleId, status, evidenceTier, locations }) => ({ ruleId, status, evidenceTier, locations })),
      coverageUnknown: run.plan?.tasks.some((task) => task.phase === "HUNT" && task.status !== "COMPLETED") ?? true,
      tokenTotal: run.tokenAccounting.inputTokens + run.tokenAccounting.outputTokens,
      durationMs,
      sourceKind: item.source ? "CHECKOUT" : "INLINE",
      sourceRevision,
      sourceTreeDigest: run.snapshot.treeDigest,
      validationOutcome,
      runId: run.runId,
    };
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

export async function runBenchmark(directory: string, split?: string, options: BenchmarkOptions = {}): Promise<BenchmarkReport> {
  const allCases = await loadCases(directory);
  if (options.manifestPath) await verifyBenchmarkManifest(directory, allCases, options.manifestPath);
  const cases = allCases.filter((item) => !split || item.split === split);
  if (cases.length === 0) throw new Error(`No benchmark cases found${split ? ` for split ${split}` : ""}.`);
  const results: BenchmarkCaseResult[] = [];
  for (const item of cases) results.push(await runCase(item, directory, options));
  const expected = results.filter((item) => item.expectedVulnerable);
  const reported = results.filter((item) => item.candidateFound);
  const matching = expected.filter((item) => item.matchingCandidate);
  const falsePositives = results.filter((item) => item.falsePositive);
  const unknown = results.filter((item) => item.coverageUnknown);
  const safeDenominator = results.length - expected.length;
  const tokenTotal = results.reduce((sum, item) => sum + item.tokenTotal, 0);
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    split: split ?? "ALL",
    cases: results,
    metrics: {
      cases: results.length,
      expectedVulnerable: expected.length,
      candidateRecall: expected.length === 0 ? 1 : matching.length / expected.length,
      candidatePrecision: reported.length === 0 ? 1 : (reported.length - falsePositives.length) / reported.length,
      falsePositiveRate: safeDenominator <= 0 ? 0 : falsePositives.length / safeDenominator,
      matchingCandidateRecall: expected.length === 0 ? 1 : matching.length / expected.length,
      reportableRecall: expected.length === 0 ? 1 : expected.filter((item) => item.reportableFinding).length / expected.length,
      validatedFindingRate: reported.length === 0 ? 0 : reported.filter((item) => item.reportableFinding).length / reported.length,
      unsupportedClaimRate: results.length === 0 ? 0 : results.filter((item) => item.unsupportedClaim).length / results.length,
      unknownCoverageRate: results.length === 0 ? 0 : unknown.length / results.length,
      tokensPerCase: tokenTotal / results.length,
      tokensPerValidatedFinding: results.filter((item) => item.reportableFinding).length === 0 ? null : tokenTotal / results.filter((item) => item.reportableFinding).length,
      durationMsPerCase: results.reduce((sum, item) => sum + item.durationMs, 0) / results.length,
    },
    notes: [
      "This runner measures deterministic candidate discovery; it does not claim production vulnerability recall.",
      "A candidate is not a reportable finding until independent validation supplies reproducible evidence.",
      ...(options.model ? [`Model-backed worker mode: ${options.model}; validator execution is still required for reportable evidence.`] : []),
      ...(options.validate ? ["Benchmark validator mode was requested; BLOCKED means the isolated runtime or reproducer was unavailable, not safe."] : []),
      "Holdout cases must not be used to tune detectors, prompts, or model routing.",
    ],
  };
}

function metricFailure(name: string, actual: number, comparator: "min" | "max", threshold: number): string | null {
  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1) throw new Error(`${name} threshold must be between 0 and 1.`);
  const passed = comparator === "min" ? actual >= threshold : actual <= threshold;
  return passed ? null : `${name}=${actual.toFixed(3)} violates ${comparator}=${threshold.toFixed(3)}`;
}

export function evaluateBenchmark(report: BenchmarkReport, policy: BenchmarkAcceptancePolicy = {}): BenchmarkAcceptance {
  const failures = [
    policy.minCandidateRecall === undefined ? null : metricFailure("candidateRecall", report.metrics.candidateRecall, "min", policy.minCandidateRecall),
    policy.minCandidatePrecision === undefined ? null : metricFailure("candidatePrecision", report.metrics.candidatePrecision, "min", policy.minCandidatePrecision),
    policy.maxFalsePositiveRate === undefined ? null : metricFailure("falsePositiveRate", report.metrics.falsePositiveRate, "max", policy.maxFalsePositiveRate),
    policy.maxUnknownCoverageRate === undefined ? null : metricFailure("unknownCoverageRate", report.metrics.unknownCoverageRate, "max", policy.maxUnknownCoverageRate),
    policy.minReportableRecall === undefined ? null : metricFailure("reportableRecall", report.metrics.reportableRecall, "min", policy.minReportableRecall),
    policy.maxUnsupportedClaimRate === undefined ? null : metricFailure("unsupportedClaimRate", report.metrics.unsupportedClaimRate, "max", policy.maxUnsupportedClaimRate),
  ].filter((failure): failure is string => failure !== null);
  return { accepted: failures.length === 0, policy, failures };
}
