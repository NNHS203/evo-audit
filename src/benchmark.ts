import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { initWorkspace, runAudit } from "./core.js";
import { ModelRegistry } from "./models.js";
import { executeWorkerTask } from "./worker-runner.js";
import { mergeWorkerResult } from "./workers.js";
import type { AuditModelConfig, AuditRun, Finding } from "./types.js";

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
  code: string;
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
    if (parsed.schemaVersion !== 1 || !parsed.caseId || typeof parsed.code !== "string" || !parsed.expected) throw new Error(`Invalid benchmark case: ${entry.name}`);
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

async function runCase(item: BenchmarkCase, options: BenchmarkOptions = {}): Promise<BenchmarkCaseResult> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "evo-audit-benchmark-"));
  try {
    await initWorkspace(root);
    const sourceFile = sourceFileFor(item);
    await fs.mkdir(path.dirname(path.join(root, sourceFile)), { recursive: true });
    await fs.writeFile(path.join(root, sourceFile), item.code, "utf8");
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
  for (const item of cases) results.push(await runCase(item, options));
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
