import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { initWorkspace, runAudit } from "./core.js";
import type { AuditRun, Finding } from "./types.js";

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
  findings: Array<Pick<Finding, "ruleId" | "status" | "evidenceTier" | "locations">>;
  coverageUnknown: boolean;
  tokenTotal: number;
  runId: string;
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
    unknownCoverageRate: number;
    tokensPerCase: number;
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

async function runCase(item: BenchmarkCase): Promise<BenchmarkCaseResult> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "evo-audit-benchmark-"));
  try {
    await initWorkspace(root);
    const sourceFile = sourceFileFor(item);
    await fs.mkdir(path.dirname(path.join(root, sourceFile)), { recursive: true });
    await fs.writeFile(path.join(root, sourceFile), item.code, "utf8");
    const result = await runAudit(root, { output: path.join(root, "runs") });
    const vulnerable = expectedVulnerable(item.expected);
    const candidateFound = result.run.findings.length > 0;
    const matchingCandidate = item.expected.ruleId
      ? result.run.findings.some((finding) => finding.ruleId === item.expected.ruleId)
      : candidateFound;
    return {
      caseId: item.caseId,
      split: item.split,
      expectedVulnerable: vulnerable,
      expectedRuleId: item.expected.ruleId,
      candidateFound,
      matchingCandidate,
      falsePositive: !vulnerable && candidateFound,
      findings: result.run.findings.map(({ ruleId, status, evidenceTier, locations }) => ({ ruleId, status, evidenceTier, locations })),
      coverageUnknown: result.run.plan?.tasks.some((task) => task.phase === "HUNT" && task.status !== "COMPLETED") ?? true,
      tokenTotal: result.run.tokenAccounting.inputTokens + result.run.tokenAccounting.outputTokens,
      runId: result.run.runId,
    };
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

export async function runBenchmark(directory: string, split?: string): Promise<BenchmarkReport> {
  const cases = (await loadCases(directory)).filter((item) => !split || item.split === split);
  if (cases.length === 0) throw new Error(`No benchmark cases found${split ? ` for split ${split}` : ""}.`);
  const results: BenchmarkCaseResult[] = [];
  for (const item of cases) results.push(await runCase(item));
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
      unknownCoverageRate: results.length === 0 ? 0 : unknown.length / results.length,
      tokensPerCase: tokenTotal / results.length,
    },
    notes: [
      "This runner measures deterministic candidate discovery; it does not claim production vulnerability recall.",
      "A candidate is not a reportable finding until independent validation supplies reproducible evidence.",
      "Holdout cases must not be used to tune detectors, prompts, or model routing.",
    ],
  };
}
