import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { readJson, runAudit, writeJson } from "./core.js";
import { scannerFindingsFromRun, scoreScannerFindings, groundTruthLabelsFromValue, type ScannerScore } from "./scoring.js";
import type { AuditRun } from "./types.js";

interface RealVulnRepository {
  repo_url: string;
  commit_sha: string;
  language?: string;
  framework?: string | null;
  vulnerable_findings?: number;
  false_positive_traps?: number;
}

interface RealVulnManifest {
  schema_version: string;
  benchmark_version: string;
  ground_truth_version?: string;
  repos: Record<string, RealVulnRepository>;
}

export interface RealVulnReport {
  schemaVersion: 1;
  benchmark: "RealVuln";
  benchmarkVersion: string;
  groundTruthVersion?: string;
  benchmarkManifest: string;
  repository: {
    id: string;
    url: string;
    commit: string;
    language?: string;
    framework?: string | null;
  };
  groundTruth: {
    path: string;
    sha256: string;
    labels: number;
  };
  audit: {
    runId: string;
    treeDigest: string;
    artifactDir: string;
  };
  score: ScannerScore;
  notes: string[];
}

export interface RealVulnAggregateReport {
  schemaVersion: 1;
  benchmark: "RealVuln";
  benchmarkVersion: string;
  groundTruthVersion?: string;
  benchmarkManifest: string;
  repositories: number;
  completed: number;
  blocked: number;
  aggregate: ScannerScore;
  entries: Array<{
    id: string;
    status: "COMPLETED" | "BLOCKED";
    url: string;
    commit: string;
    language?: string;
    framework?: string | null;
    report?: string;
    score?: ScannerScore;
    error?: string;
  }>;
  notes: string[];
}

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function git(root: string, args: string[]): string {
  return execFileSync("git", ["-C", root, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function f3(precision: number, recall: number): number {
  if (precision + recall === 0) return 0;
  return (10 * precision * recall) / (9 * precision + recall);
}

function aggregateCounts(scores: ScannerScore[], reportable: boolean): ScannerScore["candidate"] {
  const counts = scores.reduce((total, score) => {
    const channel = reportable ? score.reportable : score.candidate;
    return {
      truePositive: total.truePositive + channel.truePositive,
      falsePositive: total.falsePositive + channel.falsePositive,
      falseNegative: total.falseNegative + channel.falseNegative,
      trueNegative: total.trueNegative + channel.trueNegative,
      candidateCount: total.candidateCount + channel.candidateCount,
      validatedCount: total.validatedCount + channel.validatedCount,
    };
  }, { truePositive: 0, falsePositive: 0, falseNegative: 0, trueNegative: 0, candidateCount: 0, validatedCount: 0 });
  const positivePredictions = counts.truePositive + counts.falsePositive;
  const actualPositives = counts.truePositive + counts.falseNegative;
  const negativeLabels = counts.trueNegative + counts.falsePositive;
  const precision = positivePredictions === 0 ? 0 : counts.truePositive / positivePredictions;
  const recall = actualPositives === 0 ? 0 : counts.truePositive / actualPositives;
  return {
    ...counts,
    precision,
    recall,
    falsePositiveRate: negativeLabels === 0 ? 0 : counts.falsePositive / negativeLabels,
    f3: f3(precision, recall),
    tokensPerValidatedFinding: null,
  };
}

function aggregateScores(scores: ScannerScore[]): ScannerScore {
  const candidate = aggregateCounts(scores, false);
  const reportable = aggregateCounts(scores, true);
  const inputTokens = scores.reduce((sum, score) => sum + score.inputTokens, 0);
  const outputTokens = scores.reduce((sum, score) => sum + score.outputTokens, 0);
  const durationMs = scores.reduce((sum, score) => sum + score.durationMs, 0);
  candidate.tokensPerValidatedFinding = candidate.validatedCount > 0 ? (inputTokens + outputTokens) / candidate.validatedCount : null;
  reportable.tokensPerValidatedFinding = reportable.validatedCount > 0 ? (inputTokens + outputTokens) / reportable.validatedCount : null;
  return {
    schemaVersion: 1,
    scanner: "evo-audit",
    labels: scores.reduce((sum, score) => sum + score.labels, 0),
    vulnerableLabels: scores.reduce((sum, score) => sum + score.vulnerableLabels, 0),
    safeLabels: scores.reduce((sum, score) => sum + score.safeLabels, 0),
    findings: scores.reduce((sum, score) => sum + score.findings, 0),
    unsupportedClaimCount: scores.reduce((sum, score) => sum + score.unsupportedClaimCount, 0),
    unsupportedClaimRate: scores.reduce((sum, score) => sum + score.findings, 0) === 0
      ? 0
      : scores.reduce((sum, score) => sum + score.unsupportedClaimCount, 0) / scores.reduce((sum, score) => sum + score.findings, 0),
    candidate,
    reportable,
    inputTokens,
    outputTokens,
    durationMs,
    notes: [
      "Aggregate metrics sum one-to-one labels across completed pinned repositories only.",
      "Blocked repositories are excluded from denominators and remain explicit entries; they are not clean results.",
      "Candidate and reportable channels are scored separately.",
    ],
  };
}

function boundedError(error: unknown): string {
  const value = error instanceof Error ? error.message : String(error);
  return value.replace(/\s+/g, " ").slice(0, 800);
}

function repositoryFromManifest(manifest: RealVulnManifest, repoId: string): RealVulnRepository {
  const repository = manifest.repos?.[repoId];
  if (!repository || typeof repository.repo_url !== "string" || typeof repository.commit_sha !== "string") throw new Error(`RealVuln repository is missing or malformed: ${repoId}`);
  if (!/^[0-9a-f]{40}$/i.test(repository.commit_sha)) throw new Error(`RealVuln repository ${repoId} is not pinned to a full commit SHA.`);
  let parsed: URL;
  try {
    parsed = new URL(repository.repo_url);
  } catch {
    throw new Error(`RealVuln repository URL is invalid: ${repository.repo_url}`);
  }
  if (parsed.protocol !== "https:") throw new Error(`Only HTTPS RealVuln repository URLs are accepted: ${repository.repo_url}`);
  return repository;
}

async function cloneAtPinnedCommit(repository: RealVulnRepository, target: string): Promise<void> {
  execFileSync("git", ["clone", "--depth", "1", repository.repo_url, target], { stdio: ["ignore", "pipe", "pipe"] });
  let actual = git(target, ["rev-parse", "HEAD"]);
  if (actual !== repository.commit_sha) {
    execFileSync("git", ["-C", target, "fetch", "--depth", "1", "origin", repository.commit_sha], { stdio: ["ignore", "pipe", "pipe"] });
    execFileSync("git", ["-C", target, "checkout", "--detach", repository.commit_sha], { stdio: ["ignore", "pipe", "pipe"] });
    actual = git(target, ["rev-parse", "HEAD"]);
  }
  if (actual !== repository.commit_sha) throw new Error(`RealVuln checkout revision mismatch: expected ${repository.commit_sha}, got ${actual}.`);
}

export async function runRealVuln(
  benchmarkRoot: string,
  repoId: string,
  options: { output: string; keepCheckout?: boolean } ,
): Promise<RealVulnReport> {
  const manifestPath = path.join(benchmarkRoot, "benchmark-manifest.json");
  const manifest = await readJson<RealVulnManifest>(manifestPath);
  if (!manifest || typeof manifest.benchmark_version !== "string" || !manifest.repos) throw new Error(`Invalid RealVuln manifest: ${manifestPath}`);
  const repository = repositoryFromManifest(manifest, repoId);
  const groundTruthPath = path.join(benchmarkRoot, "ground-truth", repoId, "ground-truth.json");
  const groundTruthBytes = await fs.readFile(groundTruthPath);
  const labels = groundTruthLabelsFromValue(JSON.parse(groundTruthBytes.toString("utf8")), "REALVULN");
  const tempParent = await fs.mkdtemp(path.join(os.tmpdir(), "evo-audit-realvuln-parent-"));
  const checkout = path.join(tempParent, "checkout");
  const output = path.resolve(options.output);
  await fs.mkdir(output, { recursive: true });
  try {
    await cloneAtPinnedCommit(repository, checkout);
    const audit = await runAudit(checkout, { output: path.join(output, "audit-runs") });
    const run = audit.run as AuditRun;
    const score = scoreScannerFindings(scannerFindingsFromRun(run), labels, {
      scanner: "evo-audit",
      inputTokens: run.tokenAccounting.inputTokens,
      outputTokens: run.tokenAccounting.outputTokens,
      durationMs: run.tokenAccounting.durationMs,
    });
    const report: RealVulnReport = {
      schemaVersion: 1,
      benchmark: "RealVuln",
      benchmarkVersion: manifest.benchmark_version,
      groundTruthVersion: manifest.ground_truth_version,
      benchmarkManifest: manifestPath,
      repository: { id: repoId, url: repository.repo_url, commit: repository.commit_sha, language: repository.language, framework: repository.framework },
      groundTruth: { path: groundTruthPath, sha256: sha256(groundTruthBytes), labels: labels.length },
      audit: { runId: run.runId, treeDigest: run.snapshot.treeDigest, artifactDir: audit.artifactDir },
      score,
      notes: [
        "The checkout was cloned from the manifest URL and verified at its full commit SHA before auditing.",
        "RealVuln ground truth is external and remains versioned by its own benchmark manifest; this report does not change or vendor those labels.",
        "Candidate and reportable channels are separate. Static candidates are not verified vulnerabilities.",
      ],
    };
    await writeJson(path.join(output, "realvuln-report.json"), report);
    if (options.keepCheckout) await fs.cp(checkout, path.join(output, "checkout"), { recursive: true, errorOnExist: true });
    return report;
  } finally {
    await fs.rm(tempParent, { recursive: true, force: true });
  }
}

export async function runRealVulnAll(
  benchmarkRoot: string,
  options: { output: string; keepCheckout?: boolean },
): Promise<RealVulnAggregateReport> {
  const manifestPath = path.join(benchmarkRoot, "benchmark-manifest.json");
  const manifest = await readJson<RealVulnManifest>(manifestPath);
  if (!manifest || typeof manifest.benchmark_version !== "string" || !manifest.repos) throw new Error(`Invalid RealVuln manifest: ${manifestPath}`);
  const output = path.resolve(options.output);
  await fs.mkdir(output, { recursive: true });
  const entries: RealVulnAggregateReport["entries"] = [];
  const scores: ScannerScore[] = [];
  for (const repoId of Object.keys(manifest.repos).sort()) {
    const rawRepository = manifest.repos[repoId] as Partial<RealVulnRepository> | undefined;
    const fallbackUrl = typeof rawRepository?.repo_url === "string" ? rawRepository.repo_url : "";
    const fallbackCommit = typeof rawRepository?.commit_sha === "string" ? rawRepository.commit_sha : "";
    const fallbackLanguage = typeof rawRepository?.language === "string" ? rawRepository.language : undefined;
    const fallbackFramework = typeof rawRepository?.framework === "string" ? rawRepository.framework : rawRepository?.framework === null ? null : undefined;
    const repoOutput = path.join(output, repoId.replace(/[^A-Za-z0-9._-]+/g, "_"));
    try {
      const repository = repositoryFromManifest(manifest, repoId);
      const report = await runRealVuln(benchmarkRoot, repoId, { output: repoOutput, keepCheckout: options.keepCheckout });
      scores.push(report.score);
      entries.push({
        id: repoId,
        status: "COMPLETED",
        url: repository.repo_url,
        commit: repository.commit_sha,
        language: repository.language,
        framework: repository.framework,
        report: path.relative(output, path.join(repoOutput, "realvuln-report.json")).split(path.sep).join("/"),
        score: report.score,
      });
    } catch (error) {
      entries.push({
        id: repoId,
        status: "BLOCKED",
        url: fallbackUrl,
        commit: fallbackCommit,
        language: fallbackLanguage,
        framework: fallbackFramework,
        error: boundedError(error),
      });
    }
  }
  const aggregate: RealVulnAggregateReport = {
    schemaVersion: 1,
    benchmark: "RealVuln",
    benchmarkVersion: manifest.benchmark_version,
    groundTruthVersion: manifest.ground_truth_version,
    benchmarkManifest: manifestPath,
    repositories: entries.length,
    completed: entries.filter((entry) => entry.status === "COMPLETED").length,
    blocked: entries.filter((entry) => entry.status === "BLOCKED").length,
    aggregate: aggregateScores(scores),
    entries,
    notes: [
      "This aggregate is reproducible only with the recorded upstream manifest revision, repository commits, playbook, scanner commit, and execution policy.",
      "A clone, ground-truth, or audit failure is recorded as BLOCKED and excluded from aggregate denominators; it is never silently treated as safe.",
      "Independent runtime validation is still required before candidate findings become reportable vulnerabilities.",
    ],
  };
  await writeJson(path.join(output, "realvuln-aggregate.json"), aggregate);
  return aggregate;
}
