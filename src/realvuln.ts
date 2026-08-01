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

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function git(root: string, args: string[]): string {
  return execFileSync("git", ["-C", root, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
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
