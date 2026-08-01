import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { defaultConfig, defaultPlaybook } from "./playbook.js";
import { detectFindings } from "./detectors.js";
import { buildCodeGraph, detectGraphFindings } from "./graph.js";
import { formatLatency, formatTokenUsage, recordSessionUsage, tokenUsageTotals } from "./usage.js";
import { defaultModelConfig } from "./models.js";
import { defaultThreatModelOverrides, renderThreatModel } from "./threat.js";
import { buildAuditPlan, buildAuditRecon, planSummary } from "./workflow.js";
import type {
  AuditConfig,
  AuditObligation,
  AuditPlaybook,
  AuditRun,
  AuditSessionUsage,
  SemanticDelta,
  FileFingerprint,
  Finding,
} from "./types.js";

export async function pathExists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

export async function readJson<T>(file: string): Promise<T> {
  return JSON.parse(await fs.readFile(file, "utf8")) as T;
}

export async function writeJson(file: string, value: unknown): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

export async function initWorkspace(root: string): Promise<void> {
  await fs.mkdir(root, { recursive: true });
  const configPath = path.join(root, "audit.config.json");
  const playbookPath = path.join(root, defaultConfig.playbook);
  if (!(await pathExists(configPath))) await writeJson(configPath, defaultConfig);
  if (!(await pathExists(playbookPath))) await writeJson(playbookPath, defaultPlaybook);
  const modelConfigPath = path.join(root, "audit.models.json");
  if (!(await pathExists(modelConfigPath))) await writeJson(modelConfigPath, defaultModelConfig());
  const threatModelPath = path.join(root, "audit.threat.json");
  if (!(await pathExists(threatModelPath))) await writeJson(threatModelPath, defaultThreatModelOverrides());
}

function shouldIgnore(relativePath: string, config: AuditConfig): boolean {
  const pieces = relativePath.split(/[\\/]/g);
  return config.ignore.some((entry) => pieces.includes(entry) || relativePath.startsWith(`${entry}/`));
}

async function walk(root: string, current: string, config: AuditConfig, output: string[]): Promise<void> {
  const entries = await fs.readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    const absolute = path.join(current, entry.name);
    const relative = path.relative(root, absolute).split(path.sep).join("/");
    if (shouldIgnore(relative, config)) continue;
    if (entry.isDirectory()) {
      await walk(root, absolute, config, output);
      continue;
    }
    const extension = path.extname(entry.name).toLowerCase();
    if (config.includeExtensions.includes(extension)) output.push(relative);
  }
}

export async function discoverFiles(root: string, config: AuditConfig): Promise<string[]> {
  const output: string[] = [];
  await walk(root, root, config, output);
  return output.sort();
}

function sha256(buffer: Buffer): string {
  return createHash("sha256").update(buffer).digest("hex");
}

function treeDigest(files: FileFingerprint[]): string {
  return createHash("sha256")
    .update(files.map((file) => `${file.path}\0${file.sha256}\0${file.bytes}`).sort().join("\n"), "utf8")
    .digest("hex");
}

function gitValue(root: string, args: string[]): string | null {
  try {
    return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
  } catch {
    return null;
  }
}

function gitMode(root: string): AuditRun["mode"] {
  return gitValue(root, ["rev-parse", "--is-inside-work-tree"]) === "true" ? "WORKTREE" : "PATH";
}

export async function loadConfig(root: string): Promise<AuditConfig> {
  const file = path.join(root, "audit.config.json");
  return (await pathExists(file)) ? readJson<AuditConfig>(file) : defaultConfig;
}

export async function loadPlaybook(root: string, config: AuditConfig): Promise<AuditPlaybook> {
  const file = path.join(root, config.playbook);
  return (await pathExists(file)) ? readJson<AuditPlaybook>(file) : defaultPlaybook;
}

function relativeToRoot(root: string, file: string): string {
  return path.relative(root, file).split(path.sep).join("/");
}

function computeSemanticDelta(files: FileFingerprint[], baseline: AuditRun | undefined): SemanticDelta {
  if (!baseline) {
    return {
      basis: "FULL_SCAN",
      changed: files.map((file) => file.path),
      added: [],
      removed: [],
      unchanged: [],
      workerHint: "No baseline was supplied; prioritize all in-scope files and do not infer safety from an empty finding set.",
    };
  }

  const previous = new Map(baseline.files.map((file) => [file.path, file.sha256]));
  const current = new Map(files.map((file) => [file.path, file.sha256]));
  const changed: string[] = [];
  const added: string[] = [];
  const unchanged: string[] = [];
  const removed = [...previous.keys()].filter((file) => !current.has(file)).sort();

  for (const file of files) {
    const oldHash = previous.get(file.path);
    if (oldHash === undefined) added.push(file.path);
    else if (oldHash === file.sha256) unchanged.push(file.path);
    else changed.push(file.path);
  }

  return {
    basis: "BASELINE_RUN",
    changed: changed.sort(),
    added: added.sort(),
    removed,
    unchanged: unchanged.sort(),
    workerHint: "Use changed and added files to prioritize model context, then expand to importers and shared boundaries before closing obligations.",
  };
}

export async function runAudit(rootInput: string, options: { output: string; strict?: boolean; baseline?: AuditRun }): Promise<{ run: AuditRun; artifactDir: string; session: AuditSessionUsage }> {
  const root = path.resolve(rootInput);
  const config = await loadConfig(root);
  const playbook = await loadPlaybook(root, config);
  const runId = randomUUID();
  const startedAt = new Date().toISOString();
  const relativeFiles = await discoverFiles(root, config);
  const files: FileFingerprint[] = [];
  const sourceContents = new Map<string, string>();
  const allFindings: Finding[] = [];
  const allObligations: AuditObligation[] = [];

  for (const relative of relativeFiles) {
    const buffer = await fs.readFile(path.join(root, relative));
    files.push({ path: relative, sha256: sha256(buffer), bytes: buffer.byteLength });
    const content = buffer.toString("utf8");
    sourceContents.set(relative, content);
    const result = detectFindings(relative, content, playbook, runId);
    allFindings.push(...result.findings);
    allObligations.push(...result.obligations);
  }

  const reportableFindings = allFindings.filter((finding) => playbook.evidencePolicy.reportableTiers.includes(finding.evidenceTier) && finding.status === "VERIFIED");
  const semanticDelta = computeSemanticDelta(files, options.baseline);
  const codeGraph = buildCodeGraph(files, sourceContents, config.includeExtensions);
  const graphResult = detectGraphFindings(codeGraph, playbook, runId, allFindings);
  allFindings.push(...graphResult.findings);
  allObligations.push(...graphResult.obligations);
  const revision = gitValue(root, ["rev-parse", "HEAD"]);
  const completedAt = new Date().toISOString();
  const snapshot = {
    treeDigest: treeDigest(files),
    revision,
    capturedAt: completedAt,
    files,
  };
  const recon = await buildAuditRecon(root, files, sourceContents, allFindings, semanticDelta, config, playbook, codeGraph, snapshot.treeDigest);
  const run: AuditRun = {
    schemaVersion: 1,
    runId,
    startedAt,
    completedAt,
    root,
    baseline: gitValue(root, ["rev-parse", "HEAD~1"]),
    head: revision,
    mode: gitMode(root),
    playbook: { id: playbook.id, version: playbook.version },
    files,
    snapshot,
    coverage: {
      complete: true,
      strategy: "FULL_SCAN",
      semantic: "STATIC_ONLY",
      filesReviewed: relativeFiles,
    },
    recon,
    semanticDelta,
    obligations: allObligations,
    findings: allFindings,
    reportableFindingIds: reportableFindings.map((finding) => finding.id),
    tokenAccounting: {
      inputTokens: 0,
      outputTokens: 0,
      cachedTokens: 0,
      estimatedCostUsd: 0,
      source: "DETERMINISTIC",
    },
    notes: [
      "This run used only deterministic static detectors.",
      "SUSPECTED and SUPPORTED findings require an execution-capable worker before they can be reported as VERIFIED.",
      "No finding is evidence that untested code is safe.",
      "Semantic coverage is STATIC_ONLY until worker hunt tasks and independent validation close the workflow queue.",
      `Semantic delta basis: ${semanticDelta.basis}; changed=${semanticDelta.changed.length}, added=${semanticDelta.added.length}, removed=${semanticDelta.removed.length}.`,
      `Snapshot tree digest: ${snapshot.treeDigest}.`,
      `Recon context digest: ${recon.contextDigest}.`,
    ],
  };
  run.plan = buildAuditPlan(run, config.tokenBudget);
  run.notes.push(`Workflow plan: ${run.plan.tasks.length} tasks, ${run.plan.allocatedTokens}/${run.plan.tokenBudget} investigation tokens allocated.`);

  const artifactDir = path.resolve(options.output, runId);
  const session = await persistRunArtifacts(artifactDir, run);
  return { run, artifactDir, session };
}

export function summarizeRun(run: AuditRun, options: { findingIds?: string[]; session?: AuditSessionUsage } = {}): string {
  const visibleIds = options.findingIds ? new Set(options.findingIds) : null;
  const visibleFindings = visibleIds ? run.findings.filter((finding) => visibleIds.has(finding.id)) : run.findings;
  const counts = new Map<string, number>();
  for (const finding of visibleFindings) counts.set(finding.status, (counts.get(finding.status) ?? 0) + 1);
  const countText = ["VERIFIED", "SUPPORTED", "SUSPECTED", "REJECTED", "DUPLICATE", "UNKNOWN", "NOT_TESTED", "HARNESS_FAILED"]
    .filter((status) => counts.has(status))
    .map((status) => `${status}=${counts.get(status)}`)
    .join("  ");
  const lines = [
    `Run ${run.runId}`,
    `Mode: ${run.mode}  Files: ${run.files.length}  Obligations: ${run.obligations.length}`,
    `Findings: ${countText || "none"}`,
    run.recon?.coverageMatrix
      ? `Coverage: semantic=${run.coverage.semantic}  cells=${run.recon.coverageMatrix.cells.length}  hunt=${run.recon.coverageMatrix.cells.filter((cell) => cell.status === "HUNT_REQUIRED").length}  unknown=${run.recon.coverageMatrix.cells.filter((cell) => cell.status === "UNKNOWN").length}  validated=${run.recon.coverageMatrix.cells.filter((cell) => cell.status === "VALIDATED").length}`
      : `Coverage: semantic=${run.coverage.semantic}  matrix=unavailable`,
    `Tokens: current ${formatTokenUsage(tokenUsageTotals(run.tokenAccounting))} (source=${run.tokenAccounting.source})`,
    `Latency: current=${formatLatency(tokenUsageTotals(run.tokenAccounting).durationMs)}`,
    planSummary(run.plan),
  ];
  if (options.session) {
    lines.push(`Session total: ${formatTokenUsage(options.session.total)} across ${options.session.runs.length} run(s) (session=${options.session.sessionId})`);
    lines.push(`Session latency: ${formatLatency(options.session.total.durationMs)}`);
  }
  for (const finding of visibleFindings) {
    const location = finding.locations[0];
    const locationText = location ? `${location.file}:${location.line}` : "<unmapped>";
    lines.push(`- [${finding.status}] ${finding.severity} ${finding.title} (${locationText})`);
  }
  return lines.join("\n");
}

export function resolveInput(root: string, input: string | undefined): string {
  return path.resolve(root, input ?? ".");
}

export async function persistRunArtifacts(artifactDir: string, run: AuditRun): Promise<AuditSessionUsage> {
  const session = await recordSessionUsage(path.dirname(artifactDir), run);
  run.sessionId = session.sessionId;
  await writeJson(path.join(artifactDir, "run.json"), run);
  await writeJson(path.join(artifactDir, "findings.json"), run.findings);
  await writeJson(path.join(artifactDir, "obligations.json"), run.obligations);
  if (run.recon) await writeJson(path.join(artifactDir, "recon.json"), run.recon);
  if (run.recon?.threatModel) {
    await writeJson(path.join(artifactDir, "threat-model.json"), run.recon.threatModel);
    await fs.writeFile(path.join(artifactDir, "threat-model.md"), renderThreatModel(run.recon.threatModel), "utf8");
  }
  if (run.dedup) await writeJson(path.join(artifactDir, "dedup.json"), run.dedup);
  if (run.plan) await writeJson(path.join(artifactDir, "plan.json"), run.plan);
  await writeJson(path.join(artifactDir, "manifest.json"), {
    schemaVersion: 1,
    runId: run.runId,
    sessionId: run.sessionId,
    files: run.files,
    snapshot: run.snapshot,
    coverage: run.coverage,
    recon: run.recon,
    dedup: run.dedup,
    plan: run.plan,
    semanticDelta: run.semanticDelta,
    reportableFindingIds: run.reportableFindingIds,
    playbook: run.playbook,
    tokenAccounting: run.tokenAccounting,
    workerReceipts: run.workerReceipts,
  });
  return session;
}
