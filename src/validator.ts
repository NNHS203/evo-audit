import { createHash, randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { discoverFiles, loadConfig } from "./core.js";
import { buildAuditPlan, refreshCoverageMatrix } from "./workflow.js";
import type {
  AuditRun,
  EvidenceItem,
  Finding,
  FileFingerprint,
  ValidationRequest,
  ValidationResult,
} from "./types.js";

export interface ValidationGate {
  accepted: boolean;
  status: "VERIFIED" | "REJECTED" | "BLOCKED" | "HARNESS_FAILED";
  reason: string;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function fallbackTreeDigest(files: FileFingerprint[]): string {
  return digest(files.map((file) => `${file.path}\0${file.sha256}\0${file.bytes}`).sort().join("\n"));
}

function runTreeDigest(run: AuditRun): string {
  return run.snapshot?.treeDigest ?? fallbackTreeDigest(run.files);
}

function findingTargetFiles(finding: Finding): string[] {
  return [...new Set(finding.locations.map((location) => location.file))].sort();
}

function sourceFilesMatchRun(run: AuditRun, result: ValidationResult, targetFiles: string[]): boolean {
  const expected = new Map(run.files.map((file) => [file.path, file.sha256]));
  const observed = new Map(result.sourceFiles.map((file) => [file.path, file.sha256]));
  return targetFiles.every((file) => expected.has(file) && observed.get(file) === expected.get(file));
}

function evidenceLocationsMatchRun(run: AuditRun, result: ValidationResult): boolean {
  const inScope = new Set(run.files.map((file) => file.path));
  return (result.evidence ?? []).every((item) => (item.locations ?? []).every((location) => inScope.has(location.file) && location.line > 0 && location.column > 0));
}

function validationEvidence(result: ValidationResult): EvidenceItem[] {
  const base: EvidenceItem[] = [
    {
      type: "TOOL_RESULT",
      title: "Independent validator result",
      detail: `${result.validator} returned ${result.outcome} under ${result.sandbox.profile}.`,
      reproducible: result.outcome === "VERIFIED",
    },
    {
      type: "REPRODUCER",
      title: "Validator reproducer",
      detail: `Command exited ${result.reproducer.exitCode ?? "without an exit code"}; passed=${result.reproducer.passed}; timedOut=${result.reproducer.timedOut}.`,
      reproducible: result.reproducer.passed && result.reproducer.exitCode === 0 && !result.reproducer.timedOut,
    },
    {
      type: "TOOL_RESULT",
      title: "Validator negative control",
      detail: `Negative control passed=${result.negativeControl.passed}; exit=${result.negativeControl.exitCode ?? "none"}.`,
      reproducible: result.negativeControl.passed,
    },
  ];
  return [...base, ...(result.evidence ?? [])];
}

export function validateResultAgainstRun(run: AuditRun, result: ValidationResult): ValidationGate {
  const finding = run.findings.find((candidate) => candidate.id === result.findingId);
  if (!finding) return { accepted: false, status: "HARNESS_FAILED", reason: "Validation references a finding that is not present in the run." };
  const targetFiles = findingTargetFiles(finding);
  if (targetFiles.length === 0) return { accepted: false, status: "HARNESS_FAILED", reason: "Validation cannot verify a finding without a source location." };
  if (!result.validator.trim()) return { accepted: false, status: "HARNESS_FAILED", reason: "Validation must identify an independent validator." };
  if (finding.worker && finding.worker === result.validator) return { accepted: false, status: "HARNESS_FAILED", reason: "The finding worker cannot also act as its independent validator." };
  if (result.runId !== run.runId) return { accepted: false, status: "HARNESS_FAILED", reason: "Validation runId does not match the audit run." };
  if (result.baseTreeDigest !== runTreeDigest(run)) {
    return { accepted: false, status: "HARNESS_FAILED", reason: "Validation was produced from a different source snapshot." };
  }
  if (!sourceFilesMatchRun(run, result, targetFiles)) {
    return { accepted: false, status: "HARNESS_FAILED", reason: "Validator source fingerprints do not match the finding's audited files." };
  }
  if (!evidenceLocationsMatchRun(run, result)) {
    return { accepted: false, status: "HARNESS_FAILED", reason: "Validator evidence references a file or location outside the audited snapshot." };
  }
  if (result.sandbox.profile === "HOST_UNSAFE" || !result.sandbox.readOnlySource || result.sandbox.network === "UNRESTRICTED") {
    return { accepted: false, status: "HARNESS_FAILED", reason: "Verification did not run under an approved read-only sandbox policy." };
  }

  if (result.outcome === "VERIFIED") {
    const reproducerOk = result.reproducer.passed && result.reproducer.exitCode === 0 && !result.reproducer.timedOut;
    const negativeControlOk = result.negativeControl.passed;
    if (!reproducerOk || !negativeControlOk) {
      return { accepted: false, status: "HARNESS_FAILED", reason: "VERIFIED requires a passing reproducer and passing negative control." };
    }
    return { accepted: true, status: "VERIFIED", reason: "Independent validator reproduced the issue on the audited snapshot." };
  }

  if (result.outcome === "REJECTED") return { accepted: true, status: "REJECTED", reason: "Independent validator rejected the proposed vulnerability." };
  if (result.outcome === "BLOCKED") return { accepted: true, status: "BLOCKED", reason: "Validator could not complete because a required environment or permission was unavailable." };
  return { accepted: true, status: "HARNESS_FAILED", reason: "Validator reported a harness failure." };
}

export function createValidationRequest(
  run: AuditRun,
  finding: Finding,
  options: { reproducerCommand: string; negativeControlCommand: string; timeoutMs?: number; sandboxProfile?: ValidationRequest["sandboxProfile"]; image?: string },
): ValidationRequest {
  return {
    schemaVersion: 1,
    requestId: randomUUID(),
    runId: run.runId,
    findingId: finding.id,
    baseTreeDigest: runTreeDigest(run),
    targetFiles: findingTargetFiles(finding),
    reproducerCommand: options.reproducerCommand,
    negativeControlCommand: options.negativeControlCommand,
    timeoutMs: options.timeoutMs ?? 30_000,
    sandboxProfile: options.sandboxProfile ?? "READ_ONLY_NO_NETWORK",
    image: options.image,
  };
}

export async function assertWorkspaceMatchesSnapshot(run: AuditRun): Promise<{ ok: boolean; changed: string[] }> {
  const changed: string[] = [];
  try {
    const config = await loadConfig(run.root);
    const currentPaths = await discoverFiles(run.root, config);
    const expectedPaths = run.files.map((file) => file.path).sort();
    const currentPathSet = new Set(currentPaths);
    const expectedPathSet = new Set(expectedPaths);
    changed.push(...currentPaths.filter((file) => !expectedPathSet.has(file)));
    changed.push(...expectedPaths.filter((file) => !currentPathSet.has(file)));
  } catch {
    changed.push("<scope discovery failed>");
  }
  for (const file of run.files) {
    try {
      const buffer = await fs.readFile(path.join(run.root, file.path));
      const currentDigest = createHash("sha256").update(buffer).digest("hex");
      if (currentDigest !== file.sha256 || buffer.byteLength !== file.bytes) changed.push(file.path);
    } catch {
      changed.push(file.path);
    }
  }
  return { ok: changed.length === 0, changed: [...new Set(changed)].sort() };
}

export function applyValidationResult(runInput: AuditRun, result: ValidationResult): { run: AuditRun; gate: ValidationGate } {
  const run = structuredClone(runInput);
  const gate = validateResultAgainstRun(run, result);
  const finding = run.findings.find((candidate) => candidate.id === result.findingId);
  if (!finding) return { run, gate };

  const evidence = validationEvidence(result);
  finding.status = gate.status === "BLOCKED" ? "HARNESS_FAILED" : gate.status;
  finding.evidenceTier = gate.status === "VERIFIED" ? "T2_REPRODUCIBLE" : finding.evidenceTier;
  run.reportableFindingIds = run.reportableFindingIds ?? [];
  if (gate.status === "VERIFIED" && !run.reportableFindingIds.includes(finding.id)) run.reportableFindingIds.push(finding.id);
  if (gate.status !== "VERIFIED") run.reportableFindingIds = run.reportableFindingIds.filter((id) => id !== finding.id);
  finding.evidence = [...finding.evidence, ...evidence, {
    type: "LIMITATION",
    title: "Validator gate",
    detail: gate.reason,
    reproducible: gate.status === "VERIFIED",
  }];
  finding.limitations = [...new Set([...finding.limitations, gate.reason])];

  const obligation = run.obligations.find((candidate) => candidate.id === finding.obligationId);
  if (obligation) {
    if (gate.status === "VERIFIED") obligation.status = "SATISFIED";
    else if (gate.status === "REJECTED") obligation.status = "REJECTED";
    else if (gate.status === "BLOCKED" || gate.status === "HARNESS_FAILED") obligation.status = "BLOCKED";
  }

  run.notes = [...new Set([...run.notes, `Validator ${result.validator} applied: ${gate.status}.` , ...(result.notes ?? [])])];
  if (run.coverage) run.coverage = { ...run.coverage, semantic: "PARTIAL_WORKER" };
  refreshCoverageMatrix(run);
  run.plan = buildAuditPlan(run, run.plan?.tokenBudget ?? 12_000);
  if (run.plan.tasks.length > 0 && run.plan.tasks.every((task) => task.status === "COMPLETED") && run.coverage) {
    run.coverage = { ...run.coverage, semantic: "VALIDATED" };
  }
  run.completedAt = new Date().toISOString();
  return { run, gate };
}
