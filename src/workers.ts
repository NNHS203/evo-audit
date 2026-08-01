import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import type {
  AuditObligation,
  AuditRun,
  AuditWorkerResult,
  EvidenceItem,
  Finding,
  FindingStatus,
  SourceLocation,
} from "./types.js";
import { buildAuditPlan, refreshCoverageMatrix } from "./workflow.js";
import { deduplicateRun } from "./dedup.js";

const statusRank: Record<FindingStatus, number> = {
  HARNESS_FAILED: 0,
  UNKNOWN: 1,
  DUPLICATE: 1,
  REJECTED: 1,
  NOT_TESTED: 1,
  SUSPECTED: 2,
  SUPPORTED: 3,
  VERIFIED: 4,
};

const evidenceRank = {
  T0_HYPOTHESIS: 0,
  T1_STATIC_PATH: 1,
  T2_REPRODUCIBLE: 2,
} as const;

function stableId(parts: string[]): string {
  return createHash("sha256").update(parts.join("|"), "utf8").digest("hex").slice(0, 20);
}

function locationKey(location: SourceLocation): string {
  return `${location.file}:${location.line}:${location.column}`;
}

function locationsKey(locations: SourceLocation[] | undefined): string {
  return (locations ?? []).map(locationKey).sort().join(",");
}

function locationInSnapshot(run: AuditRun, location: SourceLocation): boolean {
  const file = run.files.find((candidate) => candidate.path === location.file);
  if (!file) return false;
  if (!Number.isInteger(location.line) || !Number.isInteger(location.endLine) || location.line < 1 || location.endLine < location.line) return false;
  if (file.lineCount !== undefined && location.endLine > file.lineCount) return false;
  return Number.isInteger(location.column) && location.column > 0;
}

function normalizeSnippet(value: string): string {
  return value
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => line.trim().replace(/[ \t]+/g, " "))
    .join("\n")
    .trim();
}

type SnapshotLineCache = Map<string, string[] | null>;

function snapshotLines(run: AuditRun, filePath: string, cache: SnapshotLineCache): string[] | null {
  if (cache.has(filePath)) return cache.get(filePath) ?? null;
  const fingerprint = run.files.find((file) => file.path === filePath);
  if (!fingerprint) {
    cache.set(filePath, null);
    return null;
  }
  const root = path.resolve(run.root);
  const target = path.resolve(root, filePath);
  if (target !== root && !target.startsWith(`${root}${path.sep}`)) {
    cache.set(filePath, null);
    return null;
  }
  try {
    const buffer = readFileSync(target);
    const digest = createHash("sha256").update(buffer).digest("hex");
    if (digest !== fingerprint.sha256) {
      cache.set(filePath, null);
      return null;
    }
    const lines = buffer.toString("utf8").split(/\r?\n/);
    if (fingerprint.lineCount !== undefined && lines.length !== fingerprint.lineCount) {
      cache.set(filePath, null);
      return null;
    }
    cache.set(filePath, lines);
    return lines;
  } catch {
    cache.set(filePath, null);
    return null;
  }
}

function validateSourceLocation(
  run: AuditRun,
  location: SourceLocation,
  cache: SnapshotLineCache,
): { valid: boolean; reason?: string } {
  if (!locationInSnapshot(run, location)) return { valid: false, reason: "outside the fingerprinted snapshot or beyond its recorded line count" };
  const lines = snapshotLines(run, location.file, cache);
  if (!lines) return { valid: false, reason: "the source file was missing or its content no longer matched the snapshot fingerprint" };
  const actual = normalizeSnippet(lines.slice(location.line - 1, location.endLine).join("\n"));
  const expected = normalizeSnippet(location.snippet);
  if (!expected || !actual.includes(expected)) return { valid: false, reason: "the worker snippet did not match the fingerprinted source lines" };
  return { valid: true };
}

function sanitizeEvidence(
  run: AuditRun,
  items: EvidenceItem[],
  cache: SnapshotLineCache,
): { evidence: EvidenceItem[]; dropped: string[] } {
  const dropped: string[] = [];
  const evidence = items.flatMap((item) => {
    if (!item.locations || item.locations.length === 0) return [item];
    const locations = item.locations.filter((location) => {
      const validation = validateSourceLocation(run, location, cache);
      if (!validation.valid) dropped.push(`${item.title}: ${validation.reason ?? "invalid source location"}`);
      return validation.valid;
    });
    return locations.length > 0 ? [{ ...item, locations }] : [];
  });
  return { evidence, dropped };
}

function evidenceKey(item: EvidenceItem): string {
  return `${item.type}|${item.title}|${item.detail}|${(item.locations ?? []).map(locationKey).sort().join(",")}`;
}

function uniqueEvidence(items: EvidenceItem[]): EvidenceItem[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = evidenceKey(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function uniqueStrings(items: string[]): string[] {
  return [...new Set(items.filter(Boolean))];
}

function hasReproducibleEvidence(evidence: EvidenceItem[]): boolean {
  return evidence.some((item) => item.type === "REPRODUCER" && item.reproducible === true);
}

function hasTraceEvidence(evidence: EvidenceItem[]): boolean {
  return evidence.some((item) => item.type === "TRACE" || item.type === "TOOL_RESULT");
}

function workerClaimGate(status: FindingStatus, evidenceTier: Finding["evidenceTier"], evidence: EvidenceItem[]): {
  status: FindingStatus;
  evidenceTier: Finding["evidenceTier"];
  limitation?: EvidenceItem;
} {
  const trace = hasTraceEvidence(evidence);
  const gatedStatus = status === "VERIFIED" ? (trace ? "SUPPORTED" : "SUSPECTED") : status;
  const gatedTier = evidenceTier === "T2_REPRODUCIBLE" ? (trace ? "T1_STATIC_PATH" : "T0_HYPOTHESIS") : evidenceTier;
  if (gatedStatus === status && gatedTier === evidenceTier) return { status, evidenceTier };
  return {
    status: gatedStatus,
    evidenceTier: gatedTier,
    limitation: {
      type: "LIMITATION",
      title: "Worker claim gated",
      detail: "A worker can propose a reproducer, but only the independent validator can create T2 evidence or VERIFIED status.",
      reproducible: false,
    },
  };
}

function gateClaim(
  status: FindingStatus,
  evidenceTier: Finding["evidenceTier"],
  evidence: EvidenceItem[],
  scopeValid: boolean,
): { status: FindingStatus; evidenceTier: Finding["evidenceTier"]; limitation?: EvidenceItem } {
  if (evidenceTier !== "T2_REPRODUCIBLE" || (hasReproducibleEvidence(evidence) && scopeValid)) {
    if (status !== "VERIFIED") return { status, evidenceTier };
    if (evidenceTier === "T2_REPRODUCIBLE") return { status, evidenceTier };
  }

  if (status !== "VERIFIED" && evidenceTier !== "T2_REPRODUCIBLE") {
    return { status, evidenceTier };
  }

  const downgradedStatus: FindingStatus = hasTraceEvidence(evidence) ? "SUPPORTED" : "SUSPECTED";
  const downgradedTier = hasTraceEvidence(evidence) ? "T1_STATIC_PATH" : "T0_HYPOTHESIS";
  return {
    status: downgradedStatus,
    evidenceTier: downgradedTier,
    limitation: {
      type: "LIMITATION",
      title: "Verification claim gated",
      detail: scopeValid
        ? "The worker requested VERIFIED, but the result did not include a reproducible T2_REPRODUCER item."
        : "The worker requested VERIFIED, but its evidence was not mapped to a fingerprinted in-scope source location.",
      reproducible: false,
    },
  };
}

function matchingFinding(findings: Finding[], worker: AuditWorkerResult, candidate: AuditWorkerResult["findings"][number]): Finding | undefined {
  if (candidate.id) {
    const byId = findings.find((finding) => finding.id === candidate.id && finding.ruleId === candidate.ruleId);
    if (byId) return byId;
  }
  if (candidate.obligationId) {
    const byObligation = findings.find((finding) => finding.obligationId === candidate.obligationId && finding.ruleId === candidate.ruleId);
    if (byObligation) return byObligation;
  }
  const candidateLocations = locationsKey(candidate.locations);
  return findings.find(
    (finding) =>
      finding.ruleId === candidate.ruleId &&
      candidateLocations.length > 0 &&
      locationsKey(finding.locations) === candidateLocations,
  );
}

function createWorkerObligation(run: AuditRun, result: AuditWorkerResult, finding: AuditWorkerResult["findings"][number], id: string): AuditObligation {
  return {
    id,
    kind: "CUSTOM",
    title: `Verify: ${finding.title}`,
    status: "OPEN",
    targetFiles: (finding.locations ?? []).map((location) => location.file),
    falsifiers: [
      "Reproduce the claimed behavior in an isolated environment.",
      "Record the exact input, preconditions, and observed security impact.",
      "Attempt a negative control that should not trigger the behavior.",
    ],
    evidenceRequired: "T2_REPRODUCIBLE",
    createdBy: result.worker,
  };
}

function mergeFinding(run: AuditRun, result: AuditWorkerResult, candidate: AuditWorkerResult["findings"][number]): Finding {
  const existing = matchingFinding(run.findings, result, candidate);
  const locationCache: SnapshotLineCache = new Map();
  const sanitizedEvidence = sanitizeEvidence(run, [...(existing?.evidence ?? []), ...(candidate.evidence ?? [])], locationCache);
  const evidence = uniqueEvidence(sanitizedEvidence.evidence);
  const proposedLocations = candidate.locations && candidate.locations.length > 0 ? candidate.locations : existing?.locations ?? [];
  const locationValidation = proposedLocations.map((location) => ({ location, result: validateSourceLocation(run, location, locationCache) }));
  const locations = locationValidation.filter((item) => item.result.valid).map((item) => item.location);
  const droppedLocations = proposedLocations.length - locations.length;
  const locationReasons = uniqueStrings(locationValidation.filter((item) => !item.result.valid).map((item) => item.result.reason ?? "invalid source location"));
  const scopeValid = proposedLocations.length > 0 && droppedLocations === 0;
  const knownRule = !run.recon?.ruleInventory?.length || run.recon.ruleInventory.some((rule) => rule.id === candidate.ruleId);
  const ruleLimitation = knownRule ? undefined : "The worker used a rule ID outside the configured playbook; the claim is quarantined as UNKNOWN until an operator adds and evaluates that rule.";
  const workerClaim = workerClaimGate(knownRule ? candidate.status : "UNKNOWN", knownRule ? candidate.evidenceTier : "T0_HYPOTHESIS", evidence);
  const claim = gateClaim(workerClaim.status, workerClaim.evidenceTier, evidence, scopeValid);
  const locationLimitations = [
    ...(ruleLimitation ? [ruleLimitation] : []),
    ...(droppedLocations > 0 ? [`${droppedLocations} worker location(s) were rejected: ${locationReasons.join("; ")}.`] : []),
    ...(sanitizedEvidence.dropped.length > 0 ? [`${sanitizedEvidence.dropped.length} evidence location(s) were rejected because they were not anchored to the fingerprinted snapshot.`] : []),
  ];
  const limitation = [
    workerClaim.limitation,
    claim.limitation,
    ...locationLimitations.map((detail): EvidenceItem => ({ type: "LIMITATION", title: detail === ruleLimitation ? "Rule inventory gate" : "Source evidence anchored", detail, reproducible: false })),
  ].filter((item): item is EvidenceItem => Boolean(item));
  const obligationId = candidate.obligationId ?? existing?.obligationId ?? `${run.runId}-${result.worker}-${stableId([candidate.ruleId, candidate.title, locationsKey(locations)])}`;

  if (!existing && !run.obligations.some((obligation) => obligation.id === obligationId)) {
    run.obligations.push(createWorkerObligation(run, result, candidate, obligationId));
  }

  const merged: Finding = {
    id: existing?.id ?? candidate.id ?? `${run.runId}-${result.worker}-${stableId([candidate.ruleId, candidate.title, locationsKey(locations)])}-finding`,
    ruleId: candidate.ruleId,
    obligationId,
    title: candidate.title || existing?.title || candidate.ruleId,
    severity: candidate.severity ?? existing?.severity ?? "MEDIUM",
    status: claim.status,
    evidenceTier: claim.evidenceTier,
    rootCause: candidate.rootCause ?? existing?.rootCause ?? "The worker reported a potential security boundary.",
    impact: candidate.impact ?? existing?.impact ?? "The security impact requires review of the worker evidence.",
    remediation: candidate.remediation ?? existing?.remediation ?? "Review the evidence and implement a targeted fix if the claim is reproducible.",
    locations,
    evidence: uniqueEvidence([...evidence, ...limitation]),
    limitations: uniqueStrings([
      ...(existing?.limitations ?? []),
      ...(candidate.limitations ?? []),
      ...(claim.limitation ? [claim.limitation.detail] : []),
      ...locationLimitations,
    ]),
    proposedValidation: candidate.proposedValidation ?? existing?.proposedValidation,
    worker: result.worker,
  };

  if (existing) {
    const index = run.findings.indexOf(existing);
    run.findings[index] = {
      ...existing,
      ...merged,
      status: statusRank[merged.status] >= statusRank[existing.status] ? merged.status : existing.status,
      evidenceTier: evidenceRank[merged.evidenceTier] >= evidenceRank[existing.evidenceTier] ? merged.evidenceTier : existing.evidenceTier,
      evidence: uniqueEvidence([...existing.evidence, ...merged.evidence]),
      limitations: uniqueStrings([...existing.limitations, ...merged.limitations]),
    };
    return run.findings[index];
  }

  run.findings.push(merged);
  return merged;
}

function updateObligationState(run: AuditRun, finding: Finding): void {
  const obligation = run.obligations.find((candidate) => candidate.id === finding.obligationId);
  if (!obligation) return;
  if (finding.status === "VERIFIED" && finding.evidenceTier === "T2_REPRODUCIBLE") obligation.status = "SATISFIED";
  else if (finding.status === "HARNESS_FAILED") obligation.status = "BLOCKED";
}

function nonNegativeNumber(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : fallback;
}

function applyHuntCoverageReceipt(run: AuditRun, result: AuditWorkerResult): void {
  if (!result.taskId || !run.plan || !run.recon?.coverageMatrix) return;
  const task = run.plan.tasks.find((candidate) => candidate.id === result.taskId);
  if (!task || task.phase !== "HUNT" || !task.coverageCellId) return;
  const cell = run.recon.coverageMatrix.cells.find((candidate) => candidate.id === task.coverageCellId);
  if (!cell) return;
  if (result.error) {
    cell.status = "UNKNOWN";
    cell.evidence = [...new Set([...cell.evidence, `${task.id}:HARNESS_FAILED`])];
    return;
  }
  cell.attempts = (cell.attempts ?? 0) + 1;
  const reportedRule = result.findings.some((candidate) => candidate.ruleId === cell.ruleId);
  const matching = reportedRule
    ? run.findings.filter((finding) => finding.ruleId === cell.ruleId && (cell.area === "repository" || finding.locations.some((location) => cell.files.includes(location.file))))
    : [];
  if (matching.length > 0) {
    cell.status = "CANDIDATE";
    cell.evidence = [...new Set([...cell.evidence, ...matching.map((finding) => finding.id), task.id])];
  } else {
    cell.status = "UNKNOWN";
    cell.evidence = [...new Set([...cell.evidence, `${task.id}:NO_CANDIDATE`])];
  }
}

export function mergeWorkerResult(runInput: AuditRun, result: AuditWorkerResult): AuditRun {
  let run = structuredClone(runInput);
  if (result.receiptId && run.workerReceipts?.some((receipt) => receipt.receiptId === result.receiptId)) {
    run.notes = uniqueStrings([...run.notes, `Worker receipt ${result.receiptId} was already applied; ingest is idempotent.`]);
    run.completedAt = new Date().toISOString();
    return run;
  }
  for (const candidate of result.findings) {
    const finding = mergeFinding(run, result, candidate);
    updateObligationState(run, finding);
  }

  run = deduplicateRun(run);

  const reported = result.tokenAccounting;
  if (reported) {
    run.tokenAccounting = {
      inputTokens: run.tokenAccounting.inputTokens + nonNegativeNumber(reported.inputTokens, 0),
      outputTokens: run.tokenAccounting.outputTokens + nonNegativeNumber(reported.outputTokens, 0),
      cachedTokens: run.tokenAccounting.cachedTokens + nonNegativeNumber(reported.cachedTokens, 0),
      estimatedCostUsd: run.tokenAccounting.estimatedCostUsd + nonNegativeNumber(reported.estimatedCostUsd, 0),
      durationMs: (run.tokenAccounting.durationMs ?? 0) + nonNegativeNumber(reported.durationMs, 0),
      source: "WORKER_REPORTED",
    };
  }

  if (result.receiptId) {
    run.workerReceipts = [
      ...(run.workerReceipts ?? []),
      {
        receiptId: result.receiptId,
        worker: result.worker,
        taskId: result.taskId,
        modelRequestId: result.modelRequestId,
        providerModel: result.providerModel,
        promptHash: result.promptHash,
        finishReason: result.finishReason,
        cacheHit: result.cacheHit,
        usage: reported ? { inputTokens: nonNegativeNumber(reported.inputTokens, 0), outputTokens: nonNegativeNumber(reported.outputTokens, 0), cachedTokens: nonNegativeNumber(reported.cachedTokens, 0), estimatedCostUsd: nonNegativeNumber(reported.estimatedCostUsd, 0), durationMs: nonNegativeNumber(reported.durationMs, 0), source: "WORKER_REPORTED" } : undefined,
        appliedAt: new Date().toISOString(),
      },
    ];
  }

  const workerNote = `Worker ${result.worker} ingested; claims remain evidence-gated.`;
  run.notes = uniqueStrings([...run.notes, workerNote, ...(result.notes ?? [])]);
  if (run.coverage) run.coverage = { ...run.coverage, semantic: "PARTIAL_WORKER" };
  applyHuntCoverageReceipt(run, result);
  refreshCoverageMatrix(run);
  run.plan = buildAuditPlan(run, run.plan?.tokenBudget ?? 12_000);
  if (result.taskId) {
    const task = run.plan.tasks.find((candidate) => candidate.id === result.taskId);
    if (task) {
      if (result.error) {
        task.status = "BLOCKED";
        run.notes = uniqueStrings([...run.notes, `Worker ${result.worker} failed task ${result.taskId}: ${result.error}`]);
      } else {
        const reportedTokens = nonNegativeNumber(reported?.inputTokens, 0) + nonNegativeNumber(reported?.outputTokens, 0);
        if (reportedTokens > task.budgetTokens) {
          task.status = "BLOCKED";
          run.notes = uniqueStrings([...run.notes, `Worker ${result.worker} exceeded task budget: ${reportedTokens} > ${task.budgetTokens} tokens.`]);
        } else {
          task.status = "COMPLETED";
        }
      }
    }
  }
  if (run.plan.tasks.length > 0 && run.plan.tasks.every((task) => task.status === "COMPLETED") && run.coverage) {
    run.coverage = { ...run.coverage, semantic: "VALIDATED" };
  }
  run.completedAt = new Date().toISOString();
  return run;
}
