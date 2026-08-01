import type { AuditRun, AuditObligation, Finding } from "./types.js";

export interface ResumePlan {
  schemaVersion: 1;
  runId: string;
  baseTreeDigest: string | null;
  coverageComplete: boolean;
  pendingObligations: Array<Pick<AuditObligation, "id" | "kind" | "title" | "status" | "targetFiles" | "falsifiers" | "evidenceRequired">>;
  findingsToValidate: Array<Pick<Finding, "id" | "ruleId" | "title" | "severity" | "obligationId" | "locations" | "limitations">>;
  notes: string[];
}

export function buildResumePlan(run: AuditRun): ResumePlan {
  const pendingObligations = run.obligations
    .filter((obligation) => obligation.status !== "SATISFIED" && obligation.status !== "REJECTED")
    .map(({ id, kind, title, status, targetFiles, falsifiers, evidenceRequired }) => ({ id, kind, title, status, targetFiles, falsifiers, evidenceRequired }));
  const findingsToValidate = run.findings
    .filter((finding) => finding.status === "SUSPECTED" || finding.status === "SUPPORTED" || finding.status === "UNKNOWN")
    .map(({ id, ruleId, title, severity, obligationId, locations, limitations }) => ({ id, ruleId, title, severity, obligationId, locations, limitations }));

  return {
    schemaVersion: 1,
    runId: run.runId,
    baseTreeDigest: run.snapshot?.treeDigest ?? null,
    coverageComplete: run.coverage?.complete === true,
    pendingObligations,
    findingsToValidate,
    notes: [
      "Resume work must use the same base snapshot; changed files invalidate validation requests.",
      "Unknown coverage must remain visible and must not be interpreted as a clean audit.",
    ],
  };
}
