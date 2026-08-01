import type { AuditRun, AuditObligation, AuditTask, Finding } from "./types.js";
import { buildAuditPlan } from "./workflow.js";

export interface ResumePlan {
  schemaVersion: 1;
  runId: string;
  baseTreeDigest: string | null;
  coverageComplete: boolean;
  coverageSemantic: "STATIC_ONLY" | "PARTIAL_WORKER" | "VALIDATED" | "UNKNOWN";
  pendingObligations: Array<Pick<AuditObligation, "id" | "kind" | "title" | "status" | "targetFiles" | "falsifiers" | "evidenceRequired">>;
  findingsToValidate: Array<Pick<Finding, "id" | "ruleId" | "title" | "severity" | "obligationId" | "locations" | "limitations">>;
  workflow: {
    tokenBudget: number;
    allocatedTokens: number;
    unallocatedTokens: number;
    pendingTasks: Array<Pick<AuditTask, "id" | "phase" | "findingId" | "obligationId" | "title" | "priority" | "status" | "budgetTokens" | "context" | "dependsOn">>;
  };
  notes: string[];
}

export function buildResumePlan(run: AuditRun): ResumePlan {
  const workflow = run.plan ?? buildAuditPlan(run);
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
    coverageSemantic: run.coverage?.semantic ?? "UNKNOWN",
    pendingObligations,
    findingsToValidate,
    workflow: {
      tokenBudget: workflow.tokenBudget,
      allocatedTokens: workflow.allocatedTokens,
      unallocatedTokens: workflow.unallocatedTokens,
      pendingTasks: workflow.tasks.filter((task) => task.status !== "COMPLETED").map(({ id, phase, findingId, obligationId, title, priority, status, budgetTokens, context, dependsOn }) => ({
        id,
        phase,
        findingId,
        obligationId,
        title,
        priority,
        status,
        budgetTokens,
        context,
        dependsOn,
      })),
    },
    notes: [
      "Resume work must use the same base snapshot; changed files invalidate validation requests.",
      "Unknown coverage must remain visible and must not be interpreted as a clean audit.",
    ],
  };
}
