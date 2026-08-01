import { createHash } from "node:crypto";
import { compareRuns, type FindingComparison, type RunComparison } from "./compare.js";
import type { AuditRun } from "./types.js";

export type RevalidationAction =
  | "VALIDATE_NEW"
  | "REVALIDATE"
  | "INVESTIGATE_COVERAGE"
  | "BLOCKING_REGRESSION"
  | "NO_ACTION";

export interface RevalidationItem {
  identity: string;
  lifecycle: FindingComparison["lifecycle"];
  action: RevalidationAction;
  reason: string;
  beforeFindingId?: string;
  afterFindingId?: string;
}

export interface RevalidationPlan {
  schemaVersion: 1;
  planId: string;
  generatedAt: string;
  beforeRunId: string;
  afterRunId: string;
  status: "PASS" | "ACTION_REQUIRED";
  comparison: RunComparison;
  items: RevalidationItem[];
  requiredFindingIds: string[];
  blockingIdentities: string[];
  notes: string[];
}

function planId(before: AuditRun, after: AuditRun): string {
  return createHash("sha256").update(`${before.runId}\0${after.runId}`, "utf8").digest("hex").slice(0, 24);
}

function itemAction(item: FindingComparison, after: AuditRun): { action: RevalidationAction; reason: string } {
  if (item.lifecycle === "NEW") return { action: "VALIDATE_NEW", reason: "The after run contains a new root cause that has not been independently validated." };
  if (item.lifecycle === "REOPENED") return { action: "REVALIDATE", reason: "A previously verified root cause is present again without current VERIFIED evidence." };
  if (item.lifecycle === "UNKNOWN") return { action: "REVALIDATE", reason: "The after run does not prove that a previously verified root cause was fixed." };
  if (item.lifecycle === "PERSISTING" && item.before?.status === "VERIFIED" && item.after?.status === "VERIFIED") {
    return { action: "BLOCKING_REGRESSION", reason: "The same vulnerability remains VERIFIED after the proposed change." };
  }
  if (item.lifecycle === "PERSISTING" && item.after && item.after.status !== "VERIFIED") {
    return { action: "REVALIDATE", reason: "The root cause persists as a candidate and needs current-snapshot validation." };
  }
  if (item.lifecycle === "RESOLVED" && after.coverage.semantic !== "VALIDATED") {
    return { action: "INVESTIGATE_COVERAGE", reason: "The finding disappeared, but the after run does not have validated semantic coverage." };
  }
  return { action: "NO_ACTION", reason: "The after run has complete validated coverage for this identity." };
}

export function buildRevalidationPlan(before: AuditRun, after: AuditRun): RevalidationPlan {
  const comparison = compareRuns(before, after);
  const items = comparison.findings.map((finding) => {
    const selected = itemAction(finding, after);
    return {
      identity: finding.identity,
      lifecycle: finding.lifecycle,
      action: selected.action,
      reason: selected.reason,
      beforeFindingId: finding.before?.id,
      afterFindingId: finding.after?.id,
    };
  });
  const actionable = items.filter((item) => item.action !== "NO_ACTION");
  const requiredFindingIds = actionable
    .map((item) => item.afterFindingId ?? item.beforeFindingId)
    .filter((id): id is string => Boolean(id));
  const blockingIdentities = items.filter((item) => item.action === "BLOCKING_REGRESSION").map((item) => item.identity);
  return {
    schemaVersion: 1,
    planId: planId(before, after),
    generatedAt: new Date().toISOString(),
    beforeRunId: before.runId,
    afterRunId: after.runId,
    status: actionable.length === 0 ? "PASS" : "ACTION_REQUIRED",
    comparison,
    items,
    requiredFindingIds: [...new Set(requiredFindingIds)],
    blockingIdentities,
    notes: [
      "A missing finding is not treated as fixed unless the after run proves complete validated semantic coverage.",
      "Use verify against the after run to create a fresh request, then validate it with an independent validator.",
      ...(blockingIdentities.length > 0 ? ["The after run still contains a VERIFIED vulnerability; this plan is a release-blocking regression."] : []),
    ],
  };
}

