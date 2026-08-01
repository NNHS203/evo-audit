import { createHash } from "node:crypto";
import type { AuditRun, Finding } from "./types.js";

export type FindingLifecycle = "NEW" | "PERSISTING" | "REOPENED" | "RESOLVED" | "UNKNOWN";

export interface FindingComparison {
  identity: string;
  lifecycle: FindingLifecycle;
  before?: Finding;
  after?: Finding;
}

export interface RunComparison {
  schemaVersion: 1;
  beforeRunId: string;
  afterRunId: string;
  coverage: {
    complete: boolean;
    note: string;
  };
  findings: FindingComparison[];
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/\s+/g, " ").replace(/\bline\s+\d+\b/g, "line").trim();
}

export function findingIdentity(finding: Finding): string {
  const files = finding.locations.map((location) => location.file).sort().join(",");
  return createHash("sha256")
    .update([finding.ruleId, normalize(finding.rootCause), normalize(finding.impact), files].join("|"), "utf8")
    .digest("hex")
    .slice(0, 24);
}

function indexFindings(findings: Finding[]): Map<string, Finding> {
  const output = new Map<string, Finding>();
  for (const finding of findings) output.set(findingIdentity(finding), finding);
  return output;
}

export function compareRuns(before: AuditRun, after: AuditRun): RunComparison {
  const beforeFindings = indexFindings(before.findings);
  const afterFindings = indexFindings(after.findings);
  const identities = new Set([...beforeFindings.keys(), ...afterFindings.keys()]);
  const afterCoverageComplete = after.coverage?.complete === true;
  const afterSemantic = after.coverage?.semantic ?? "STATIC_ONLY";
  const findings: FindingComparison[] = [];

  for (const identity of identities) {
    const previous = beforeFindings.get(identity);
    const current = afterFindings.get(identity);
    let lifecycle: FindingLifecycle;
    if (!previous && current) lifecycle = "NEW";
    else if (previous && !current) {
      lifecycle = !afterCoverageComplete || (previous.status === "VERIFIED" && afterSemantic !== "VALIDATED") ? "UNKNOWN" : "RESOLVED";
    }
    else if (previous && current && previous.status === "VERIFIED" && current.status !== "VERIFIED") lifecycle = "REOPENED";
    else lifecycle = "PERSISTING";
    findings.push({ identity, lifecycle, before: previous, after: current });
  }

  const order: Record<FindingLifecycle, number> = { NEW: 0, REOPENED: 1, PERSISTING: 2, UNKNOWN: 3, RESOLVED: 4 };
  findings.sort((left, right) => order[left.lifecycle] - order[right.lifecycle] || left.identity.localeCompare(right.identity));
  return {
    schemaVersion: 1,
    beforeRunId: before.runId,
    afterRunId: after.runId,
    coverage: {
      complete: afterCoverageComplete,
      note: afterCoverageComplete
        ? `Missing unverified candidates may be treated as resolved because the after run declares complete file coverage (${afterSemantic}); previously VERIFIED findings remain UNKNOWN until revalidation is complete.`
        : "Missing findings remain UNKNOWN because the after run does not prove complete coverage.",
    },
    findings,
  };
}
