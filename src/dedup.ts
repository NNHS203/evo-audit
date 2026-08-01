import { createHash } from "node:crypto";
import type { AuditDedup, AuditDedupGroup, AuditRun, EvidenceItem, Finding, FindingStatus } from "./types.js";

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

const evidenceRank = { T0_HYPOTHESIS: 0, T1_STATIC_PATH: 1, T2_REPRODUCIBLE: 2 } as const;

function normalize(value: string): string {
  return value.toLowerCase().replace(/\s+/g, " ").trim();
}

export function findingDedupKey(finding: Finding): string {
  const locations = finding.locations
    .map((location) => `${location.file}|${normalize(location.snippet)}`)
    .sort()
    .join(",");
  return createHash("sha256")
    .update([finding.ruleId, normalize(finding.rootCause), normalize(finding.impact), locations].join("|"), "utf8")
    .digest("hex")
    .slice(0, 24);
}

function duplicateEvidence(canonical: Finding, duplicate: Finding): EvidenceItem {
  return {
    type: "LIMITATION",
    title: "Deterministic duplicate cluster",
    detail: `Finding ${duplicate.id} was clustered under ${canonical.id} because its rule, root-cause/impact summary, and source snippets match. Separate sink snippets remain separate instances.`,
    locations: duplicate.locations,
    reproducible: false,
  };
}

function canonicalSort(left: Finding, right: Finding): number {
  return statusRank[right.status] - statusRank[left.status]
    || evidenceRank[right.evidenceTier] - evidenceRank[left.evidenceTier]
    || left.id.localeCompare(right.id);
}

export function deduplicateRun(runInput: AuditRun): AuditRun {
  const run = structuredClone(runInput);
  const groups = new Map<string, Finding[]>();
  for (const finding of run.findings) {
    const key = findingDedupKey(finding);
    const list = groups.get(key) ?? [];
    list.push(finding);
    groups.set(key, list);
  }
  const dedupGroups: AuditDedupGroup[] = [];
  for (const [key, findings] of groups) {
    if (findings.length < 2) continue;
    const ordered = [...findings].sort(canonicalSort);
    const canonical = ordered[0];
    const duplicateIds: string[] = [];
    for (const duplicate of ordered.slice(1)) {
      duplicateIds.push(duplicate.id);
      duplicate.status = "DUPLICATE";
      duplicate.evidence = [...duplicate.evidence, duplicateEvidence(canonical, duplicate)];
      duplicate.limitations = [...new Set([...duplicate.limitations, `Clustered under duplicate canonical finding ${canonical.id}.`])];
      const obligation = run.obligations.find((candidate) => candidate.id === duplicate.obligationId);
      if (obligation && obligation.status === "OPEN") obligation.status = "REJECTED";
    }
    dedupGroups.push({
      key,
      canonicalFindingId: canonical.id,
      duplicateFindingIds: duplicateIds,
      reason: "Same rule, normalized root-cause/impact, and source snippets; distinct sink/source snippets remain separate.",
    });
  }
  dedupGroups.sort((left, right) => left.key.localeCompare(right.key));
  const dedup: AuditDedup = { schemaVersion: 1, groups: dedupGroups };
  run.dedup = dedup;
  const duplicateIds = new Set(dedupGroups.flatMap((group) => group.duplicateFindingIds));
  run.reportableFindingIds = run.reportableFindingIds.filter((id) => !duplicateIds.has(id));
  if (dedupGroups.length > 0) run.notes = [...new Set([...run.notes, `Deterministic dedup clustered ${duplicateIds.size} duplicate finding instance(s) into ${dedupGroups.length} group(s).`])];
  return run;
}
