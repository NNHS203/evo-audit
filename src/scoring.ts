import type { AuditRun, Finding } from "./types.js";
import path from "node:path";

export interface GroundTruthLabel {
  id: string;
  vulnerable: boolean;
  file: string;
  startLine: number;
  endLine?: number;
  ruleIds?: string[];
  alternateLocations?: Array<{ file: string; startLine: number; endLine?: number }>;
}

export interface ScannerLocation {
  file: string;
  startLine: number;
  endLine: number;
}

export interface NormalizedScannerFinding {
  id: string;
  scanner: string;
  ruleId: string;
  ruleIds?: string[];
  locations: ScannerLocation[];
  reportable: boolean;
  unsupportedClaim: boolean;
}

export interface ScoreCounts {
  truePositive: number;
  falsePositive: number;
  falseNegative: number;
  trueNegative: number;
  precision: number;
  recall: number;
  falsePositiveRate: number;
  f3: number;
  candidateCount: number;
  validatedCount: number;
  tokensPerValidatedFinding: number | null;
}

export interface ScannerScore {
  schemaVersion: 1;
  scanner: string;
  labels: number;
  vulnerableLabels: number;
  safeLabels: number;
  findings: number;
  unsupportedClaimCount: number;
  unsupportedClaimRate: number;
  candidate: ScoreCounts;
  reportable: ScoreCounts;
  inputTokens: number;
  outputTokens: number;
  durationMs: number;
  notes: string[];
}

export interface ScoreOptions {
  scanner?: string;
  lineTolerance?: number;
  inputTokens?: number;
  outputTokens?: number;
  durationMs?: number;
}

export type GroundTruthFormat = "EVO" | "REALVULN";

function recordValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" ? value as Record<string, unknown> : null;
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const values = value.filter((item): item is string => typeof item === "string" && item.length > 0);
  return values.length > 0 ? values : undefined;
}

export function groundTruthLabelsFromValue(value: unknown, format: GroundTruthFormat = "EVO"): GroundTruthLabel[] {
  const root = recordValue(value);
  if (format === "REALVULN") {
    const findings = Array.isArray(root?.findings) ? root.findings : [];
    return findings.map((item, index) => {
      const entry = recordValue(item);
      const location = recordValue(entry?.location);
      const file = typeof entry?.file === "string" ? entry.file : undefined;
      const startLine = typeof location?.start_line === "number" ? location.start_line : typeof entry?.start_line === "number" ? entry.start_line : undefined;
      if (!entry || typeof entry.id !== "string" || typeof entry.is_vulnerable !== "boolean" || !file || startLine === undefined) throw new Error(`Invalid RealVuln ground-truth entry at index ${index}.`);
      const endLine = typeof location?.end_line === "number" ? location.end_line : typeof entry.end_line === "number" ? entry.end_line : undefined;
      const ruleIds = [entry.primary_cwe, ...(stringArray(entry.acceptable_cwes) ?? [])].filter((item): item is string => typeof item === "string" && item.length > 0);
      const alternateLocations: Array<{ file: string; startLine: number; endLine?: number }> = [];
      if (Array.isArray(entry.acceptable_locations)) {
        for (const candidate of entry.acceptable_locations) {
          const alternative = recordValue(candidate);
          const alternativeLocation = alternative ? recordValue(alternative.location) : null;
          const alternativeFile = typeof alternative?.file === "string" ? alternative.file : undefined;
          const alternativeStart = typeof alternativeLocation?.start_line === "number" ? alternativeLocation.start_line : typeof alternative?.start_line === "number" ? alternative.start_line : undefined;
          const alternativeEnd = typeof alternativeLocation?.end_line === "number" ? alternativeLocation.end_line : typeof alternative?.end_line === "number" ? alternative.end_line : undefined;
          if (alternativeFile && alternativeStart !== undefined) alternateLocations.push({ file: alternativeFile, startLine: alternativeStart, ...(alternativeEnd === undefined ? {} : { endLine: alternativeEnd }) });
        }
      }
      const label = { id: entry.id, vulnerable: entry.is_vulnerable, file, startLine, endLine, ruleIds: ruleIds.length > 0 ? [...new Set(ruleIds)] : undefined };
      return alternateLocations.length > 0 ? { ...label, alternateLocations } : label;
    });
  }
  const raw = Array.isArray(value) ? value : Array.isArray(root?.labels) ? root.labels : null;
  if (!raw) throw new Error("Ground truth must be an array or an object with a labels array.");
  return raw.map((item, index) => {
    const label = recordValue(item);
    if (!label || typeof label.id !== "string" || typeof label.vulnerable !== "boolean" || typeof label.file !== "string" || typeof label.startLine !== "number") throw new Error(`Invalid ground-truth label at index ${index}.`);
    return { id: label.id, vulnerable: label.vulnerable, file: label.file, startLine: label.startLine, endLine: typeof label.endLine === "number" ? label.endLine : undefined, ruleIds: stringArray(label.ruleIds) };
  });
}

function normalizedFile(value: string): string {
  try {
    value = decodeURIComponent(value);
  } catch {
    // Keep an undecodable URI visible; it will fail closed during matching.
  }
  return value
    .replace(/^file:\/\//i, "")
    .replace(/\\/g, "/")
    .replace(/^\.\//, "")
    .replace(/^\/+/, "");
}

function relativeScannerFile(value: string, root?: string): string {
  if (!root || !path.isAbsolute(value)) return value;
  const relative = path.relative(path.resolve(root), path.resolve(value)).split(path.sep).join("/");
  return relative && !relative.startsWith("../") && relative !== ".." ? relative : value;
}

function nonNegative(value: number | undefined): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : 0;
}

function f3(precision: number, recall: number): number {
  if (precision + recall === 0) return 0;
  return (10 * precision * recall) / (9 * precision + recall);
}

function locationMatches(finding: NormalizedScannerFinding, label: GroundTruthLabel, lineTolerance: number): boolean {
  const expectedLocations = [{ file: label.file, startLine: label.startLine, endLine: label.endLine }, ...(label.alternateLocations ?? [])];
  return expectedLocations.some((expected) => {
    const expectedStart = Math.max(1, Math.floor(expected.startLine));
    const expectedEnd = Math.max(expectedStart, Math.floor(expected.endLine ?? expected.startLine));
    return finding.locations.some((location) => {
      if (normalizedFile(location.file) !== normalizedFile(expected.file)) return false;
      const actualStart = Math.max(1, Math.floor(location.startLine));
      const actualEnd = Math.max(actualStart, Math.floor(location.endLine));
      return actualStart <= expectedEnd + lineTolerance && actualEnd >= expectedStart - lineTolerance;
    });
  });
}

function matches(finding: NormalizedScannerFinding, label: GroundTruthLabel, lineTolerance: number): boolean {
  if (label.ruleIds && label.ruleIds.length > 0) {
    const findingRuleIds = new Set([finding.ruleId, ...(finding.ruleIds ?? [])]);
    if (!label.ruleIds.some((ruleId) => findingRuleIds.has(ruleId))) return false;
  }
  return locationMatches(finding, label, lineTolerance);
}

function matchSpecificity(finding: NormalizedScannerFinding, label: GroundTruthLabel): number {
  if (!label.ruleIds || label.ruleIds.length === 0) return 0;
  const findingRuleIds = new Set([finding.ruleId, ...(finding.ruleIds ?? [])]);
  if (findingRuleIds.has(label.ruleIds[0])) return 2;
  return label.ruleIds.some((ruleId) => findingRuleIds.has(ruleId)) ? 1 : -1;
}

function emptyCounts(): ScoreCounts {
  return {
    truePositive: 0,
    falsePositive: 0,
    falseNegative: 0,
    trueNegative: 0,
    precision: 0,
    recall: 0,
    falsePositiveRate: 0,
    f3: 0,
    candidateCount: 0,
    validatedCount: 0,
    tokensPerValidatedFinding: null,
  };
}

function scoreChannel(
  findings: NormalizedScannerFinding[],
  labels: GroundTruthLabel[],
  lineTolerance: number,
  inputTokens: number,
  outputTokens: number,
  hasTokenData: boolean,
): ScoreCounts {
  const counts = emptyCounts();
  const availableLabels = labels
    .map((label, index) => ({ label, index }))
    .sort((left, right) => Number(right.label.vulnerable) - Number(left.label.vulnerable) || left.index - right.index);
  const matched = new Set<number>();
  counts.candidateCount = findings.length;
  counts.validatedCount = findings.filter((finding) => finding.reportable).length;

  for (const finding of findings) {
    const match = availableLabels
      .filter((candidate) => !matched.has(candidate.index) && matches(finding, candidate.label, lineTolerance))
      .sort((left, right) => matchSpecificity(finding, right.label) - matchSpecificity(finding, left.label) || Number(right.label.vulnerable) - Number(left.label.vulnerable) || left.index - right.index)[0];
    if (!match) {
      counts.falsePositive += 1;
      continue;
    }
    matched.add(match.index);
    if (match.label.vulnerable) counts.truePositive += 1;
    else counts.falsePositive += 1;
  }
  for (const item of availableLabels) {
    if (matched.has(item.index)) continue;
    if (item.label.vulnerable) counts.falseNegative += 1;
    else counts.trueNegative += 1;
  }
  const positivePredictions = counts.truePositive + counts.falsePositive;
  const actualPositives = counts.truePositive + counts.falseNegative;
  const negativeLabels = counts.trueNegative + counts.falsePositive;
  counts.precision = positivePredictions === 0 ? 0 : counts.truePositive / positivePredictions;
  counts.recall = actualPositives === 0 ? 0 : counts.truePositive / actualPositives;
  counts.falsePositiveRate = negativeLabels === 0 ? 0 : counts.falsePositive / negativeLabels;
  counts.f3 = f3(counts.precision, counts.recall);
  counts.tokensPerValidatedFinding = hasTokenData && counts.truePositive > 0 ? (inputTokens + outputTokens) / counts.truePositive : null;
  return counts;
}

export function scoreScannerFindings(findings: NormalizedScannerFinding[], labels: GroundTruthLabel[], options: ScoreOptions = {}): ScannerScore {
  const scanner = options.scanner ?? findings[0]?.scanner ?? "unknown-scanner";
  const lineTolerance = Math.max(0, Math.floor(options.lineTolerance ?? 10));
  const inputTokens = nonNegative(options.inputTokens);
  const outputTokens = nonNegative(options.outputTokens);
  const durationMs = nonNegative(options.durationMs);
  const hasTokenData = options.inputTokens !== undefined || options.outputTokens !== undefined;
  const candidate = scoreChannel(findings, labels, lineTolerance, inputTokens, outputTokens, hasTokenData);
  const reportable = scoreChannel(findings.filter((finding) => finding.reportable), labels, lineTolerance, inputTokens, outputTokens, hasTokenData);
  const unsupportedClaimCount = findings.filter((finding) => finding.unsupportedClaim).length;
  return {
    schemaVersion: 1,
    scanner,
    labels: labels.length,
    vulnerableLabels: labels.filter((label) => label.vulnerable).length,
    safeLabels: labels.filter((label) => !label.vulnerable).length,
    findings: findings.length,
    unsupportedClaimCount,
    unsupportedClaimRate: findings.length === 0 ? 0 : unsupportedClaimCount / findings.length,
    candidate,
    reportable,
    inputTokens,
    outputTokens,
    durationMs,
    notes: [
      `Matching uses normalized file paths, rule IDs when supplied, and a +/-${lineTolerance}-line tolerance.`,
      "Each ground-truth label can be matched once; unmatched scanner findings count as false positives.",
      "Candidate and reportable channels are scored separately; reportable means explicit evidence-gated output.",
    ],
  };
}

function firstLocation(finding: Finding): ScannerLocation[] {
  return finding.locations.map((location) => ({ file: location.file, startLine: location.line, endLine: location.endLine }));
}

function ruleAliases(ruleId: string): string[] {
  if (ruleId.includes("COMMAND-INJECTION")) return ["CWE-78"];
  if (ruleId.includes("DYNAMIC-CODE")) return ["CWE-95"];
  if (ruleId.includes("SQL-INJECTION")) return ["CWE-89"];
  if (ruleId.includes("OPEN-REDIRECT")) return ["CWE-601"];
  if (ruleId.includes("SSRF")) return ["CWE-918"];
  if (ruleId.includes("SSTI")) return ["CWE-1336"];
  if (ruleId.includes("XXE")) return ["CWE-611"];
  if (ruleId.includes("UNSAFE-DESERIALIZATION")) return ["CWE-502"];
  if (ruleId.includes("REFLECTED-XSS")) return ["CWE-79", "CWE-80"];
  if (ruleId.includes("CLEARTEXT-PASSWORD")) return ["CWE-256", "CWE-257", "CWE-522", "CWE-312"];
  if (ruleId.includes("MISSING-AUTH")) return ["CWE-306", "CWE-862", "CWE-287", "CWE-284"];
  if (ruleId.includes("PATH-TRAVERSAL")) return ["CWE-22"];
  if (ruleId.includes("HARDCODED-CREDENTIAL")) return ["CWE-798", "CWE-259", "CWE-321"];
  if (ruleId.includes("DEBUG-MODE")) return ["CWE-215", "CWE-489", "CWE-16"];
  return [];
}

export function scannerFindingsFromRun(run: AuditRun, scanner = "evo-audit"): NormalizedScannerFinding[] {
  const reportableIds = new Set(run.reportableFindingIds ?? []);
  return run.findings.map((finding) => ({
    id: finding.id,
    scanner,
    ruleId: finding.ruleId,
    ruleIds: [finding.ruleId, ...ruleAliases(finding.ruleId)],
    locations: firstLocation(finding),
    reportable: reportableIds.has(finding.id) && finding.status === "VERIFIED" && finding.evidenceTier === "T2_REPRODUCIBLE",
    unsupportedClaim: finding.status === "VERIFIED" && !(reportableIds.has(finding.id) && finding.evidenceTier === "T2_REPRODUCIBLE"),
  }));
}

function objectRecord(value: unknown): Record<string, unknown> | null {
  return recordValue(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

export function scannerFindingsFromSarif(value: unknown, scanner = "sarif-scanner", rootPath?: string): NormalizedScannerFinding[] {
  const root = objectRecord(value);
  const runs = Array.isArray(root?.runs) ? root.runs : [];
  const findings: NormalizedScannerFinding[] = [];
  let index = 0;
  for (const run of runs) {
    const runRecord = objectRecord(run);
    const tool = objectRecord(objectRecord(runRecord?.tool)?.driver);
    const toolName = stringValue(tool?.name);
    const results = Array.isArray(runRecord?.results) ? runRecord.results : [];
    for (const result of results) {
      const item = objectRecord(result);
      if (!item) continue;
      const locations: ScannerLocation[] = [];
      for (const location of Array.isArray(item.locations) ? item.locations : []) {
        const locationRecord = objectRecord(location);
        const physical = objectRecord(locationRecord?.physicalLocation);
        const artifact = objectRecord(physical?.artifactLocation);
        const region = objectRecord(physical?.region);
        const file = stringValue(artifact?.uri);
        const startLine = numberValue(region?.startLine);
        if (!file || !startLine) continue;
        locations.push({ file: relativeScannerFile(file, rootPath), startLine, endLine: numberValue(region?.endLine) ?? startLine });
      }
      if (locations.length === 0) continue;
      const properties = objectRecord(item.properties);
      const reportable = properties?.reportable === true || properties?.reportable === "true";
      findings.push({
        id: stringValue(item.id) ?? stringValue(objectRecord(item.fingerprints)?.primaryLocationLineHash) ?? `${scanner}:${index}`,
        scanner: toolName ?? scanner,
        ruleId: stringValue(item.ruleId) ?? "UNKNOWN-RULE",
        ruleIds: stringArray(properties?.cwe),
        locations,
        reportable,
        unsupportedClaim: properties?.status === "VERIFIED" && !reportable,
      });
      index += 1;
    }
  }
  return findings;
}

export function scannerFindingsFromBandit(value: unknown, scanner = "bandit", rootPath?: string): NormalizedScannerFinding[] {
  const root = objectRecord(value);
  const results = Array.isArray(root?.results) ? root.results : [];
  return results.flatMap((result, index) => {
    const item = objectRecord(result);
    if (!item) return [];
    const file = stringValue(item.filename);
    const line = numberValue(item.line_number);
    if (!file || line === undefined) return [];
    const cwe = objectRecord(item.issue_cwe);
    const cweId = numberValue(cwe?.id);
    const testId = stringValue(item.test_id) ?? "UNKNOWN-RULE";
    const lineRange = Array.isArray(item.line_range) ? numberValue(item.line_range[0]) : undefined;
    return [{
      id: stringValue(item.test_id) ? `${scanner}:${item.test_id}:${file}:${line}:${index}` : `${scanner}:${index}`,
      scanner,
      ruleId: testId,
      ruleIds: [testId, ...(cweId === undefined ? [] : [`CWE-${cweId}`])],
      locations: [{ file: relativeScannerFile(file, rootPath), startLine: line, endLine: lineRange ?? line }],
      reportable: false,
      unsupportedClaim: false,
    }];
  });
}
