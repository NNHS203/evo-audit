import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import {
  groundTruthLabelsFromValue,
  scannerFindingsFromBandit,
  scannerFindingsFromRun,
  scannerFindingsFromSarif,
  scoreScannerFindings,
  type GroundTruthFormat,
  type ScannerScore,
} from "./scoring.js";
import type { AuditRun } from "./types.js";

export type BaselineArtifactFormat = "run" | "sarif" | "bandit";

export interface BaselineArtifactInput {
  name: string;
  file: string;
  format?: BaselineArtifactFormat;
  root?: string;
}

export interface BaselineArtifactProvenance {
  format: BaselineArtifactFormat;
  artifactPath: string;
  artifactSha256: string;
  scanner: string;
  runId?: string;
  snapshotTreeDigest?: string;
  snapshotRevision?: string | null;
  playbook?: { id: string; version: string };
  coverage?: AuditRun["coverage"];
  workerIds?: string[];
  providerModels?: string[];
  workerReceiptCount?: number;
  tokenAccounting?: AuditRun["tokenAccounting"];
  root?: string;
}

export interface BaselineComparisonEntry {
  name: string;
  provenance: BaselineArtifactProvenance;
  score: ScannerScore;
}

export interface BaselineComparisonReport {
  schemaVersion: 1;
  generatedAt: string;
  benchmark: {
    groundTruthPath: string;
    groundTruthSha256: string;
    groundTruthFormat: GroundTruthFormat;
    labels: number;
    vulnerableLabels: number;
    safeLabels: number;
    lineTolerance: number;
  };
  artifacts: BaselineComparisonEntry[];
  notes: string[];
}

export interface BaselineComparisonOptions {
  groundTruthFormat?: GroundTruthFormat;
  lineTolerance?: number;
}

function objectRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" ? value as Record<string, unknown> : null;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function hashBuffer(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function formatValue(value: string | undefined): BaselineArtifactFormat | undefined {
  if (value === "run" || value === "sarif" || value === "bandit") return value;
  return undefined;
}

function inferFormat(value: unknown): BaselineArtifactFormat {
  const root = objectRecord(value);
  if (typeof root?.runId === "string" && Array.isArray(root.findings)) return "run";
  if (Array.isArray(root?.runs)) return "sarif";
  if (Array.isArray(root?.results)) return "bandit";
  throw new Error("Unable to infer scanner artifact format; use run, sarif, or bandit explicitly.");
}

function scannerName(name: string, format: BaselineArtifactFormat, value: unknown): string {
  if (format !== "sarif") return name;
  const root = objectRecord(value);
  const runs = Array.isArray(root?.runs) ? root.runs : [];
  const names = runs.flatMap((run) => {
    const record = objectRecord(run);
    const tool = objectRecord(objectRecord(record?.tool)?.driver);
    return stringValue(tool?.name) ? [stringValue(tool?.name) as string] : [];
  });
  return [...new Set(names)].sort().join(", ") || name;
}

function runProvenance(run: AuditRun, name: string, file: string, hash: string): BaselineArtifactProvenance {
  const providerModels = [...new Set((run.workerReceipts ?? [])
    .map((receipt) => receipt.providerModel)
    .filter((model): model is string => typeof model === "string" && model.length > 0))].sort();
  const workerIds = [...new Set((run.workerReceipts ?? [])
    .map((receipt) => receipt.worker)
    .filter((worker): worker is string => typeof worker === "string" && worker.length > 0))].sort();
  return {
    format: "run",
    artifactPath: file,
    artifactSha256: hash,
    scanner: name,
    runId: run.runId,
    snapshotTreeDigest: run.snapshot.treeDigest,
    snapshotRevision: run.snapshot.revision,
    playbook: run.playbook,
    coverage: run.coverage,
    workerIds: workerIds.length > 0 ? workerIds : undefined,
    providerModels: providerModels.length > 0 ? providerModels : undefined,
    workerReceiptCount: run.workerReceipts?.length ?? 0,
    tokenAccounting: run.tokenAccounting,
  };
}

function artifactProvenance(
  input: BaselineArtifactInput,
  format: BaselineArtifactFormat,
  value: unknown,
  hash: string,
): BaselineArtifactProvenance {
  if (format === "run") return runProvenance(value as AuditRun, input.name, input.file, hash);
  return {
    format,
    artifactPath: input.file,
    artifactSha256: hash,
    scanner: scannerName(input.name, format, value),
    root: input.root,
  };
}

function findingsFor(
  value: unknown,
  format: BaselineArtifactFormat,
  scanner: string,
  root?: string,
): ReturnType<typeof scannerFindingsFromRun> {
  if (format === "run") return scannerFindingsFromRun(value as AuditRun, scanner);
  if (format === "bandit") return scannerFindingsFromBandit(value, scanner, root);
  return scannerFindingsFromSarif(value, scanner, root);
}

export async function compareBaselineScores(
  groundTruthFile: string,
  inputs: BaselineArtifactInput[],
  options: BaselineComparisonOptions = {},
): Promise<BaselineComparisonReport> {
  if (inputs.length === 0) throw new Error("At least one scanner artifact is required.");
  const names = new Set<string>();
  for (const input of inputs) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(input.name)) throw new Error(`Invalid scanner name: ${input.name}`);
    if (names.has(input.name)) throw new Error(`Duplicate scanner name: ${input.name}`);
    names.add(input.name);
    if (input.format && !formatValue(input.format)) throw new Error(`Unsupported scanner artifact format: ${input.format}`);
  }

  const groundTruthBuffer = await fs.readFile(groundTruthFile);
  const groundTruthValue = JSON.parse(groundTruthBuffer.toString("utf8")) as unknown;
  const groundTruthFormat = options.groundTruthFormat ?? "EVO";
  if (groundTruthFormat !== "EVO" && groundTruthFormat !== "REALVULN") throw new Error("groundTruthFormat must be EVO or REALVULN.");
  const labels = groundTruthLabelsFromValue(groundTruthValue, groundTruthFormat);
  const lineTolerance = Math.max(0, Math.floor(options.lineTolerance ?? 10));
  const artifacts: BaselineComparisonEntry[] = [];

  for (const input of [...inputs].sort((left, right) => left.name.localeCompare(right.name))) {
    const artifactBuffer = await fs.readFile(input.file);
    const value = JSON.parse(artifactBuffer.toString("utf8")) as unknown;
    const format = input.format ?? inferFormat(value);
    const provenance = artifactProvenance(input, format, value, hashBuffer(artifactBuffer));
    const scanner = provenance.scanner;
    const run = format === "run" ? value as AuditRun : undefined;
    const findings = findingsFor(value, format, scanner, input.root);
    const score = scoreScannerFindings(findings, labels, {
      scanner,
      lineTolerance,
      inputTokens: run?.tokenAccounting.inputTokens,
      outputTokens: run?.tokenAccounting.outputTokens,
      durationMs: run?.tokenAccounting.durationMs,
    });
    artifacts.push({ name: input.name, provenance, score });
  }

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    benchmark: {
      groundTruthPath: path.resolve(groundTruthFile),
      groundTruthSha256: hashBuffer(groundTruthBuffer),
      groundTruthFormat,
      labels: labels.length,
      vulnerableLabels: labels.filter((label) => label.vulnerable).length,
      safeLabels: labels.filter((label) => !label.vulnerable).length,
      lineTolerance,
    },
    artifacts,
    notes: [
      "All artifacts were scored against the same frozen ground-truth file and line tolerance.",
      "Candidate and reportable channels are separate; a static or external scanner finding is not treated as validated evidence unless the artifact marks it reportable.",
      "Missing coverage is not inferred as a true negative. Artifact hashes, run snapshots, playbooks, and model receipts are retained where the format provides them.",
      "This report is a reproducible comparison record, not a claim that any scanner is universally superior.",
    ],
  };
}
