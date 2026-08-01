import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import type { AuditCodeGraph } from "./graph.js";

export interface ThreatModelOverrides {
  schemaVersion: 1;
  assumptions?: string[];
  exclusions?: string[];
  attackerControlledInputs?: string[];
  operatorControlledInputs?: string[];
  deploymentNotes?: string[];
}

export interface AuditThreatModel {
  schemaVersion: 1;
  repository: string;
  version: string;
  source: "GENERATED" | "USER_EDITED";
  overview: string;
  attackerProfiles: string[];
  trustBoundaries: Array<{ name: string; from: string; to: string; controls: string[] }>;
  assets: string[];
  attackerControlledInputs: string[];
  operatorControlledInputs: string[];
  assumptions: string[];
  exclusions: string[];
  attackSurfaces: Array<{ file: string; signals: string[] }>;
  mitigations: string[];
  attackerStories: string[];
  severityCalibration: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW", string[]>;
  digest: string;
}

export function defaultThreatModelOverrides(): ThreatModelOverrides {
  return { schemaVersion: 1, assumptions: [], exclusions: [], attackerControlledInputs: [], operatorControlledInputs: [], deploymentNotes: [] };
}

async function loadOverrides(root: string): Promise<ThreatModelOverrides> {
  try {
    const parsed = JSON.parse(await fs.readFile(path.join(root, "audit.threat.json"), "utf8")) as ThreatModelOverrides;
    if (parsed.schemaVersion !== 1) throw new Error("Unsupported audit.threat.json schemaVersion; expected 1.");
    return { ...defaultThreatModelOverrides(), ...parsed };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return defaultThreatModelOverrides();
    throw error;
  }
}

function unique(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

export async function buildThreatModel(
  root: string,
  version: string,
  entries: string[],
  surface: Array<{ file: string; signals: string[] }>,
  codeGraph: AuditCodeGraph,
): Promise<AuditThreatModel> {
  const overrides = await loadOverrides(root);
  const hasHttp = surface.some((item) => item.signals.includes("http-entrypoint"));
  const sinkNames = codeGraph.nodes.filter((node) => node.kind === "SINK").map((node) => `${node.name} (${node.file}:${node.line})`);
  const generatedInputs = hasHttp ? ["HTTP request body, query, params, headers, cookies, and uploaded files"] : ["Values crossing public function, CLI, file, or package API boundaries"];
  const generatedAssumptions = [
    "The audited snapshot is the source of truth for code and configuration visible to this run.",
    "Model output is untrusted analysis data and cannot create validation evidence.",
    "Execution-capable validation must remain isolated from the developer host and production credentials.",
  ];
  const model: Omit<AuditThreatModel, "digest"> = {
    schemaVersion: 1,
    repository: path.basename(path.resolve(root)),
    version,
    source: overrides.assumptions?.length || overrides.exclusions?.length || overrides.deploymentNotes?.length || overrides.attackerControlledInputs?.length || overrides.operatorControlledInputs?.length ? "USER_EDITED" : "GENERATED",
    overview: "Evo Audit analyzes source code and worker claims locally, then requires an independent validator before a vulnerability becomes reportable.",
    attackerProfiles: hasHttp
      ? ["Unauthenticated or low-privilege remote requester", "Authenticated user crossing an authorization boundary", "Tenant or user attempting to influence another tenant/user path"]
      : ["Caller supplying untrusted input through the exposed package, CLI, file, or integration boundary", "Malicious repository content attempting to influence the audit harness"],
    trustBoundaries: [
      { name: "Repository to audit harness", from: "Repository source/configuration", to: "Evo Audit parser, graph, detector, and worker prompt", controls: ["Pinned file fingerprints", "Snapshot tree digest", "Bounded context slices"] },
      { name: "Worker model boundary", from: "Audit snapshot and task context", to: "Configured API/OAuth/local model", controls: ["Credential references instead of raw secrets", "Token budget", "Structured JSON protocol", "Worker claims remain evidence-gated"] },
      { name: "Validator boundary", from: "Candidate finding and reproducer", to: "Isolated container runtime", controls: ["Read-only source mount", "Network disabled", "Dropped capabilities", "Resource limits", "Independent validator identity"] },
      { name: "Audit output boundary", from: "Run artifacts", to: "Human/CI/report consumers", controls: ["Coverage state", "Unknown/deferred visibility", "Reportable IDs require T2/VERIFIED evidence"] },
    ],
    assets: [
      "Source code confidentiality and integrity",
      "Credentials and model access tokens",
      "Validator host and container isolation",
      "Correctness of vulnerability evidence and reportable findings",
      "Snapshot, token, and audit trail integrity",
    ],
    attackerControlledInputs: unique([...generatedInputs, ...(overrides.attackerControlledInputs ?? [])]),
    operatorControlledInputs: unique(["Playbook rules and evidence policy", "Model/provider configuration references", "Validator commands and sandbox image", ...(overrides.operatorControlledInputs ?? [])]),
    assumptions: unique([...generatedAssumptions, ...(overrides.assumptions ?? []), ...(overrides.deploymentNotes ?? [])]),
    exclusions: unique(["A static no-match result is not a safety proof.", "The harness does not claim to enumerate every vulnerability in an unlabeled repository.", ...(overrides.exclusions ?? [])]),
    attackSurfaces: surface,
    mitigations: [
      "Deterministic AST/data-flow candidates provide source and sink locations before model reasoning.",
      "Coverage matrix generates HUNT work for empty areas and keeps UNKNOWN visible.",
      "Independent validation checks snapshot fingerprints, evidence locations, sandbox policy, reproducer, and negative control.",
      "Dedup and worker receipts reduce duplicate findings and duplicate token spend without collapsing distinct snippets.",
      ...entries.map((entry) => `Entrypoint candidate: ${entry}`),
    ],
    attackerStories: [
      "A remote input reaches a dynamic-code, command, query, redirect, or outbound-request sink through helper indirection.",
      "A missing authorization guard exposes a sensitive state change or cross-tenant object.",
      "A malicious or stale worker claim attempts to become VERIFIED without matching the pinned snapshot.",
      "A validation command attempts to escape the source mount, network boundary, or resource budget.",
      ...(sinkNames.length > 0 ? [`Observed sink candidates requiring review: ${sinkNames.slice(0, 24).join(", ")}`] : []),
    ],
    severityCalibration: {
      CRITICAL: ["Confirmed unauthenticated remote code execution, sandbox escape, or cross-tenant compromise with material impact."],
      HIGH: ["Confirmed command/query/file/network impact or privileged state change across a realistic trust boundary."],
      MEDIUM: ["A security-relevant boundary weakness with meaningful preconditions or limited blast radius."],
      LOW: ["Defense-in-depth weakness, narrow local impact, or a proof gap that does not yet establish exploitability."],
    },
  };
  const digest = createHash("sha256").update(JSON.stringify(model), "utf8").digest("hex");
  return { ...model, digest };
}

export function renderThreatModel(model: AuditThreatModel): string {
  const boundaries = model.trustBoundaries.map((boundary) => `- **${boundary.name}**: ${boundary.from} -> ${boundary.to}. Controls: ${boundary.controls.join(", ")}.`).join("\n");
  const surfaces = model.attackSurfaces.length > 0 ? model.attackSurfaces.map((surface) => `- ${surface.file}: ${surface.signals.join(", ")}`).join("\n") : "- No deterministic security surface was identified; this remains an unknown, not a clean result.";
  const calibration = (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((level) => `- **${level}**: ${model.severityCalibration[level].join(" ")}`).join("\n");
  return [
    `# Repository threat model: ${model.repository}`,
    "",
    `Repository: ${model.repository}`,
    `Version: ${model.version}`,
    `Source: ${model.source}`,
    `Digest: ${model.digest}`,
    "",
    "## Overview",
    "",
    model.overview,
    "",
    "## Threat Model, Trust Boundaries, and Assumptions",
    "",
    `Attacker profiles: ${model.attackerProfiles.join("; ")}`,
    "",
    "Trust boundaries:",
    boundaries,
    "",
    `Assets: ${model.assets.join("; ")}`,
    "",
    `Attacker-controlled inputs: ${model.attackerControlledInputs.join("; ")}`,
    `Operator-controlled inputs: ${model.operatorControlledInputs.join("; ")}`,
    "",
    "Assumptions:",
    model.assumptions.map((item) => `- ${item}`).join("\n"),
    "",
    "Exclusions and unknowns:",
    model.exclusions.map((item) => `- ${item}`).join("\n"),
    "",
    "## Attack Surface, Mitigations, and Attacker Stories",
    "",
    "Attack surfaces:",
    surfaces,
    "",
    "Mitigations:",
    model.mitigations.map((item) => `- ${item}`).join("\n"),
    "",
    "Attacker stories:",
    model.attackerStories.map((item) => `- ${item}`).join("\n"),
    "",
    "## Severity Calibration (Critical, High, Medium, Low)",
    "",
    calibration,
    "",
  ].join("\n");
}
