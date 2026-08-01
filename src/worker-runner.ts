import { promises as fs } from "node:fs";
import path from "node:path";
import { ModelRegistry, type ModelCompletionResponse, type ModelMessage } from "./models.js";
import type { AuditRun, AuditTask, AuditWorkerResult, EvidenceItem, FindingStatus, EvidenceTier, SourceLocation } from "./types.js";

const findingStatuses = new Set<FindingStatus>(["SUSPECTED", "SUPPORTED", "VERIFIED", "REJECTED", "DUPLICATE", "UNKNOWN", "NOT_TESTED", "HARNESS_FAILED"]);
const evidenceTiers = new Set<EvidenceTier>(["T0_HYPOTHESIS", "T1_STATIC_PATH", "T2_REPRODUCIBLE"]);

function bounded(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, Math.max(0, max - 80))}\n...[truncated by harness]`;
}

function safeSourcePath(run: AuditRun, relative: string): string {
  const root = path.resolve(run.root);
  const target = path.resolve(root, relative);
  if (target !== root && !target.startsWith(`${root}${path.sep}`)) throw new Error(`Task context escapes the audited root: ${relative}`);
  if (!run.files.some((file) => file.path === relative)) throw new Error(`Task context references a file outside the audited snapshot: ${relative}`);
  return target;
}

async function sourceContext(run: AuditRun, task: AuditTask): Promise<string> {
  const files = task.context.files.length > 0 ? task.context.files : run.files.slice(0, 8).map((file) => ({ path: file.path, relation: "SURFACE" as const, distance: 0 }));
  const perFile = Math.max(600, Math.floor(Math.max(1, task.budgetTokens) * 1.4 / Math.max(1, files.length)));
  const sections: string[] = [];
  for (const file of files) {
    const content = await fs.readFile(safeSourcePath(run, file.path), "utf8");
    const numbered = content.split(/\r?\n/).map((line, index) => `${index + 1}| ${line}`).join("\n");
    sections.push(`### ${file.relation} ${file.path}\n${bounded(numbered, perFile)}`);
  }
  return sections.join("\n\n");
}

function graphContext(run: AuditRun, task: AuditTask): string {
  const graph = run.recon?.codeGraph;
  if (!graph) return "No AST graph artifact is available for this legacy run.";
  const targetFiles = new Set(task.context.files.map((file) => file.path));
  const nodes = graph.nodes.filter((node) => targetFiles.size === 0 || targetFiles.has(node.file));
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = graph.edges.filter((edge) => nodeIds.has(edge.from) || nodeIds.has(edge.to)).slice(0, 100);
  const flows = graph.flows.filter((flow) => nodeIds.has(flow.sourceNodeId) || nodeIds.has(flow.sinkNodeId)).slice(0, 80);
  return JSON.stringify({ nodes, edges, flows }, null, 2);
}

export async function buildWorkerMessages(run: AuditRun, task: AuditTask): Promise<{ messages: ModelMessage[]; estimatedInputTokens: number }> {
  if (task.phase === "VALIDATE") throw new Error("The model worker cannot own VALIDATE tasks; use an independent validator.");
  const finding = task.findingId ? run.findings.find((candidate) => candidate.id === task.findingId) : undefined;
  const obligation = task.obligationId ? run.obligations.find((candidate) => candidate.id === task.obligationId) : undefined;
  const system = [
    "You are an evidence-constrained security audit worker.",
    "Return JSON only with {findings: [], notes: []}.",
    "You may propose SUSPECTED or SUPPORTED findings and static TRACE evidence.",
    "Never claim VERIFIED or T2_REPRODUCIBLE; only an independent validator can do that.",
    "Every location must be an exact file and line from the provided snapshot. Do not invent files, commands, test results, or runtime behavior.",
    "If evidence is insufficient, return no finding and explain the missing proof in notes.",
  ].join("\n");
  const user = [
    `Run snapshot: ${run.snapshot.treeDigest}`,
    `Task: ${task.id} phase=${task.phase} rule=${task.ruleId ?? "none"} priority=${task.priority} budgetTokens=${task.budgetTokens}`,
    `Title: ${task.title}`,
    `Rationale: ${task.rationale.join(" | ")}`,
    `Obligation: ${obligation ? JSON.stringify(obligation) : "none"}`,
    `Existing finding: ${finding ? JSON.stringify(finding) : "none"}`,
    "Coverage: a no-match result is not evidence of safety; report coverage gaps explicitly.",
    "AST graph slice:",
    graphContext(run, task),
    "Source context:",
    await sourceContext(run, task),
    "Expected finding item shape: {ruleId,title,status,evidenceTier,rootCause,impact,remediation,locations,evidence,limitations}.",
  ].join("\n\n");
  const messages: ModelMessage[] = [{ role: "system", content: system }, { role: "user", content: user }];
  return { messages, estimatedInputTokens: Math.ceil(messages.reduce((total, message) => total + message.content.length, 0) / 4) };
}

function parseJson(text: string): unknown {
  const trimmed = text.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
    if (fenced) return JSON.parse(fenced[1]);
    const start = trimmed.indexOf("{");
    const end = trimmed.lastIndexOf("}");
    if (start >= 0 && end > start) return JSON.parse(trimmed.slice(start, end + 1));
    throw new Error("Model response was not valid JSON.");
  }
}

function validLocation(value: unknown): value is SourceLocation {
  if (!value || typeof value !== "object") return false;
  const location = value as Partial<SourceLocation>;
  return typeof location.file === "string" && typeof location.line === "number" && location.line > 0 && typeof location.column === "number" && location.column > 0 && typeof location.endLine === "number" && location.endLine >= location.line && typeof location.snippet === "string";
}

function validEvidence(value: unknown): value is EvidenceItem {
  if (!value || typeof value !== "object") return false;
  const evidence = value as Partial<EvidenceItem>;
  return ["STATIC_PATTERN", "TRACE", "REPRODUCER", "TOOL_RESULT", "LIMITATION"].includes(evidence.type ?? "") && typeof evidence.title === "string" && typeof evidence.detail === "string" && typeof evidence.reproducible === "boolean" && (!evidence.locations || evidence.locations.every(validLocation));
}

function normalizedFinding(value: unknown): AuditWorkerResult["findings"][number] | null {
  if (!value || typeof value !== "object") return null;
  const item = value as Record<string, unknown>;
  if (typeof item.ruleId !== "string" || typeof item.title !== "string") return null;
  const status = findingStatuses.has(item.status as FindingStatus) ? item.status as FindingStatus : "SUSPECTED";
  const evidenceTier = evidenceTiers.has(item.evidenceTier as EvidenceTier) ? item.evidenceTier as EvidenceTier : "T0_HYPOTHESIS";
  const locations = Array.isArray(item.locations) ? item.locations.filter(validLocation) : [];
  const evidence = Array.isArray(item.evidence) ? item.evidence.filter(validEvidence) : [];
  return {
    ruleId: item.ruleId,
    title: item.title,
    status,
    evidenceTier,
    obligationId: typeof item.obligationId === "string" ? item.obligationId : undefined,
    severity: typeof item.severity === "string" ? item.severity as AuditWorkerResult["findings"][number]["severity"] : undefined,
    rootCause: typeof item.rootCause === "string" ? item.rootCause : undefined,
    impact: typeof item.impact === "string" ? item.impact : undefined,
    remediation: typeof item.remediation === "string" ? item.remediation : undefined,
    locations,
    evidence,
    limitations: Array.isArray(item.limitations) ? item.limitations.filter((value): value is string => typeof value === "string") : [],
  };
}

export function workerResultFromCompletion(response: ModelCompletionResponse, task: AuditTask): AuditWorkerResult {
  try {
    const parsed = parseJson(response.text);
    if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as { findings?: unknown }).findings)) throw new Error("Model JSON must contain a findings array.");
    const value = parsed as { findings: unknown[]; notes?: unknown };
    const findings = value.findings.map(normalizedFinding).filter((finding): finding is NonNullable<typeof finding> => finding !== null);
    const notes = [
      ...(Array.isArray(value.notes) ? value.notes.filter((note): note is string => typeof note === "string") : []),
      `Model response ${response.requestId} selected ${response.modelId}.`,
    ];
    return { worker: response.modelId, taskId: task.id, findings, tokenAccounting: response.usage, notes };
  } catch (error) {
    return {
      worker: response.modelId,
      taskId: task.id,
      error: error instanceof Error ? error.message : String(error),
      findings: [],
      tokenAccounting: response.usage,
      notes: [`Model response ${response.requestId} was rejected by the worker protocol.`],
    };
  }
}

export async function executeWorkerTask(run: AuditRun, task: AuditTask, registry: ModelRegistry, model?: string): Promise<AuditWorkerResult> {
  const prompt = await buildWorkerMessages(run, task);
  const response = await registry.complete({
    phase: task.phase,
    priority: task.priority,
    estimatedInputTokens: prompt.estimatedInputTokens,
    budgetTokens: task.budgetTokens,
    requiredCapabilities: [task.phase, "JSON"],
    model,
    messages: prompt.messages,
    maxOutputTokens: Math.max(128, task.budgetTokens - prompt.estimatedInputTokens),
    temperature: 0,
  });
  return workerResultFromCompletion(response, task);
}
