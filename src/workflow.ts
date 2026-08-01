import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { maskNonCode } from "./detectors.js";
import type {
  AuditConfig,
  AuditContextSlice,
  AuditPlan,
  AuditPlaybook,
  AuditRecon,
  AuditRun,
  AuditTask,
  Finding,
  FileFingerprint,
  ModuleGraphEdge,
  SemanticDelta,
} from "./types.js";

// The graph is deliberately lexical in this first workflow layer. It is a
// cheap context router, not a substitute for an AST/semantic analysis engine.
const importPatterns = [
  /\bimport\s+(?:[\s\S]*?\sfrom\s*)?["']([^"']+)["']/g,
  /\bexport\s+(?:[\s\S]*?\sfrom\s*)["']([^"']+)["']/g,
  /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
  /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
];

const manifestNames = [
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
  "tsconfig.json",
  "Dockerfile",
  "docker-compose.yml",
  "docker-compose.yaml",
];

const entrypointPattern = /(^|\/)(?:index|main|server|app|middleware|route|routes|handler|api|lambda|function|functions)(?:\.[^/]+)?$/i;

const surfaceSignals: Array<[string, RegExp]> = [
  ["http-entrypoint", /\b(?:express|fastify|koa|hapi|router|createServer|app\.(?:get|post|put|patch|delete|use))\b/i],
  ["auth-boundary", /\b(?:auth|authorize|authorization|middleware|session|jwt|passport|cookie|csrf)\b/i],
  ["dynamic-execution", /(?:\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(|\bvm\.(?:runInNewContext|runInThisContext)\b|\brunInNewContext\s*\()/],
  ["command-execution", /\b(?:child_process|exec|execSync|spawn|spawnSync)\b/i],
  ["data-store", /\b(?:query|execute|prepare|sequelize|prisma|mongoose|mongodb|redis|sql)\b/i],
  ["redirect-or-url", /\b(?:redirect|location\.href|res\.redirect|fetch|axios|request)\b/i],
  ["secret-boundary", /\b(?:process\.env|secret|token|credential|privateKey|apiKey)\b/i],
];

const relationOrder: Record<AuditContextSlice["files"][number]["relation"], number> = {
  TARGET: 0,
  CHANGED: 1,
  IMPORTS: 2,
  IMPORTED_BY: 3,
  SURFACE: 4,
};

function normalizePath(value: string): string {
  return value.split(path.sep).join("/").replace(/^\.\//, "");
}

function stableDigest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function extensionWithoutDot(file: string): string {
  return path.extname(file).toLowerCase();
}

function extractImportSpecifiers(content: string): string[] {
  const values: string[] = [];
  for (const pattern of importPatterns) {
    pattern.lastIndex = 0;
    for (const match of content.matchAll(pattern)) {
      if (match[1]) values.push(match[1]);
    }
  }
  return unique(values);
}

function moduleCandidates(base: string, includeExtensions: string[]): string[] {
  const normalized = normalizePath(base);
  const extension = path.posix.extname(normalized).toLowerCase();
  const candidates: string[] = [];
  const add = (value: string) => {
    const clean = normalizePath(value);
    if (!clean.startsWith("../") && !clean.includes("/../") && !candidates.includes(clean)) candidates.push(clean);
  };

  if (extension) {
    add(normalized);
    if ([".js", ".jsx", ".mjs", ".cjs"].includes(extension)) {
      const stem = normalized.slice(0, -extension.length);
      for (const candidateExtension of includeExtensions) add(`${stem}${candidateExtension}`);
    }
  } else {
    add(normalized);
    for (const candidateExtension of includeExtensions) add(`${normalized}${candidateExtension}`);
  }

  for (const candidateExtension of includeExtensions) add(`${normalized}/index${candidateExtension}`);
  return candidates;
}

function resolveRelativeImport(
  from: string,
  specifier: string,
  files: Set<string>,
  includeExtensions: string[],
): string | null {
  if (!specifier.startsWith(".")) return null;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(from), specifier));
  return moduleCandidates(base, includeExtensions).find((candidate) => files.has(candidate)) ?? null;
}

function buildModuleGraph(
  files: FileFingerprint[],
  contents: Map<string, string>,
  includeExtensions: string[],
): { edges: ModuleGraphEdge[]; unresolvedImports: number } {
  const fileSet = new Set(files.map((file) => file.path));
  const edges: ModuleGraphEdge[] = [];
  let unresolvedImports = 0;
  const edgeKeys = new Set<string>();

  for (const file of files) {
    const content = contents.get(file.path) ?? "";
    for (const specifier of extractImportSpecifiers(content)) {
      if (!specifier.startsWith(".")) continue;
      const target = resolveRelativeImport(file.path, specifier, fileSet, includeExtensions);
      if (!target) {
        unresolvedImports += 1;
        continue;
      }
      const key = `${file.path}\0${target}\0${specifier}`;
      if (edgeKeys.has(key)) continue;
      edgeKeys.add(key);
      edges.push({ from: file.path, to: target, specifier });
    }
  }

  edges.sort((left, right) => `${left.from}\0${left.to}\0${left.specifier}`.localeCompare(`${right.from}\0${right.to}\0${right.specifier}`));
  return { edges, unresolvedImports };
}

async function existingRootFiles(root: string): Promise<string[]> {
  const output: string[] = [];
  for (const name of manifestNames) {
    try {
      await fs.access(path.join(root, name));
      output.push(name);
    } catch {
      // A missing manifest is normal and is intentionally not a warning.
    }
  }
  return output;
}

async function packageScripts(root: string): Promise<Record<string, string>> {
  try {
    const parsed = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf8")) as { scripts?: Record<string, unknown> };
    if (!parsed.scripts || typeof parsed.scripts !== "object") return {};
    return Object.fromEntries(
      Object.entries(parsed.scripts)
        .filter((entry): entry is [string, string] => typeof entry[1] === "string")
        .filter(([name]) => /^(?:test|lint|typecheck|type-check|build|start|dev|check|format)/i.test(name))
        .sort(([left], [right]) => left.localeCompare(right)),
    );
  } catch {
    return {};
  }
}

function securitySurface(files: FileFingerprint[], contents: Map<string, string>): Array<{ file: string; signals: string[] }> {
  return files
    .map((file) => {
      const content = maskNonCode(contents.get(file.path) ?? "").replace(/\/(?:\\.|[^/\\\n])+\/[dgimsuvy]*/g, " ");
      const signals = surfaceSignals.filter(([, pattern]) => pattern.test(content)).map(([name]) => name);
      return signals.length > 0 ? { file: file.path, signals } : null;
    })
    .filter((item): item is { file: string; signals: string[] } => item !== null)
    .sort((left, right) => left.file.localeCompare(right.file))
    .slice(0, 64);
}

function inferEntrypoints(files: FileFingerprint[], surface: Array<{ file: string; signals: string[] }>): string[] {
  const direct = files.filter((file) => entrypointPattern.test(file.path)).map((file) => file.path);
  const surfaceFiles = surface.filter((item) => item.signals.includes("http-entrypoint")).map((item) => item.file);
  return unique([...direct, ...surfaceFiles]).sort().slice(0, 64);
}

function relatedFiles(run: AuditRun, finding: Finding, maxFiles = 8): AuditContextSlice {
  const targetFiles = unique(finding.locations.map((location) => location.file)).sort();
  const inScope = new Set(run.files.map((file) => file.path));
  const changed = new Set(
    run.semanticDelta.basis === "BASELINE_RUN"
      ? [...run.semanticDelta.changed, ...run.semanticDelta.added].filter((file) => inScope.has(file))
      : [],
  );
  const entries = new Map<string, AuditContextSlice["files"][number]>();
  const add = (file: string, relation: AuditContextSlice["files"][number]["relation"], distance: number) => {
    if (!inScope.has(file)) return;
    const candidate = { path: file, relation, distance };
    const current = entries.get(file);
    if (!current || relationOrder[relation] < relationOrder[current.relation] || distance < current.distance) entries.set(file, candidate);
  };

  for (const file of targetFiles) add(file, "TARGET", 0);
  for (const file of changed) add(file, "CHANGED", 0);

  const edges = run.recon?.moduleGraph.edges ?? [];
  for (const target of targetFiles) {
    for (const edge of edges) {
      if (edge.from === target) add(edge.to, "IMPORTS", 1);
      if (edge.to === target) add(edge.from, "IMPORTED_BY", 1);
    }
  }

  if (entries.size < maxFiles) {
    for (const surface of run.recon?.securitySurface ?? []) {
      if (surface.signals.includes("auth-boundary") || surface.signals.includes("http-entrypoint")) add(surface.file, "SURFACE", 1);
      if (entries.size >= maxFiles) break;
    }
  }

  const files = [...entries.values()]
    .sort((left, right) => relationOrder[left.relation] - relationOrder[right.relation] || left.path.localeCompare(right.path))
    .slice(0, maxFiles);
  const rationale = ["Start with the finding location and only expand along local module edges."];
  if (changed.size > 0) rationale.push("Changed or added files are included before unrelated repository context.");
  if (files.some((file) => file.relation === "SURFACE")) rationale.push("An entrypoint or authorization surface was added as boundary context.");
  return {
    targetFiles,
    files,
    truncated: entries.size > maxFiles,
    rationale,
  };
}

function broadContext(run: AuditRun, maxFiles = 8): AuditContextSlice {
  const inScope = new Set(run.files.map((file) => file.path));
  const changed = new Set(
    run.semanticDelta.basis === "BASELINE_RUN"
      ? [...run.semanticDelta.changed, ...run.semanticDelta.added].filter((file) => inScope.has(file))
      : [],
  );
  const entries = new Map<string, AuditContextSlice["files"][number]>();
  const add = (file: string, relation: AuditContextSlice["files"][number]["relation"]) => {
    if (!inScope.has(file) || entries.has(file)) return;
    entries.set(file, { path: file, relation, distance: 0 });
  };
  for (const file of changed) add(file, "CHANGED");
  for (const file of run.recon?.entrypoints ?? []) add(file, "SURFACE");
  for (const item of run.recon?.securitySurface ?? []) {
    if (item.signals.includes("auth-boundary") || item.signals.includes("http-entrypoint")) add(item.file, "SURFACE");
    if (entries.size >= maxFiles) break;
  }
  if (entries.size === 0) for (const file of run.recon?.focusFiles ?? []) add(file, "SURFACE");
  const files = [...entries.values()].sort((left, right) => relationOrder[left.relation] - relationOrder[right.relation] || left.path.localeCompare(right.path)).slice(0, maxFiles);
  return {
    targetFiles: [],
    files,
    truncated: entries.size > maxFiles,
    rationale: [
      "No static candidate was found for this rule; this task is a coverage probe, not a clean result.",
      "Start from changed files and likely entrypoints before expanding to the whole repository.",
    ],
  };
}

function severityWeightValue(severity: Finding["severity"]): number {
  return { CRITICAL: 100, HIGH: 75, MEDIUM: 45, LOW: 20 }[severity];
}

function severityWeight(finding: Finding): number {
  return severityWeightValue(finding.severity);
}

function taskPriority(run: AuditRun, finding: Finding, context: AuditContextSlice): number {
  const changed = new Set(run.semanticDelta.basis === "BASELINE_RUN" ? [...run.semanticDelta.changed, ...run.semanticDelta.added] : []);
  const targetChanged = context.targetFiles.some((file) => changed.has(file));
  const surface = context.files.some((file) => file.relation === "SURFACE");
  const unresolvedPenalty = finding.status === "UNKNOWN" ? -5 : 0;
  return severityWeight(finding) + (targetChanged ? 35 : 0) + (surface ? 10 : 0) + (context.files.length > context.targetFiles.length ? 5 : 0) + unresolvedPenalty;
}

function investigationBudget(context: AuditContextSlice, severity: Finding["severity"]): number {
  const severityExtra = severity === "CRITICAL" ? 350 : severity === "HIGH" ? 200 : 0;
  return Math.min(2_400, 750 + Math.max(0, context.files.length - 1) * 300 + severityExtra);
}

function taskStatus(finding: Finding, phase: AuditTask["phase"]): AuditTask["status"] {
  if (phase === "INVESTIGATE") {
    if (finding.status === "SUPPORTED" || finding.status === "VERIFIED" || finding.status === "REJECTED" || finding.status === "DUPLICATE") return "COMPLETED";
    if (finding.status === "HARNESS_FAILED") return "BLOCKED";
    return "PENDING";
  }
  if (finding.status === "VERIFIED" || finding.status === "REJECTED" || finding.status === "DUPLICATE") return "COMPLETED";
  if (finding.status === "HARNESS_FAILED") return "BLOCKED";
  if (finding.status === "SUPPORTED") return "PENDING";
  return "WAITING";
}

export async function buildAuditRecon(
  root: string,
  files: FileFingerprint[],
  contents: Map<string, string>,
  findings: Finding[],
  semanticDelta: SemanticDelta,
  config: AuditConfig,
  playbook: AuditPlaybook,
): Promise<AuditRecon> {
  const manifests = await existingRootFiles(root);
  const scripts = await packageScripts(root);
  const graph = buildModuleGraph(files, contents, config.includeExtensions);
  const surface = securitySurface(files, contents);
  const entries = inferEntrypoints(files, surface);
  const focusFiles = unique([
    ...(semanticDelta.basis === "BASELINE_RUN" ? [...semanticDelta.changed, ...semanticDelta.added] : []),
    ...findings.flatMap((finding) => finding.locations.map((location) => location.file)),
    ...entries,
  ]).filter((file) => files.some((candidate) => candidate.path === file)).sort().slice(0, 96);
  const hasTypeScript = files.some((file) => [".ts", ".tsx"].includes(extensionWithoutDot(file.path)));
  const hasJavaScript = files.some((file) => [".js", ".jsx", ".mjs", ".cjs"].includes(extensionWithoutDot(file.path)));
  const projectKind = hasTypeScript ? "NODE_TYPESCRIPT" : hasJavaScript ? "NODE_JAVASCRIPT" : "UNKNOWN";
  const ruleInventory = playbook.rules.filter((rule) => rule.enabled).map(({ id, title, severity, evidenceRequired }) => ({ id, title, severity, evidenceRequired }));
  const contextDigest = stableDigest({ manifests, scripts, entries, surface, graph, focusFiles, ruleInventory });

  return {
    schemaVersion: 1,
    projectKind,
    ruleInventory,
    manifests,
    scripts,
    entrypoints: entries,
    securitySurface: surface,
    moduleGraph: { nodes: files.length, edgeCount: graph.edges.length, unresolvedImports: graph.unresolvedImports, edges: graph.edges },
    focusFiles,
    contextDigest,
    notes: [
      "Recon is deterministic and does not execute package scripts or import external security knowledge.",
      "The module graph is a lexical context router; semantic reachability still requires a worker or validator.",
      "Workers should receive the task context slice before requesting broader repository context.",
    ],
  };
}

export function buildAuditPlan(run: AuditRun, tokenBudget = 12_000): AuditPlan {
  const tasks: AuditTask[] = [];
  const previousStatuses = new Map((run.plan?.tasks ?? []).map((task) => [task.id, task.status]));
  const candidates = run.findings
    .map((finding) => ({ finding, context: relatedFiles(run, finding) }))
    .map(({ finding, context }) => ({ finding, context, priority: taskPriority(run, finding, context) }))
    .sort((left, right) => right.priority - left.priority || left.finding.id.localeCompare(right.finding.id));

  for (const { finding, context, priority } of candidates) {
    const investigationId = `investigate:${finding.id}`;
    tasks.push({
      id: investigationId,
      phase: "INVESTIGATE",
      findingId: finding.id,
      obligationId: finding.obligationId,
      title: `Investigate ${finding.title}`,
      priority,
      status: taskStatus(finding, "INVESTIGATE"),
      budgetTokens: 0,
      context,
      dependsOn: [],
      rationale: [
        "Trace the source-to-sink or trust-boundary claim before asking for a full-repository review.",
        ...finding.limitations.slice(0, 2),
      ],
    });

    const obligation = run.obligations.find((candidate) => candidate.id === finding.obligationId);
    if (obligation?.evidenceRequired === "T2_REPRODUCIBLE") {
      tasks.push({
        id: `validate:${finding.id}`,
        phase: "VALIDATE",
        findingId: finding.id,
        obligationId: finding.obligationId,
        title: `Validate ${finding.title}`,
        priority,
        status: taskStatus(finding, "VALIDATE"),
        budgetTokens: 0,
        context,
        dependsOn: [investigationId],
      rationale: ["Use an independent, isolated reproducer and a negative control; crashes alone are not proof."],
      });
    }
  }

  const coveredRuleIds = new Set(run.findings.map((finding) => finding.ruleId));
  for (const rule of run.recon?.ruleInventory ?? []) {
    if (coveredRuleIds.has(rule.id)) continue;
    const id = `hunt:${rule.id}`;
    tasks.push({
      id,
      phase: "HUNT",
      findingId: null,
      obligationId: null,
      ruleId: rule.id,
      title: `Hunt beyond static matches: ${rule.title}`,
      priority: severityWeightValue(rule.severity) + 15,
      status: previousStatuses.get(id) === "COMPLETED" ? "COMPLETED" : "PENDING",
      budgetTokens: 0,
      context: broadContext(run),
      dependsOn: [],
      rationale: [
        "The deterministic pass found no candidate for this rule; absence of a match is not evidence of safety.",
        "Look for equivalent sinks, helper indirection, alternate entrypoints, and guard bypasses.",
      ],
    });
  }

  const budget = Math.max(0, Math.floor(tokenBudget));
  let remaining = budget;
  let allocatedTokens = 0;
  for (const task of tasks.filter((candidate) => ["INVESTIGATE", "HUNT"].includes(candidate.phase) && candidate.status === "PENDING")) {
    const finding = task.findingId ? run.findings.find((candidate) => candidate.id === task.findingId) : undefined;
    const rule = task.ruleId ? run.recon?.ruleInventory.find((candidate) => candidate.id === task.ruleId) : undefined;
    const estimate = investigationBudget(task.context, finding?.severity ?? rule?.severity ?? "MEDIUM");
    if (remaining < 500) {
      task.status = "DEFERRED";
      task.rationale.push("Deferred because the configured worker token budget is exhausted.");
      continue;
    }
    task.budgetTokens = Math.min(estimate, remaining);
    allocatedTokens += task.budgetTokens;
    remaining -= task.budgetTokens;
  }

  for (const task of tasks) {
    if (task.phase !== "VALIDATE" || task.status !== "PENDING") continue;
    const dependency = tasks.find((candidate) => candidate.id === task.dependsOn[0]);
    if (dependency && ["PENDING", "WAITING", "DEFERRED"].includes(dependency.status)) task.status = "WAITING";
  }

  return {
    schemaVersion: 1,
    runId: run.runId,
    tokenBudget: budget,
    allocatedTokens,
    unallocatedTokens: remaining,
    tasks,
    notes: [
      "Token allocation applies to model investigation tasks; validator resource limits are tracked by the validation contract.",
      "A WAITING validation task is not evidence of safety; it has not run yet.",
      "If context is insufficient, expand along graph edges before sending the entire repository to a worker.",
    ],
  };
}

export function planSummary(plan: AuditPlan | undefined): string {
  if (!plan) return "Plan: unavailable (legacy run artifact)";
  const pending = plan.tasks.filter((task) => task.status === "PENDING").length;
  const waiting = plan.tasks.filter((task) => task.status === "WAITING").length;
  const deferred = plan.tasks.filter((task) => task.status === "DEFERRED").length;
  return `Plan: ${plan.tasks.length} tasks  pending=${pending} waiting=${waiting} deferred=${deferred}  tokens=${plan.allocatedTokens}/${plan.tokenBudget}`;
}
