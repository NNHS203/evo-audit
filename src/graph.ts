import { createHash } from "node:crypto";
import path from "node:path";
import ts from "typescript";
import type {
  AuditObligation,
  AuditPlaybook,
  FileFingerprint,
  Finding,
  PlaybookRule,
  SourceLocation,
} from "./types.js";

export type CodeGraphNodeKind = "FILE" | "FUNCTION" | "CALL" | "SOURCE" | "SINK" | "GUARD" | "VARIABLE";
export type CodeGraphEdgeKind = "IMPORT" | "CONTAINS" | "CALLS" | "DATA_FLOW" | "GUARDS";

export interface CodeGraphNode {
  id: string;
  kind: CodeGraphNodeKind;
  file: string;
  line: number;
  column: number;
  endLine: number;
  name: string;
  detail: string;
  snippet: string;
}

export interface CodeGraphEdge {
  from: string;
  to: string;
  kind: CodeGraphEdgeKind;
  label?: string;
  confidence: "HIGH" | "MEDIUM";
}

export interface CodeDataFlowFact {
  id: string;
  sourceNodeId: string;
  sinkNodeId: string;
  pathNodeIds: string[];
  controlNodeIds: string[];
  status: "POSSIBLE";
  reason: string;
}

export interface AuditCodeGraph {
  schemaVersion: 1;
  nodes: CodeGraphNode[];
  edges: CodeGraphEdge[];
  flows: CodeDataFlowFact[];
  stats: {
    files: number;
    functions: number;
    calls: number;
    sources: number;
    sinks: number;
    guards: number;
    flows: number;
    imports: number;
  };
  digest: string;
}

interface Scope {
  functionNodeId: string;
  tainted: Map<string, string[]>;
  controls: string[];
}

interface GraphBuilder {
  nodes: CodeGraphNode[];
  edges: CodeGraphEdge[];
  flows: CodeDataFlowFact[];
  nodeKeys: Map<string, string>;
  sourceKeys: Map<string, string>;
  fileNodes: Map<string, string>;
  sourceOrigins: Map<string, string[]>;
  flowKeys: Set<string>;
  edgeKeys: Set<string>;
}

function stableId(parts: string[]): string {
  return createHash("sha256").update(parts.join("\0"), "utf8").digest("hex").slice(0, 24);
}

function normalizePath(value: string): string {
  return value.split(path.sep).join("/").replace(/^\.\//, "");
}

function scriptKind(file: string): ts.ScriptKind {
  switch (path.extname(file).toLowerCase()) {
    case ".tsx": return ts.ScriptKind.TSX;
    case ".jsx": return ts.ScriptKind.JSX;
    case ".js": return ts.ScriptKind.JS;
    case ".mjs": return ts.ScriptKind.JS;
    case ".cjs": return ts.ScriptKind.JS;
    default: return ts.ScriptKind.TS;
  }
}

function position(sourceFile: ts.SourceFile, node: ts.Node): Pick<CodeGraphNode, "line" | "column" | "endLine"> {
  const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());
  return { line: start.line + 1, column: start.character + 1, endLine: end.line + 1 };
}

function snippet(sourceFile: ts.SourceFile, node: ts.Node): string {
  return node.getText(sourceFile).replace(/\s+/g, " ").trim().slice(0, 280);
}

function propertyChain(expression: ts.Expression): string {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return `${propertyChain(expression.expression)}.${expression.name.text}`;
  if (ts.isElementAccessExpression(expression)) return `${propertyChain(expression.expression)}[]`;
  return expression.getText().replace(/\s+/g, " ").slice(0, 160);
}

function callName(expression: ts.Expression): string {
  if (ts.isIdentifier(expression) || ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
    return propertyChain(expression);
  }
  return expression.getText().replace(/\s+/g, " ").slice(0, 160);
}

function isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node) || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node);
}

function functionName(node: ts.FunctionLikeDeclaration, sourceFile: ts.SourceFile): string {
  const named = "name" in node && node.name && ts.isIdentifier(node.name) ? node.name.text : "anonymous";
  return `${named}@${position(sourceFile, node).line}`;
}

function isSourceExpression(node: ts.Node): node is ts.Expression {
  if (ts.isIdentifier(node)) return /^(?:userInput|user_input|untrusted|rawInput|raw_input|input)$/i.test(node.text);
  if (!ts.isPropertyAccessExpression(node) && !ts.isElementAccessExpression(node)) return false;
  const chain = propertyChain(node).toLowerCase();
  return /(?:^|\.)(?:body|query|params|headers|cookies|files|file|input|payload|data)(?:\.|\[|$)/.test(chain)
    && /^(?:req|request|ctx|context|event|input|payload|data|body|query|params)\b/i.test(chain);
}

function sinkKind(name: string): string | null {
  const normalized = name.toLowerCase();
  if (/(?:^|\.)eval$|(?:^|\.)function$|\bvm\.runin/.test(normalized)) return "DYNAMIC_CODE";
  if (/(?:^|\.)(?:exec|execsync|spawn|spawnsync|execfile|execfilesync)$/.test(normalized) || normalized.endsWith("child_process.exec")) return "COMMAND_EXECUTION";
  if (/(?:^|\.)(?:query|execute|raw|executescript)$/.test(normalized)) return "QUERY_EXECUTION";
  if (/(?:^|\.)(?:redirect|location\.href)$/.test(normalized)) return "REDIRECT";
  if (/(?:^|\.)(?:fetch|axios|request|get|post)$/.test(normalized)) return "OUTBOUND_REQUEST";
  return null;
}

function isGuardCall(name: string): boolean {
  return /(?:sanitize|validate|allowlist|allow-list|sameorigin|same-origin|authorize|authorized|permission|is safe|issafe|escape|csrf|checkauth|verify)/i.test(name);
}

function addNode(
  builder: GraphBuilder,
  sourceFile: ts.SourceFile,
  node: ts.Node,
  kind: CodeGraphNodeKind,
  name: string,
  detail: string,
  key = `${sourceFile.fileName}:${node.getStart(sourceFile)}:${kind}:${name}`,
): string {
  const existing = builder.nodeKeys.get(key);
  if (existing) return existing;
  const location = position(sourceFile, node);
  const id = `${kind.toLowerCase()}:${stableId([sourceFile.fileName, String(node.getStart(sourceFile)), kind, name])}`;
  builder.nodeKeys.set(key, id);
  builder.nodes.push({ id, kind, file: normalizePath(sourceFile.fileName), ...location, name, detail, snippet: snippet(sourceFile, node) });
  return id;
}

function addEdge(builder: GraphBuilder, edge: CodeGraphEdge): void {
  const key = `${edge.from}\0${edge.to}\0${edge.kind}\0${edge.label ?? ""}`;
  if (builder.edgeKeys.has(key)) return;
  builder.edgeKeys.add(key);
  builder.edges.push(edge);
}

function sourceNode(builder: GraphBuilder, sourceFile: ts.SourceFile, node: ts.Expression): string {
  const key = `${sourceFile.fileName}:${node.getStart(sourceFile)}:SOURCE`;
  const existing = builder.sourceKeys.get(key);
  if (existing) return existing;
  const id = addNode(builder, sourceFile, node, "SOURCE", propertyChain(node), "Attacker-controlled or boundary input expression.", key);
  builder.sourceKeys.set(key, id);
  return id;
}

function sourceOriginsIn(
  builder: GraphBuilder,
  sourceFile: ts.SourceFile,
  expression: ts.Node,
  scope: Scope,
): string[] {
  const origins = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (isSourceExpression(node)) {
      origins.add(sourceNode(builder, sourceFile, node));
      return;
    }
    if (ts.isIdentifier(node)) {
      for (const origin of scope.tainted.get(node.text) ?? []) origins.add(origin);
    }
    ts.forEachChild(node, visit);
  };
  visit(expression);
  return [...origins];
}

function resolveRelativeImport(from: string, specifier: string, files: Set<string>): string | null {
  if (!specifier.startsWith(".")) return null;
  const base = normalizePath(path.posix.normalize(path.posix.join(path.posix.dirname(from), specifier)));
  const extension = path.posix.extname(base).toLowerCase();
  const candidates = [
    base,
    ...(extension ? [base.slice(0, -extension.length) + ".ts", base.slice(0, -extension.length) + ".tsx", base.slice(0, -extension.length) + ".js", base.slice(0, -extension.length) + ".jsx"] : [base + ".ts", base + ".tsx", base + ".js", base + ".jsx"]),
    `${base}/index.ts`, `${base}/index.tsx`, `${base}/index.js`, `${base}/index.jsx`,
  ];
  return candidates.map(normalizePath).find((candidate) => files.has(candidate)) ?? null;
}

function addFlow(builder: GraphBuilder, sourceId: string, sinkId: string, controls: string[], reason: string): void {
  const key = `${sourceId}\0${sinkId}`;
  if (builder.flowKeys.has(key)) return;
  builder.flowKeys.add(key);
  const id = `flow:${stableId([sourceId, sinkId])}`;
  builder.flows.push({
    id,
    sourceNodeId: sourceId,
    sinkNodeId: sinkId,
    pathNodeIds: [sourceId, sinkId],
    controlNodeIds: [...controls],
    status: "POSSIBLE",
    reason,
  });
  addEdge(builder, { from: sourceId, to: sinkId, kind: "DATA_FLOW", confidence: "MEDIUM", label: reason });
}

function buildFileGraph(builder: GraphBuilder, files: FileFingerprint[], contents: Map<string, string>, includeExtensions: string[]): void {
  const fileSet = new Set(files.map((file) => file.path));
  for (const file of files) {
    const sourceFile = ts.createSourceFile(file.path, contents.get(file.path) ?? "", ts.ScriptTarget.Latest, true, scriptKind(file.path));
    const fileNodeId = `file:${stableId([file.path])}`;
    builder.fileNodes.set(file.path, fileNodeId);
    builder.nodes.push({ id: fileNodeId, kind: "FILE", file: file.path, line: 1, column: 1, endLine: 1, name: file.path, detail: "Audited source file.", snippet: file.path });
    const visitImports = (node: ts.Node): void => {
      if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
        const target = resolveRelativeImport(file.path, node.moduleSpecifier.text, fileSet);
        if (target) addEdge(builder, { from: fileNodeId, to: builder.fileNodes.get(target) ?? `file:${stableId([target])}`, kind: "IMPORT", confidence: "HIGH", label: node.moduleSpecifier.text });
      }
      ts.forEachChild(node, visitImports);
    };
    visitImports(sourceFile);
  }
}

function analyzeFile(builder: GraphBuilder, file: FileFingerprint, content: string): void {
  const sourceFile = ts.createSourceFile(file.path, content, ts.ScriptTarget.Latest, true, scriptKind(file.path));
  const fileNodeId = builder.fileNodes.get(file.path) ?? `file:${stableId([file.path])}`;
  const rootScope: Scope = { functionNodeId: fileNodeId, tainted: new Map(), controls: [] };

  const visit = (node: ts.Node, scope: Scope): void => {
    let active = scope;
    if (isFunctionLike(node)) {
      const functionNodeId = addNode(builder, sourceFile, node, "FUNCTION", functionName(node, sourceFile), "Function or method scope used for local flow analysis.");
      addEdge(builder, { from: fileNodeId, to: functionNodeId, kind: "CONTAINS", confidence: "HIGH" });
      active = { functionNodeId, tainted: new Map(scope.tainted), controls: [...scope.controls] };
      for (const parameter of node.parameters) {
        if (ts.isIdentifier(parameter.name) && /^(?:req|request|ctx|context|event)$/i.test(parameter.name.text)) {
          active.tainted.set(parameter.name.text, []);
        }
      }
    }

    if (ts.isVariableDeclaration(node) && node.initializer && ts.isIdentifier(node.name)) {
      const origins = sourceOriginsIn(builder, sourceFile, node.initializer, active);
      const variableId = addNode(builder, sourceFile, node, "VARIABLE", node.name.text, "Local value carrying a boundary input.");
      if (origins.length > 0) {
        active.tainted.set(node.name.text, origins);
        for (const origin of origins) addEdge(builder, { from: origin, to: variableId, kind: "DATA_FLOW", confidence: "HIGH" });
        builder.sourceOrigins.set(variableId, origins);
      }
    }

    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) {
      const origins = sourceOriginsIn(builder, sourceFile, node.right, active);
      if (origins.length > 0) active.tainted.set(node.left.text, origins);
    }

    if (ts.isCallExpression(node)) {
      const name = callName(node.expression);
      const callNodeId = addNode(builder, sourceFile, node, "CALL", name, "Call expression discovered by the AST graph.");
      addEdge(builder, { from: active.functionNodeId, to: callNodeId, kind: "CALLS", confidence: "MEDIUM", label: name });
      const origins = node.arguments.flatMap((argument) => sourceOriginsIn(builder, sourceFile, argument, active));
      const uniqueOrigins = [...new Set(origins)];
      if (isGuardCall(name)) {
        const guardId = addNode(builder, sourceFile, node, "GUARD", name, "Potential sanitizer, authorization, validation, or boundary guard.");
        active.controls.push(guardId);
        addEdge(builder, { from: guardId, to: active.functionNodeId, kind: "GUARDS", confidence: "MEDIUM", label: name });
      }
      const kind = sinkKind(name);
      if (kind) {
        const sinkId = addNode(builder, sourceFile, node, "SINK", name, kind);
        addEdge(builder, { from: callNodeId, to: sinkId, kind: "CONTAINS", confidence: "HIGH", label: kind });
        for (const origin of uniqueOrigins) addFlow(builder, origin, sinkId, active.controls, `${propertyChain(node.expression)} receives a value derived from a boundary input.`);
      }
    }

    ts.forEachChild(node, (child) => visit(child, active));
  };

  visit(sourceFile, rootScope);
}

export function buildCodeGraph(files: FileFingerprint[], contents: Map<string, string>, includeExtensions: string[]): AuditCodeGraph {
  const builder: GraphBuilder = {
    nodes: [],
    edges: [],
    flows: [],
    nodeKeys: new Map(),
    sourceKeys: new Map(),
    fileNodes: new Map(),
    sourceOrigins: new Map(),
    flowKeys: new Set(),
    edgeKeys: new Set(),
  };
  buildFileGraph(builder, files, contents, includeExtensions);
  for (const file of files) analyzeFile(builder, file, contents.get(file.path) ?? "");
  builder.nodes.sort((left, right) => left.id.localeCompare(right.id));
  builder.edges.sort((left, right) => `${left.from}\0${left.to}\0${left.kind}\0${left.label ?? ""}`.localeCompare(`${right.from}\0${right.to}\0${right.kind}\0${right.label ?? ""}`));
  builder.flows.sort((left, right) => left.id.localeCompare(right.id));
  const stats = {
    files: files.length,
    functions: builder.nodes.filter((node) => node.kind === "FUNCTION").length,
    calls: builder.nodes.filter((node) => node.kind === "CALL").length,
    sources: builder.nodes.filter((node) => node.kind === "SOURCE").length,
    sinks: builder.nodes.filter((node) => node.kind === "SINK").length,
    guards: builder.nodes.filter((node) => node.kind === "GUARD").length,
    flows: builder.flows.length,
    imports: builder.edges.filter((edge) => edge.kind === "IMPORT").length,
  };
  const withoutDigest = { schemaVersion: 1 as const, nodes: builder.nodes, edges: builder.edges, flows: builder.flows, stats };
  const digest = createHash("sha256").update(JSON.stringify(withoutDigest), "utf8").digest("hex");
  return { ...withoutDigest, digest };
}

function locationFor(node: CodeGraphNode): SourceLocation {
  return { file: node.file, line: node.line, column: node.column, endLine: node.endLine, snippet: node.snippet };
}

function ruleForSink(playbook: AuditPlaybook, kind: string): PlaybookRule | undefined {
  const suffix = kind === "DYNAMIC_CODE" ? "DYNAMIC-CODE" : kind === "COMMAND_EXECUTION" ? "COMMAND-INJECTION" : kind === "QUERY_EXECUTION" ? "SQL-INJECTION" : kind === "REDIRECT" ? "OPEN-REDIRECT" : undefined;
  if (!suffix) return undefined;
  return playbook.rules.find((rule) => rule.enabled && rule.id.includes(suffix));
}

function findingText(kind: string): Pick<Finding, "rootCause" | "impact" | "remediation"> {
  if (kind === "DYNAMIC_CODE") return {
    rootCause: "An AST-traced boundary input reaches a dynamic code execution sink.",
    impact: "An attacker may execute arbitrary code if the traced input is externally reachable and not constrained.",
    remediation: "Remove dynamic evaluation or constrain the input to a reviewed non-user-controlled allowlist, then add a regression test.",
  };
  if (kind === "COMMAND_EXECUTION") return {
    rootCause: "An AST-traced boundary input reaches a child-process execution sink.",
    impact: "An attacker may influence command execution if shell interpretation or argument construction is unsafe.",
    remediation: "Use fixed commands and argument arrays with execFile-style APIs, then verify attacker metacharacters remain data.",
  };
  if (kind === "QUERY_EXECUTION") return {
    rootCause: "An AST-traced boundary input reaches a query execution sink through a local data-flow path.",
    impact: "An attacker may alter query semantics if the driver does not parameterize the traced value.",
    remediation: "Use parameterized query APIs and add a test proving metacharacters remain data.",
  };
  return {
    rootCause: "An AST-traced boundary input reaches an outbound redirect sink.",
    impact: "An attacker may redirect users to an external destination if same-origin or allowlist controls are absent.",
    remediation: "Use same-origin defaults or an explicit destination allowlist and test external destinations are rejected.",
  };
}

export function detectGraphFindings(
  graph: AuditCodeGraph,
  playbook: AuditPlaybook,
  runId: string,
  existing: Finding[] = [],
): { findings: Finding[]; obligations: AuditObligation[] } {
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  const findings: Finding[] = [];
  const obligations: AuditObligation[] = [];
  for (const flow of graph.flows) {
    const source = nodes.get(flow.sourceNodeId);
    const sink = nodes.get(flow.sinkNodeId);
    if (!source || !sink) continue;
    const kind = sink.detail;
    const rule = ruleForSink(playbook, kind);
    if (!rule) continue;
    const duplicate = [...existing, ...findings].some((finding) => finding.ruleId === rule.id && finding.locations.some((location) => location.file === sink.file && location.line === sink.line));
    if (duplicate) continue;
    const text = findingText(kind);
    const obligationId = `${runId}-${rule.id}-graph-${flow.id}`;
    const findingId = `${obligationId}-finding`;
    const locations = [locationFor(source), locationFor(sink)];
    obligations.push({
      id: obligationId,
      kind: kind === "DYNAMIC_CODE" ? "DYNAMIC_CODE" : "SOURCE_TO_SINK",
      title: `Verify: ${rule.title}`,
      status: "OPEN",
      targetFiles: [...new Set(locations.map((location) => location.file))],
      falsifiers: [
        "Prove the source is not reachable from an attacker-controlled boundary.",
        "Prove a sanitizer or authorization guard fully constrains the value before the sink.",
        "Run a positive reproducer and an independent negative control in the pinned snapshot.",
      ],
      evidenceRequired: rule.evidenceRequired,
      createdBy: "ast-data-flow-graph",
    });
    findings.push({
      id: findingId,
      ruleId: rule.id,
      obligationId,
      title: rule.title,
      severity: rule.severity,
      status: "SUSPECTED",
      evidenceTier: "T1_STATIC_PATH",
      ...text,
      locations,
      evidence: [
        {
          type: "TRACE",
          title: "AST data-flow trace",
          detail: `${flow.reason} Flow ${flow.id} is a possible path, not runtime proof. Controls observed: ${flow.controlNodeIds.length}.`,
          locations,
          reproducible: false,
        },
        {
          type: "LIMITATION",
          title: "Static flow limitation",
          detail: "The graph establishes a local AST path but does not prove deployment reachability, sanitizer completeness, or exploitability.",
          locations,
          reproducible: false,
        },
      ],
      limitations: [
        "AST flow is a candidate path and requires an independent validator.",
        flow.controlNodeIds.length > 0 ? "Potential guard calls were observed and must be checked for completeness." : "No recognized guard call was observed on the local path.",
      ],
    });
  }
  return { findings, obligations };
}
