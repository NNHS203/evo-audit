import { createHash } from "node:crypto";
import type { CodeDataFlowFact, CodeGraphEdge, CodeGraphNode } from "./graph.js";
import type { FileFingerprint } from "./types.js";

export interface PythonGraphFragment {
  nodes: CodeGraphNode[];
  edges: CodeGraphEdge[];
  flows: CodeDataFlowFact[];
}

interface PythonFunction {
  name: string;
  file: string;
  line: number;
  indent: number;
  endLine: number;
  parameters: string[];
  nodeId: string;
}

interface TaintState {
  origins: Map<string, Set<string>>;
  parameters: Map<string, Set<string>>;
}

interface PythonSinkSummary {
  function: PythonFunction;
  sinkNodeId: string;
  kind: string;
  parameterNames: string[];
}

interface FragmentState extends PythonGraphFragment {
  nodeKeys: Map<string, string>;
  edgeKeys: Set<string>;
  flowKeys: Set<string>;
}

const sourcePattern = /\b(?:request|req|ctx|context)\s*\.\s*(?:args|form|values|json|headers|cookies|files|GET|POST|PUT|PATCH|META|COOKIES|FILES|data|body|query_params|path_params)\b|\b(?:os\s*\.\s*environ(?:\s*\.\s*get)?|sys\s*\.\s*argv|input)\s*(?:\(|\b)/gi;

const sinkPatterns: Array<{ kind: string; pattern: RegExp }> = [
  { kind: "DYNAMIC_CODE", pattern: /\b(?:eval|exec)\s*\(/gi },
  { kind: "COMMAND_EXECUTION", pattern: /\b(?:os\s*\.\s*(?:system|popen)|(?:popen|system)|subprocess\s*\.\s*(?:run|Popen|call|check_call|check_output|getoutput|getstatusoutput))\s*\(/gi },
  { kind: "COMMAND_EXECUTION", pattern: /\b(?:rp)\s*\([^)]*(?:\+|%|request|address|command|cmd)\b/gi },
  { kind: "QUERY_EXECUTION", pattern: /\b(?:execute|executemany|executescript)\s*\(/gi },
  { kind: "SSTI", pattern: /\b(?:render_template_string|jinja2\s*\.\s*(?:Template|Environment)|Template)\s*\(/gi },
  { kind: "REDIRECT", pattern: /\b(?:redirect|flask\s*\.\s*redirect)\s*\(/gi },
  { kind: "OUTBOUND_REQUEST", pattern: /\b(?:requests|httpx|urllib\s*\.\s*request|urlopen)\s*\.\s*(?:get|post|put|patch|request|urlopen)\s*\(/gi },
  { kind: "XML_PARSE", pattern: /\b(?:etree\s*\.\s*(?:XMLParser|fromstring|parse)|XMLParser|fromstring)\s*\(/gi },
  { kind: "UNSAFE_DESERIALIZATION", pattern: /\b(?:pickle|marshal|yaml)\s*\.\s*(?:loads|load)\s*\(/gi },
  { kind: "HTML_OUTPUT", pattern: /\b(?:return|make_response|Response)\b[^\r\n]*(?:\+|%)[^\r\n]*|(?:\+|%)[^\r\n]*\b[A-Za-z_]\w*\b[^\r\n]*(?:\+|%|(?:request|req)\s*\.)|(?:\+|%)[^\r\n]*\b(?:request|req)\s*\./gi },
  { kind: "PASSWORD_STORAGE", pattern: /\b(?:password|passwd|secret)\s*=\s*(?:request|req|user_input|input|raw_input)\b/gi },
  { kind: "PATH_FILE", pattern: /\b(?:open|send_file|send_from_directory)\s*\(/gi },
];

const guardPattern = /\b(?:sanitize|sanitise|validate|allowlist|allow_list|escape|safe_join|authorize|authorise|permission|is_safe|parameterized|parameterised)\s*\(/i;

function stableId(parts: string[]): string {
  return createHash("sha256").update(parts.join("\0"), "utf8").digest("hex").slice(0, 24);
}

function normalizePath(value: string): string {
  return value.replace(/\\/g, "/").replace(/^\.\//, "");
}

function fileNodeId(file: string): string {
  return `file:${stableId([file])}`;
}

export function maskPython(content: string): string {
  type Mode = "single" | "double" | "triple-single" | "triple-double" | "comment" | null;
  let mode: Mode = null;
  let escaped = false;
  let output = "";
  for (let index = 0; index < content.length; index += 1) {
    const current = content[index];
    const next = content[index + 1];
    const third = content[index + 2];
    if (mode === "comment") {
      if (current === "\n" || current === "\r") {
        mode = null;
        output += current;
      } else output += " ";
      continue;
    }
    if (mode === "triple-single" || mode === "triple-double") {
      const quote = mode === "triple-single" ? "'" : '"';
      if (current === quote && next === quote && third === quote) {
        output += "   ";
        index += 2;
        mode = null;
      } else output += current === "\n" || current === "\r" ? current : " ";
      continue;
    }
    if (mode === "single" || mode === "double") {
      const quote = mode === "single" ? "'" : '"';
      if (escaped) {
        output += current === "\n" || current === "\r" ? current : " ";
        escaped = false;
      } else if (current === "\\") {
        output += " ";
        escaped = true;
      } else if (current === quote) {
        output += " ";
        mode = null;
      } else output += current === "\n" || current === "\r" ? current : " ";
      continue;
    }
    if (current === "#") {
      output += " ";
      mode = "comment";
      continue;
    }
    if (current === "'" && next === "'" && third === "'") {
      output += "   ";
      index += 2;
      mode = "triple-single";
      continue;
    }
    if (current === '"' && next === '"' && third === '"') {
      output += "   ";
      index += 2;
      mode = "triple-double";
      continue;
    }
    if (current === "'") {
      output += " ";
      mode = "single";
      escaped = false;
      continue;
    }
    if (current === '"') {
      output += " ";
      mode = "double";
      escaped = false;
      continue;
    }
    output += current;
  }
  return output;
}

function indentation(line: string): number {
  return line.match(/^\s*/)?.[0].replace(/\t/g, "    ").length ?? 0;
}

function namesIn(text: string, names: Iterable<string>): string[] {
  return [...names].filter((name) => new RegExp(`\\b${name.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}\\b`).test(text));
}

function boundaryParameter(name: string): boolean {
  return /^(?:request|req|ctx|context|user_input|raw_input|input|payload|query|params|body|url|command|cmd|filename|username|user_id|book_title|title|slug|identifier|email)$/i.test(name);
}

function linePosition(line: number, offset: number): { line: number; column: number; endLine: number } {
  return { line, column: Math.max(1, offset + 1), endLine: line };
}

function addNode(state: FragmentState, file: string, line: number, column: number, kind: CodeGraphNode["kind"], name: string, detail: string, snippet: string): string {
  const normalizedFile = normalizePath(file);
  const key = `${normalizedFile}:${line}:${column}:${kind}:${name}`;
  const existing = state.nodeKeys.get(key);
  if (existing) return existing;
  const id = `${kind.toLowerCase()}:py:${stableId([normalizedFile, String(line), String(column), kind, name])}`;
  state.nodeKeys.set(key, id);
  state.nodes.push({ id, kind, file: normalizedFile, line, column, endLine: line, name, detail, snippet: snippet.trim().replace(/\s+/g, " ").slice(0, 280) });
  return id;
}

function addEdge(state: FragmentState, edge: CodeGraphEdge): void {
  const key = `${edge.from}\0${edge.to}\0${edge.kind}\0${edge.label ?? ""}`;
  if (state.edgeKeys.has(key)) return;
  state.edgeKeys.add(key);
  state.edges.push(edge);
}

function addFlow(state: FragmentState, sourceId: string, sinkId: string, controls: string[], reason: string, pathNodeIds: string[]): void {
  const key = `${sourceId}\0${sinkId}`;
  if (state.flowKeys.has(key)) return;
  state.flowKeys.add(key);
  state.flows.push({
    id: `flow:py:${stableId([sourceId, sinkId])}`,
    sourceNodeId: sourceId,
    sinkNodeId: sinkId,
    pathNodeIds,
    controlNodeIds: [...controls],
    status: "POSSIBLE",
    reason,
  });
  addEdge(state, { from: sourceId, to: sinkId, kind: "DATA_FLOW", confidence: "MEDIUM", label: reason });
}

function sourceMatches(line: string): Array<{ index: number; text: string }> {
  sourcePattern.lastIndex = 0;
  return [...line.matchAll(sourcePattern)].map((match) => ({ index: match.index ?? 0, text: match[0] }));
}

function sinkMatches(line: string, includeHtmlOutput = true): Array<{ index: number; text: string; kind: string }> {
  const matches: Array<{ index: number; text: string; kind: string }> = [];
  for (const candidate of sinkPatterns) {
    if (!includeHtmlOutput && candidate.kind === "HTML_OUTPUT") continue;
    candidate.pattern.lastIndex = 0;
    for (const match of line.matchAll(candidate.pattern)) matches.push({ index: match.index ?? 0, text: match[0], kind: candidate.kind });
  }
  return matches.sort((left, right) => left.index - right.index || left.kind.localeCompare(right.kind));
}

function callArgumentText(line: string, index: number): string {
  const open = line.indexOf("(", index);
  if (open < 0) return "";
  let depth = 0;
  for (let cursor = open; cursor < line.length; cursor += 1) {
    if (line[cursor] === "(") depth += 1;
    else if (line[cursor] === ")") {
      depth -= 1;
      if (depth === 0) return line.slice(open + 1, cursor);
    }
  }
  return line.slice(open + 1);
}

function functionNameAndParameters(line: string): { name: string; parameters: string[]; indent: number } | null {
  const match = line.match(/^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*:/);
  if (!match) return null;
  const parameters = match[3]
    .split(",")
    .map((parameter) => parameter.trim().replace(/=.*$/, "").replace(/^\*+/, "").split(":", 1)[0].trim())
    .filter((parameter) => /^[A-Za-z_]\w*$/.test(parameter));
  return { name: match[2], parameters, indent: indentation(line) };
}

function findFunctions(file: string, lines: string[]): PythonFunction[] {
  const functions: PythonFunction[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const parsed = functionNameAndParameters(lines[index]);
    if (!parsed) continue;
    let endLine = lines.length;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      if (lines[cursor].trim() && indentation(lines[cursor]) <= parsed.indent) {
        endLine = cursor;
        break;
      }
    }
    const nodeId = `function:py:${stableId([file, String(index + 1), String(parsed.indent + 1), "FUNCTION", parsed.name])}`;
    functions.push({ name: parsed.name, file, line: index + 1, indent: parsed.indent, endLine, parameters: parsed.parameters, nodeId });
  }
  return functions;
}

function functionForLine(functions: PythonFunction[], lineIndex: number): PythonFunction | null {
  return functions
    .filter((candidate) => lineIndex >= candidate.line - 1 && lineIndex < candidate.endLine)
    .sort((left, right) => right.line - left.line || right.indent - left.indent)[0] ?? null;
}

function sinkRuleKind(kind: string): string {
  return kind;
}

function buildPythonFile(state: FragmentState, file: FileFingerprint, content: string, allFiles: Set<string>): void {
  const normalizedFile = normalizePath(file.path);
  const rawLines = content.split(/\r?\n/);
  const lines = maskPython(content).split(/\r?\n/);
  const functions = findFunctions(normalizedFile, lines);
  const webContext = /\b(?:flask|django|fastapi|starlette|bottle|render_template|request)\b/i.test(content);
  const htmlContext = webContext && (/<\s*(?:html|body|br|form|script|iframe|img|a|p|div|span|h[1-6]|li|ul|ol|table|textarea)\b/i.test(content) || /\brender_template_string\s*\(/i.test(content));
  for (const fn of functions) {
    addNode(state, normalizedFile, fn.line, fn.indent + 1, "FUNCTION", fn.name, "Python function scope used for bounded source-to-sink analysis.", rawLines[fn.line - 1] ?? "");
    addEdge(state, { from: fileNodeId(normalizedFile), to: fn.nodeId, kind: "CONTAINS", confidence: "HIGH" });
  }

  for (const rawLine of rawLines) {
    const importMatch = rawLine.match(/^\s*(?:from\s+([.\w]+)\s+import|import\s+([.\w]+))/);
    if (!importMatch) continue;
    const specifier = importMatch[1] ?? importMatch[2] ?? "";
    if (!specifier.startsWith(".")) continue;
    const base = normalizePath(`${pathWithoutExtension(normalizedFile)}/../${specifier.replace(/^\.+/, "")}`);
    const candidates = [
      `${base}.py`,
      `${base}/__init__.py`,
    ].map(normalizePath);
    const target = candidates.find((candidate) => allFiles.has(candidate));
    if (target) addEdge(state, { from: fileNodeId(normalizedFile), to: fileNodeId(target), kind: "IMPORT", confidence: "HIGH", label: specifier });
  }

  const summaries: PythonSinkSummary[] = [];
  const scopes = [
    { function: null as PythonFunction | null, start: 0, end: lines.length, parameters: [] as string[] },
    ...functions.map((fn) => ({ function: fn, start: fn.line, end: fn.endLine, parameters: fn.parameters })),
  ];
  for (const scope of scopes) {
    const stateByName: TaintState = { origins: new Map(), parameters: new Map() };
    const pendingTemplates = new Map<string, number>();
    for (const parameter of scope.parameters) {
      stateByName.parameters.set(parameter, new Set([parameter]));
      if (boundaryParameter(parameter) && scope.function) {
        const offset = Math.max(0, (rawLines[scope.function.line - 1] ?? "").indexOf(parameter));
        const sourceId = addNode(state, normalizedFile, scope.function.line, offset + 1, "SOURCE", parameter, "Conservatively treated as an external boundary parameter.", rawLines[scope.function.line - 1] ?? "");
        stateByName.origins.set(parameter, new Set([sourceId]));
      }
    }
    for (let lineIndex = scope.start; lineIndex < scope.end; lineIndex += 1) {
      const masked = lines[lineIndex] ?? "";
      const raw = rawLines[lineIndex] ?? "";
      if (!scope.function && functions.some((fn) => lineIndex >= fn.line - 1 && lineIndex < fn.endLine)) continue;
      if (!masked.trim() && pendingTemplates.size === 0 || functionNameAndParameters(masked)) continue;
      for (const [templateName, startLine] of pendingTemplates) {
        const embeddedOrigins = [...new Set(namesIn(raw, stateByName.origins.keys()).flatMap((name) => [...(stateByName.origins.get(name) ?? [])]))];
        if (embeddedOrigins.length > 0) stateByName.origins.set(templateName, new Set(embeddedOrigins));
        if (lineIndex > startLine && /(?:'''|\"\"\")/.test(raw)) pendingTemplates.delete(templateName);
      }
      const currentFunction = scope.function;
      const controls: string[] = [];
      if (guardPattern.test(masked)) {
        const guardOffset = Math.max(0, masked.search(guardPattern));
        controls.push(addNode(state, normalizedFile, lineIndex + 1, guardOffset + 1, "GUARD", masked.slice(guardOffset).split("(")[0].trim(), "Potential validation, authorization, escaping, or allowlist guard.", raw));
        addEdge(state, { from: controls[0], to: currentFunction?.nodeId ?? fileNodeId(normalizedFile), kind: "GUARDS", confidence: "MEDIUM" });
      }

      const assignment = masked.match(/^\s*([A-Za-z_]\w*)\s*=\s*(?![=])(.+)$/);
      if (assignment) {
        const name = assignment[1];
        const expression = assignment[2];
        const rawAssignment = raw.match(/^\s*[A-Za-z_]\w*\s*=\s*(?![=])(.+)$/)?.[1] ?? raw;
        const origins = new Set<string>();
        for (const source of sourceMatches(expression)) {
          const sourceId = addNode(state, normalizedFile, lineIndex + 1, masked.indexOf(source.text) + 1, "SOURCE", source.text.trim(), "Attacker-controlled or environment-derived Python input.", raw);
          origins.add(sourceId);
        }
        for (const variable of namesIn(expression, stateByName.origins.keys())) for (const origin of stateByName.origins.get(variable) ?? []) origins.add(origin);
        for (const interpolation of rawAssignment.matchAll(/\{\s*([A-Za-z_]\w*)\s*[^}]*\}/g)) {
          for (const origin of stateByName.origins.get(interpolation[1]) ?? []) origins.add(origin);
        }
        const parameters = new Set<string>();
        for (const variable of namesIn(expression, stateByName.parameters.keys())) for (const parameter of stateByName.parameters.get(variable) ?? []) parameters.add(parameter);
        for (const interpolation of rawAssignment.matchAll(/\{\s*([A-Za-z_]\w*)\s*[^}]*\}/g)) {
          for (const parameter of stateByName.parameters.get(interpolation[1]) ?? []) parameters.add(parameter);
        }
        if (origins.size > 0 || parameters.size > 0) {
          const variableId = addNode(state, normalizedFile, lineIndex + 1, Math.max(1, masked.indexOf(name) + 1), "VARIABLE", name, "Python value carrying boundary taint.", raw);
          stateByName.origins.set(name, origins);
          stateByName.parameters.set(name, parameters);
          for (const origin of origins) addEdge(state, { from: origin, to: variableId, kind: "DATA_FLOW", confidence: "HIGH" });
        }
        if (/(?:'''|\"\"\")/.test(raw)) pendingTemplates.set(name, lineIndex);
      }

      if (!masked.trim()) continue;

      for (const sink of sinkMatches(masked, htmlContext)) {
        const callNodeId = addNode(state, normalizedFile, lineIndex + 1, sink.index + 1, "CALL", sink.text.replace(/\s*\($/, ""), "Python call expression discovered by the source-to-sink graph.", raw);
        addEdge(state, { from: currentFunction?.nodeId ?? fileNodeId(normalizedFile), to: callNodeId, kind: "CALLS", confidence: "MEDIUM", label: sink.text });
        const sinkNodeId = addNode(state, normalizedFile, lineIndex + 1, sink.index + 1, "SINK", sink.text.replace(/\s*\($/, ""), sinkRuleKind(sink.kind), raw);
        addEdge(state, { from: callNodeId, to: sinkNodeId, kind: "CONTAINS", confidence: "HIGH", label: sink.kind });
        const argumentText = sink.kind === "HTML_OUTPUT" || sink.kind === "PASSWORD_STORAGE" ? masked : callArgumentText(masked, sink.index);
        const origins = new Set<string>();
        for (const source of sourceMatches(argumentText)) {
          const sourceId = addNode(state, normalizedFile, lineIndex + 1, sink.index + Math.max(1, argumentText.indexOf(source.text)) + 2, "SOURCE", source.text.trim(), "Attacker-controlled or environment-derived Python input.", raw);
          origins.add(sourceId);
        }
        for (const variable of namesIn(argumentText, stateByName.origins.keys())) for (const origin of stateByName.origins.get(variable) ?? []) origins.add(origin);
        const parameterNames = new Set<string>();
        for (const variable of namesIn(argumentText, stateByName.parameters.keys())) for (const parameter of stateByName.parameters.get(variable) ?? []) parameterNames.add(parameter);
        for (const origin of origins) addFlow(state, origin, sinkNodeId, controls, `A Python boundary value reaches a ${sink.kind} sink.`, [origin, callNodeId, sinkNodeId]);
        if (currentFunction && parameterNames.size > 0) summaries.push({ function: currentFunction, sinkNodeId, kind: sink.kind, parameterNames: [...parameterNames].sort() });
      }
    }
  }

  const uniqueSummaries = summaries.filter((summary, index, all) => all.findIndex((candidate) => candidate.sinkNodeId === summary.sinkNodeId && candidate.parameterNames.join("\0") === summary.parameterNames.join("\0")) === index);
  const functionsByName = new Map<string, PythonFunction[]>();
  for (const fn of functions) functionsByName.set(fn.name, [...(functionsByName.get(fn.name) ?? []), fn]);
  for (const scope of scopes) {
    const currentFunction = scope.function;
    const stateByName: TaintState = { origins: new Map(), parameters: new Map() };
    for (const parameter of scope.parameters) {
      stateByName.parameters.set(parameter, new Set([parameter]));
      if (boundaryParameter(parameter) && currentFunction) {
        const sourceId = addNode(state, normalizedFile, currentFunction.line, Math.max(1, (rawLines[currentFunction.line - 1] ?? "").indexOf(parameter) + 1), "SOURCE", parameter, "Conservatively treated as an external boundary parameter.", rawLines[currentFunction.line - 1] ?? "");
        stateByName.origins.set(parameter, new Set([sourceId]));
      }
    }
    for (let lineIndex = scope.start; lineIndex < scope.end; lineIndex += 1) {
      const masked = lines[lineIndex] ?? "";
      const raw = rawLines[lineIndex] ?? "";
      if (!scope.function && functions.some((fn) => lineIndex >= fn.line - 1 && lineIndex < fn.endLine)) continue;
      if (!masked.trim() || functionNameAndParameters(masked)) continue;
      const assignment = masked.match(/^\s*([A-Za-z_]\w*)\s*=\s*(?![=])(.+)$/);
      if (assignment) {
        const origins = new Set<string>();
        for (const variable of namesIn(assignment[2], stateByName.origins.keys())) for (const origin of stateByName.origins.get(variable) ?? []) origins.add(origin);
        for (const source of sourceMatches(assignment[2])) origins.add(addNode(state, normalizedFile, lineIndex + 1, Math.max(1, masked.indexOf(source.text) + 1), "SOURCE", source.text.trim(), "Attacker-controlled or environment-derived Python input.", raw));
        const parameters = new Set<string>();
        for (const variable of namesIn(assignment[2], stateByName.parameters.keys())) for (const parameter of stateByName.parameters.get(variable) ?? []) parameters.add(parameter);
        if (origins.size > 0 || parameters.size > 0) {
          stateByName.origins.set(assignment[1], origins);
          stateByName.parameters.set(assignment[1], parameters);
        }
      }
      const calls = [...masked.matchAll(/\b([A-Za-z_]\w*)\s*\(/g)];
      for (const call of calls) {
        const helperName = call[1];
        const candidates = functionsByName.get(helperName) ?? [];
        if (candidates.length !== 1 || candidates[0] === currentFunction) continue;
        const helper = candidates[0];
        const argumentText = callArgumentText(masked, call.index ?? 0);
        const argumentOrigins = [...new Set(namesIn(argumentText, stateByName.origins.keys()).flatMap((name) => [...(stateByName.origins.get(name) ?? [])]))];
        if (argumentOrigins.length === 0) continue;
        const args = argumentText.split(",").map((value) => value.trim());
        for (const summary of uniqueSummaries.filter((candidate) => candidate.function === helper)) {
          for (const parameter of summary.parameterNames) {
            const parameterIndex = helper.parameters.indexOf(parameter);
            if (parameterIndex < 0) continue;
            const argument = args[parameterIndex] ?? "";
            const origins = [...new Set(namesIn(argument, stateByName.origins.keys()).flatMap((name) => [...(stateByName.origins.get(name) ?? [])]))];
            for (const origin of origins) {
              const callNodeId = addNode(state, normalizedFile, lineIndex + 1, (call.index ?? 0) + 1, "CALL", helperName, "Python helper call used for interprocedural flow resolution.", raw);
              addEdge(state, { from: currentFunction?.nodeId ?? fileNodeId(normalizedFile), to: callNodeId, kind: "CALLS", confidence: "MEDIUM", label: helperName });
              addFlow(state, origin, summary.sinkNodeId, [], `A tainted argument reaches Python helper parameter ${parameter} and then a ${summary.kind} sink.`, [origin, callNodeId, summary.sinkNodeId]);
            }
          }
        }
      }
    }
  }
}

function pathWithoutExtension(file: string): string {
  return file.endsWith(".py") ? file.slice(0, -3) : file;
}

export function buildPythonGraph(files: FileFingerprint[], contents: Map<string, string>): PythonGraphFragment {
  const state: FragmentState = { nodes: [], edges: [], flows: [], nodeKeys: new Map(), edgeKeys: new Set(), flowKeys: new Set() };
  const allFiles = new Set(files.map((file) => normalizePath(file.path)));
  for (const file of files.filter((candidate) => candidate.path.toLowerCase().endsWith(".py"))) buildPythonFile(state, file, contents.get(file.path) ?? "", allFiles);
  return { nodes: state.nodes, edges: state.edges, flows: state.flows };
}
