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
  parameterSpecs: string[];
  route: boolean;
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
  sourceKinds: Map<string, "STRUCTURED_REQUEST" | "BOUNDARY_PARAMETER" | "CONFIGURATION">;
}

const sourcePattern = /\b(?:request|req|ctx|context)\s*\.\s*(?:args|form|values|json|headers|cookies|files|GET|POST|PUT|PATCH|META|COOKIES|FILES|data|body|query_params|path_params)\b|\b(?:self\s*\.\s*)?get_argument\s*\(|\bself\s*\.\s*request\s*\.\s*(?:arguments|body|files|uri|query)\b|\b(?:os\s*\.\s*(?:environ(?:\s*\.\s*get)?|getenv)|sys\s*\.\s*argv|input)\s*(?:\(|\b)|\b(?:config|settings)\s*\.\s*[A-Za-z_]\w*(?:URL|URI|ENDPOINT|HOST|PORT|TOKEN|SECRET|KEY)\b/gi;

const sinkPatterns: Array<{ kind: string; pattern: RegExp }> = [
  { kind: "DYNAMIC_CODE", pattern: /\b(?:eval|exec)\s*\(/gi },
  { kind: "COMMAND_EXECUTION", pattern: /\b(?:os\s*\.\s*(?:system|popen)|(?:popen|system)|subprocess\s*\.\s*(?:run|Popen|call|check_call|check_output|getoutput|getstatusoutput))\s*\(/gi },
  { kind: "COMMAND_EXECUTION", pattern: /\b(?:rp)\s*\([^)]*(?:\+|%|request|address|command|cmd)\b/gi },
  { kind: "QUERY_EXECUTION", pattern: /\b(?:execute|executemany|executescript|raw)\s*\(/gi },
  { kind: "NOSQL_QUERY", pattern: /\b(?:find|find_one|find_one_and_update|find_one_and_delete|delete_one|delete_many|update_one|update_many|replace_one|aggregate)\s*\(/gi },
  { kind: "SSTI", pattern: /\b(?:render_template_string|jinja2\s*\.\s*(?:Template|Environment)|Template)\s*\(/gi },
  { kind: "REDIRECT", pattern: /\b(?:redirect|HttpResponseRedirect|flask\s*\.\s*redirect)\s*\(/gi },
  { kind: "OUTBOUND_REQUEST", pattern: /\b(?:requests|httpx|urllib\s*\.\s*request|urlopen)\s*\.\s*(?:get|post|put|patch|request|urlopen)\s*\(/gi },
  { kind: "XML_PARSE", pattern: /\b(?:etree\s*\.\s*(?:XMLParser|fromstring|parse)|XMLParser|fromstring)\s*\(/gi },
  { kind: "UNSAFE_DESERIALIZATION", pattern: /\b(?:pickle|marshal|yaml)\s*\.\s*(?:loads|load)\s*\(/gi },
  { kind: "HTML_OUTPUT", pattern: /\b(?:return|make_response|Response|HttpResponse)\b[^\r\n]*(?:\+|%)[^\r\n]*|(?:\+|%)[^\r\n]*\b[A-Za-z_]\w*\b[^\r\n]*(?:\+|%|(?:request|req)\s*\.)|(?:\+|%)[^\r\n]*\b(?:request|req)\s*\./gi },
  { kind: "PASSWORD_STORAGE", pattern: /\b(?:password|passwd|secret)\s*=\s*(?:request|req|user_input|input|raw_input|form|data|payload)\b/gi },
  { kind: "PATH_FILE", pattern: /\b(?:open|send_file|send_from_directory|os\s*\.\s*path\s*\.\s*join)\s*\(/gi },
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
  return /^(?:request|req|ctx|context|user_input|raw_input|input|payload|query|params|body|url|command|cmd|filename|file_name|full_file_name|full_path|data_path|username|user_id|user_id_form|book_title|title|slug|identifier|email|input_email|input_password|password|ip|host|port|col|field|redirect|next)$/i.test(name);
}

function splitParameterSpecs(value: string): string[] {
  const output: string[] = [];
  let start = 0;
  let depth = 0;
  for (let index = 0; index < value.length; index += 1) {
    const current = value[index];
    if (current === "(" || current === "[" || current === "{") depth += 1;
    else if (current === ")" || current === "]" || current === "}") depth = Math.max(0, depth - 1);
    else if (current === "," && depth === 0) {
      output.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  const final = value.slice(start).trim();
  if (final) output.push(final);
  return output;
}

function isRouteDecorator(line: string): boolean {
  return /^\s*@\s*(?:[A-Za-z_]\w*\s*\.\s*)?(?:route|get|post|put|patch|delete|options|head|api_route)\s*\(/i.test(line);
}

function hasRouteDecorator(lines: string[], functionIndex: number): boolean {
  for (let cursor = functionIndex - 1; cursor >= 0; cursor -= 1) {
    const line = lines[cursor] ?? "";
    if (!line.trim()) continue;
    if (line.trim().startsWith("@")) {
      if (isRouteDecorator(line)) return true;
      continue;
    }
    break;
  }
  return false;
}

function routeBoundaryParameter(spec: string, name: string, route: boolean): boolean {
  if (route && /\b(?:Depends|Security)\s*\(/i.test(spec)) return false;
  if (boundaryParameter(name)) return true;
  if (!route) return false;
  if (/\b(?:BackgroundTasks|Response|WebSocket)\b/i.test(spec)) return false;
  if (/^(?:self|cls|db|database|session|settings|config|current_user|principal|claims|token|credentials|background_tasks|response|websocket|app)$/i.test(name)) return false;
  return true;
}

function sourceKind(text: string): "STRUCTURED_REQUEST" | "BOUNDARY_PARAMETER" | "CONFIGURATION" {
  if (/\b(?:config|settings)\s*\./i.test(text)) return "CONFIGURATION";
  return /\b(?:request|req)\s*\.\s*(?:json|body|data|query_params|path_params|form|values|files|GET|POST|PUT|PATCH|META|COOKIES|FILES)\b|\b(?:self\s*\.\s*)?get_argument\s*\(|\bself\s*\.\s*request\s*\.\s*(?:arguments|body|files|uri|query)\b/i.test(text)
    ? "STRUCTURED_REQUEST"
    : "BOUNDARY_PARAMETER";
}

function isPasswordPersistenceContext(context: string): boolean {
  return /\b(?:User|Account|Credential|Customer|Profile|Model)\s*\(/i.test(context)
    || /\b(?:objects|db|session|record|model)\s*\.\s*(?:create|create_user|add|insert|update|save|bulk_create)\s*\(/i.test(context)
    || /\b(?:create_user|register_user)\s*\(/i.test(context);
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

function firstCallArgumentText(argumentsText: string): string {
  let quote: string | null = null;
  let escaped = false;
  let depth = 0;
  for (let index = 0; index < argumentsText.length; index += 1) {
    const current = argumentsText[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (current === "\\") escaped = true;
      else if (current === quote) quote = null;
      continue;
    }
    if (current === "'" || current === '"' || current === "`") {
      quote = current;
      continue;
    }
    if (current === "(" || current === "[" || current === "{") depth += 1;
    else if (current === ")" || current === "]" || current === "}") depth = Math.max(0, depth - 1);
    else if (current === "," && depth === 0) return argumentsText.slice(0, index);
  }
  return argumentsText;
}

function redirectTargetVariable(name: string): boolean {
  return /^(?:url|uri|next|continue|return|return_to|return_url|redirect|redirect_to|target|destination|dest|location|path|link|lane)$/i.test(name)
    || /(?:_url|_uri|_path|_location|_destination|_target)$/i.test(name);
}

function boundedCallText(lines: string[], lineIndex: number, sinkIndex: number): string {
  let output = lines[lineIndex] ?? "";
  let depth = 0;
  let started = false;
  const updateDepth = (value: string): void => {
    for (const character of value.slice(started ? 0 : sinkIndex)) {
      if (character === "(") {
        depth += 1;
        started = true;
      } else if (character === ")" && started) depth = Math.max(0, depth - 1);
    }
  };
  updateDepth(output);
  for (let cursor = lineIndex + 1; depth > 0 && cursor < Math.min(lines.length, lineIndex + 6); cursor += 1) {
    output += ` ${lines[cursor] ?? ""}`;
    updateDepth(lines[cursor] ?? "");
  }
  return output;
}

function functionNameAndParameters(line: string): { name: string; parameters: string[]; parameterSpecs: string[]; indent: number } | null {
  const match = line.match(/^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*:/);
  if (!match) return null;
  const parameterSpecs = splitParameterSpecs(match[3]);
  const parameters = parameterSpecs
    .map((parameter) => parameter.replace(/=.*$/, "").replace(/^\*+/, "").split(":", 1)[0].trim())
    .filter((parameter) => /^[A-Za-z_]\w*$/.test(parameter));
  return { name: match[2], parameters, parameterSpecs, indent: indentation(line) };
}

function findFunctions(file: string, lines: string[], tornadoHandler = false): PythonFunction[] {
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
    functions.push({
      name: parsed.name,
      file,
      line: index + 1,
      indent: parsed.indent,
      endLine,
      parameters: parsed.parameters,
      parameterSpecs: parsed.parameterSpecs,
      route: hasRouteDecorator(lines, index) || (tornadoHandler && /^(?:get|post|put|patch|delete|head|options)$/i.test(parsed.name)),
      nodeId,
    });
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

function addSourceNode(
  state: FragmentState,
  file: string,
  line: number,
  column: number,
  name: string,
  detail: string,
  snippet: string,
  kind: "STRUCTURED_REQUEST" | "BOUNDARY_PARAMETER" | "CONFIGURATION",
): string {
  const id = addNode(state, file, line, column, "SOURCE", name, detail, snippet);
  state.sourceKinds.set(id, kind);
  return id;
}

function flowOriginsForSink(state: FragmentState, sinkKind: string, origins: Iterable<string>): string[] {
  const values = [...origins];
  if (sinkKind === "SSTI") return values.filter((origin) => state.sourceKinds.get(origin) !== "CONFIGURATION");
  if (sinkKind !== "NOSQL_QUERY") return values;
  // A scalar route value interpolated into a fixed object key is not a NoSQL
  // operator injection. Require a structured request object to reach the
  // query sink, which preserves the important distinction in Mongo-like APIs.
  return values.filter((origin) => state.sourceKinds.get(origin) === "STRUCTURED_REQUEST");
}

function buildPythonFile(state: FragmentState, file: FileFingerprint, content: string, allFiles: Set<string>): void {
  const normalizedFile = normalizePath(file.path);
  const rawLines = content.split(/\r?\n/);
  const lines = maskPython(content).split(/\r?\n/);
  const tornadoContext = /\b(?:tornado\s*\.\s*web\s*\.\s*RequestHandler|RequestHandler)\b/.test(content);
  const functions = findFunctions(normalizedFile, lines, tornadoContext);
  const webContext = /\b(?:flask|django|fastapi|starlette|bottle|tornado|render_template|request)\b/i.test(content);
  const htmlContext = webContext && (/<\s*(?:html|body|br|form|script|iframe|img|a|p|div|span|h[1-6]|li|ul|ol|table|textarea)\b/i.test(content) || /\brender_template_string\s*\(/i.test(content));
  const modelContext = /(?:^|\/)models(?:\/|$)/i.test(normalizedFile);
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
    const explicitVulnerableBranch = scope.function ? /\bif\s+vuln\b/.test(lines.slice(scope.start, scope.end).join("\n")) : false;
    for (const parameter of scope.parameters) {
      stateByName.parameters.set(parameter, new Set([parameter]));
      const parameterIndex = scope.function?.parameters.indexOf(parameter) ?? -1;
      const parameterSpec = parameterIndex >= 0 ? scope.function?.parameterSpecs[parameterIndex] ?? parameter : parameter;
      if (scope.function && (scope.function.route || explicitVulnerableBranch || modelContext) && routeBoundaryParameter(parameterSpec, parameter, true)) {
        const offset = Math.max(0, (rawLines[scope.function.line - 1] ?? "").indexOf(parameter));
        const sourceId = addSourceNode(state, normalizedFile, scope.function.line, offset + 1, parameter, scope.function.route ? "FastAPI or web route parameter treated as an external boundary input." : "Conservatively treated as an external boundary parameter.", rawLines[scope.function.line - 1] ?? "", "BOUNDARY_PARAMETER");
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
          const sourceId = addSourceNode(state, normalizedFile, lineIndex + 1, masked.indexOf(source.text) + 1, source.text.trim(), "Attacker-controlled or environment-derived Python input.", raw, sourceKind(source.text));
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

      const sinks = sinkMatches(masked, htmlContext);
      const htmlAssignment = htmlContext
        && /^\s*[A-Za-z_]\w*\s*=/.test(masked)
        && /<\s*(?:html|body|h[1-6]|p|div|span|a|script|iframe|code)\b/i.test(raw)
        && /(?:\{\s*[A-Za-z_]\w*[^}]*\}|%\s*[A-Za-z_(])/.test(raw)
        && !sinks.some((sink) => sink.kind === "HTML_OUTPUT");
      if (htmlAssignment) sinks.push({ index: Math.max(0, masked.search(/[A-Za-z_]\w*\s*=/)), text: "HTML assignment", kind: "HTML_OUTPUT" });
      for (const sink of sinks.sort((left, right) => left.index - right.index || left.kind.localeCompare(right.kind))) {
        if (sink.kind === "PASSWORD_STORAGE") {
          const context = lines
            .slice(Math.max(0, lineIndex - 2), Math.min(lines.length, lineIndex + 3))
            .join(" ");
          if (!isPasswordPersistenceContext(context)) continue;
        }
        const callNodeId = addNode(state, normalizedFile, lineIndex + 1, sink.index + 1, "CALL", sink.text.replace(/\s*\($/, ""), "Python call expression discovered by the source-to-sink graph.", raw);
        addEdge(state, { from: currentFunction?.nodeId ?? fileNodeId(normalizedFile), to: callNodeId, kind: "CALLS", confidence: "MEDIUM", label: sink.text });
        const sinkNodeId = addNode(state, normalizedFile, lineIndex + 1, sink.index + 1, "SINK", sink.text.replace(/\s*\($/, ""), sinkRuleKind(sink.kind), raw);
        addEdge(state, { from: callNodeId, to: sinkNodeId, kind: "CONTAINS", confidence: "HIGH", label: sink.kind });
        const multilineCall = /^(?:QUERY_EXECUTION|COMMAND_EXECUTION|PATH_FILE)$/.test(sink.kind)
          ? boundedCallText(lines, lineIndex, sink.index)
          : masked;
        const rawMultilineCall = /^(?:QUERY_EXECUTION|COMMAND_EXECUTION|PATH_FILE)$/.test(sink.kind)
          ? boundedCallText(rawLines, lineIndex, sink.index)
          : raw;
        const argumentText = sink.kind === "HTML_OUTPUT" || sink.kind === "PASSWORD_STORAGE" ? masked : callArgumentText(multilineCall, sink.index);
        const taintArgumentText = sink.kind === "QUERY_EXECUTION" ? firstCallArgumentText(argumentText) : argumentText;
        const safeRedirectWrapper = sink.kind === "REDIRECT" && /\b(?:url_for|reverse|redirect_to|build_absolute_uri)\s*\(/i.test(taintArgumentText);
        if (sink.kind === "PATH_FILE" && /\b(?:wb|ab|w|a)\b/i.test(rawMultilineCall) && /(?:\/tmp\/|\\\\tmp\\\\|final_filename|output_file)/i.test(rawMultilineCall)) continue;
        const origins = new Set<string>();
        const matchedSources = sourceMatches(taintArgumentText).filter((source) => !safeRedirectWrapper && (sink.kind !== "PASSWORD_STORAGE" || source.index >= sink.index));
        for (const source of matchedSources) {
          const sourceId = addSourceNode(state, normalizedFile, lineIndex + 1, sink.index + Math.max(1, argumentText.indexOf(source.text)) + 2, source.text.trim(), "Attacker-controlled or environment-derived Python input.", raw, sourceKind(source.text));
          origins.add(sourceId);
        }
        for (const variable of namesIn(taintArgumentText, stateByName.origins.keys())) {
          if (sink.kind === "REDIRECT" && !redirectTargetVariable(variable)) continue;
          for (const origin of stateByName.origins.get(variable) ?? []) origins.add(origin);
        }
        const parameterNames = new Set<string>();
        for (const variable of namesIn(argumentText, stateByName.parameters.keys())) for (const parameter of stateByName.parameters.get(variable) ?? []) parameterNames.add(parameter);
        for (const origin of flowOriginsForSink(state, sink.kind, origins)) addFlow(state, origin, sinkNodeId, controls, `A Python boundary value reaches a ${sink.kind} sink.`, [origin, callNodeId, sinkNodeId]);
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
    const pendingTemplates = new Map<string, number>();
    const explicitVulnerableBranch = currentFunction ? /\bif\s+vuln\b/.test(lines.slice(scope.start, scope.end).join("\n")) : false;
    for (const parameter of scope.parameters) {
      stateByName.parameters.set(parameter, new Set([parameter]));
      const parameterIndex = currentFunction?.parameters.indexOf(parameter) ?? -1;
      const parameterSpec = parameterIndex >= 0 ? currentFunction?.parameterSpecs[parameterIndex] ?? parameter : parameter;
      if (currentFunction && (currentFunction.route || explicitVulnerableBranch || modelContext) && routeBoundaryParameter(parameterSpec, parameter, true)) {
        const sourceId = addSourceNode(state, normalizedFile, currentFunction.line, Math.max(1, (rawLines[currentFunction.line - 1] ?? "").indexOf(parameter) + 1), parameter, currentFunction.route ? "FastAPI or web route parameter treated as an external boundary input." : "Conservatively treated as an external boundary parameter.", rawLines[currentFunction.line - 1] ?? "", "BOUNDARY_PARAMETER");
        stateByName.origins.set(parameter, new Set([sourceId]));
      }
    }
    for (let lineIndex = scope.start; lineIndex < scope.end; lineIndex += 1) {
      const masked = lines[lineIndex] ?? "";
      const raw = rawLines[lineIndex] ?? "";
      if (!scope.function && functions.some((fn) => lineIndex >= fn.line - 1 && lineIndex < fn.endLine)) continue;
      if (functionNameAndParameters(masked)) continue;
      for (const [templateName, startLine] of pendingTemplates) {
        const embeddedOrigins = [...new Set(namesIn(raw, stateByName.origins.keys()).flatMap((name) => [...(stateByName.origins.get(name) ?? [])]))];
        if (embeddedOrigins.length > 0) stateByName.origins.set(templateName, new Set(embeddedOrigins));
        if (lineIndex > startLine && /(?:'''|\"\"\")/.test(raw)) pendingTemplates.delete(templateName);
      }
      if (!masked.trim()) continue;
      const assignment = masked.match(/^\s*([A-Za-z_]\w*)\s*=\s*(?![=])(.+)$/);
      if (assignment) {
        const origins = new Set<string>();
        for (const variable of namesIn(assignment[2], stateByName.origins.keys())) for (const origin of stateByName.origins.get(variable) ?? []) origins.add(origin);
        for (const source of sourceMatches(assignment[2])) origins.add(addSourceNode(state, normalizedFile, lineIndex + 1, Math.max(1, masked.indexOf(source.text) + 1), source.text.trim(), "Attacker-controlled or environment-derived Python input.", raw, sourceKind(source.text)));
        const parameters = new Set<string>();
        for (const variable of namesIn(assignment[2], stateByName.parameters.keys())) for (const parameter of stateByName.parameters.get(variable) ?? []) parameters.add(parameter);
        if (origins.size > 0 || parameters.size > 0) {
          stateByName.origins.set(assignment[1], origins);
          stateByName.parameters.set(assignment[1], parameters);
        }
        if (/(?:'''|\"\"\")/.test(raw)) pendingTemplates.set(assignment[1], lineIndex);
      }
      const calls = [...masked.matchAll(/\b([A-Za-z_]\w*)\s*\(/g)];
      for (const call of calls) {
        const helperName = call[1];
        const candidates = functionsByName.get(helperName) ?? [];
        if (candidates.length !== 1 || candidates[0] === currentFunction) continue;
        const helper = candidates[0];
        const argumentText = callArgumentText(raw, call.index ?? 0);
        const argumentOrigins = [...new Set(namesIn(argumentText, stateByName.origins.keys()).flatMap((name) => [...(stateByName.origins.get(name) ?? [])]))];
        if (argumentOrigins.length === 0) continue;
        const args = argumentText.split(",").map((value) => value.trim());
        for (const summary of uniqueSummaries.filter((candidate) => candidate.function === helper)) {
          for (const parameter of summary.parameterNames) {
            const parameterIndex = helper.parameters.indexOf(parameter);
            if (parameterIndex < 0) continue;
            const argument = args[parameterIndex] ?? "";
            const origins = [...new Set(namesIn(argument, stateByName.origins.keys()).flatMap((name) => [...(stateByName.origins.get(name) ?? [])]))];
            if (summary.kind === "REDIRECT" && !redirectTargetVariable(parameter)) continue;
            for (const origin of flowOriginsForSink(state, summary.kind, origins)) {
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
  const state: FragmentState = { nodes: [], edges: [], flows: [], nodeKeys: new Map(), edgeKeys: new Set(), flowKeys: new Set(), sourceKinds: new Map() };
  const productionFiles = files.filter((candidate) => !/(?:^|[\\/])(?:test|tests|spec|specs|fixture|fixtures|example|examples)(?:[\\/]|$)/i.test(candidate.path));
  const allFiles = new Set(productionFiles.map((file) => normalizePath(file.path)));
  for (const file of productionFiles.filter((candidate) => candidate.path.toLowerCase().endsWith(".py"))) buildPythonFile(state, file, contents.get(file.path) ?? "", allFiles);
  return { nodes: state.nodes, edges: state.edges, flows: state.flows };
}
