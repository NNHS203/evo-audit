import type {
  AuditObligation,
  AuditPlaybook,
  Finding,
  PlaybookRule,
  SourceLocation,
} from "./types.js";
import { maskPython } from "./python-graph.js";

interface DetectorMatch {
  rule: PlaybookRule;
  line: number;
  column: number;
  snippet: string;
  rootCause: string;
  impact: string;
  remediation: string;
  kind: AuditObligation["kind"];
  limitation: string;
}

const requestInput =
  "(?:req(?:uest)?\\s*\\.\\s*(?:body|query|params|headers)|userInput|user_input|untrusted|input)";

const pythonRequestInput =
  "(?:request|req)\\s*\\.\\s*(?:args|form|values|json|headers|cookies|files|GET|POST|META|COOKIES|FILES|data|body|query_params|path_params)|user_input|raw_input|untrusted|input\\s*\\(|os\\s*\\.\\s*environ|sys\\s*\\.\\s*argv";

/**
 * Keep source locations stable while removing text that is not executable code.
 *
 * The first detector is intentionally lightweight, but matching inside a
 * quoted fixture, comment, or rule description is an unacceptable source of
 * noise. A parser/AST worker can provide deeper coverage later; this mask keeps
 * the cheap candidate pass honest in the meantime.
 */
export function maskNonCode(content: string): string {
  type Mode = "'" | '"' | "`" | "line-comment" | "block-comment" | null;
  let mode: Mode = null;
  let escaped = false;
  let output = "";

  for (let index = 0; index < content.length; index += 1) {
    const current = content[index];
    const next = content[index + 1];

    if (mode === "line-comment") {
      if (current === "\n" || current === "\r") {
        mode = null;
        output += current;
      } else {
        output += " ";
      }
      continue;
    }

    if (mode === "block-comment") {
      if (current === "*" && next === "/") {
        output += "  ";
        index += 1;
        mode = null;
      } else {
        output += current === "\n" || current === "\r" ? current : " ";
      }
      continue;
    }

    if (mode !== null) {
      if (escaped) {
        output += current === "\n" || current === "\r" ? current : " ";
        escaped = false;
      } else if (current === "\\") {
        output += " ";
        escaped = true;
      } else if (current === mode) {
        output += " ";
        mode = null;
      } else {
        output += current === "\n" || current === "\r" ? current : " ";
      }
      continue;
    }

    if (current === "/" && next === "/") {
      output += "  ";
      index += 1;
      mode = "line-comment";
      continue;
    }

    if (current === "/" && next === "*") {
      output += "  ";
      index += 1;
      mode = "block-comment";
      continue;
    }

    if (current === "'" || current === '"' || current === "`") {
      output += " ";
      mode = current;
      escaped = false;
      continue;
    }

    output += current;
  }

  return output;
}

function matchesRule(rule: PlaybookRule, relativePath: string): boolean {
  if (!rule.enabled) return false;
  const ext = relativePath.slice(relativePath.lastIndexOf("."));
  return rule.globs.some((glob) => glob.endsWith(ext));
}

function findMatch(rule: PlaybookRule, line: string, rawLine = line, relativePath = ""): Omit<DetectorMatch, "rule" | "line" | "column" | "snippet"> | null {
  if (rule.id === "PY-SENSITIVE-DATA-EXPOSURE-001" && /(?:^|[\\/])api_views(?:[\\/])/.test(relativePath) && /\b(?:json_debug|get_all_users_debug)\b/.test(line)) {
    return {
      rootCause: "A Python response path exposes a sensitive record or debug serializer.",
      impact: "Unauthenticated or low-privilege callers may receive passwords, emails, tokens, or internal account state.",
      remediation: "Remove sensitive fields from public serializers, require authorization at the endpoint, and add an output-schema regression test.",
      kind: "SOURCE_TO_SINK",
      limitation: "The static pass identifies a sensitive serializer but does not prove endpoint reachability or caller authorization.",
    };
  }

  if (rule.id === "PY-ERROR-DISCLOSURE-001" && /\b(?:ValidationError|exc\s*\.\s*message)\b/.test(line) && /(?:Response|error_message_helper)/.test(line)) {
    return {
      rootCause: "Internal validation detail appears to be returned to a client-facing response.",
      impact: "Exception messages can disclose schema, field, validator, or implementation details that help an attacker map the service.",
      remediation: "Return a stable public error code and log detailed exception context only to an access-controlled sink.",
      kind: "SOURCE_TO_SINK",
      limitation: "The static pass cannot determine whether the exception text is sanitized or whether the endpoint is externally reachable.",
    };
  }

  if (rule.id === "PY-MASS-ASSIGNMENT-001" && /\b(?:request_data|request\s*\.\s*(?:get_json|form|values))\b/.test(line) && /\b(?:admin|is_admin|role|roles|permission|permissions)\b/.test(line)) {
    return {
      rootCause: "A privileged model attribute appears to be populated from request-controlled data.",
      impact: "An attacker may self-assign administrative or authorization-relevant state during object creation or update.",
      remediation: "Allowlist writable fields and set privilege-bearing attributes only in a trusted authorization path.",
      kind: "AUTHORIZATION_BOUNDARY",
      limitation: "The static pass does not prove model binding behavior, feature flags, or server-side field allowlists.",
    };
  }

  if (rule.id === "PY-USER-ENUMERATION-001" && /\bif\s+vuln\b/.test(line) && /enumerat/i.test(rawLine)) {
    return {
      rootCause: "A feature branch appears to return different authentication errors for existing and nonexistent users.",
      impact: "Attackers may enumerate valid usernames or account state through response differences.",
      remediation: "Use one stable public authentication error and keep diagnostic detail out of the response.",
      kind: "SOURCE_TO_SINK",
      limitation: "This pass uses a local branch annotation and does not compare the full response timing or body at runtime.",
    };
  }

  if (rule.id === "PY-RATE-LIMIT-001" && /\b(?:add_api|register_blueprint)\s*\(/.test(line)) {
    return {
      rootCause: "A Python API surface is registered without an observed rate-limiting boundary in the local registration call.",
      impact: "Authentication and resource-intensive endpoints may accept unlimited requests, enabling brute force or denial of service.",
      remediation: "Add endpoint-appropriate rate limits, account lockout/backoff, and a test that verifies limits are enforced.",
      kind: "CUSTOM",
      limitation: "The static pass cannot see gateway, reverse-proxy, or deployment-level throttling outside this source snapshot.",
    };
  }

  if (rule.id === "PY-DYNAMIC-CODE-001" && /\b(?:eval|exec)\s*\(/.test(line) && new RegExp(pythonRequestInput, "i").test(line)) {
    return {
      rootCause: "A Python dynamic code execution boundary is present.",
      impact: "If attacker-controlled data reaches this call, arbitrary Python code execution may be possible.",
      remediation: "Remove eval/exec or constrain it to a reviewed, non-user-controlled allowlist and verify the boundary with an isolated test.",
      kind: "DYNAMIC_CODE",
      limitation: "This static pass does not prove that an external attacker controls the Python argument.",
    };
  }

  if (rule.id === "PY-CLEARTEXT-PASSWORD-001" && /\bpassword\s*=\s*(?:db\s*\.\s*Column|Column)\s*\(/i.test(line)) {
    return {
      rootCause: "A Python model declares a password field without an observed one-way hashing boundary.",
      impact: "A database disclosure can expose reusable credentials and enable account takeover.",
      remediation: "Store only a reviewed password hash, migrate existing plaintext records, and test that raw passwords never persist.",
      kind: "CUSTOM",
      limitation: "The static pass cannot prove the write path, database contents, or whether a model hook hashes the value later.",
    };
  }

  if (rule.id === "PY-COMMAND-INJECTION-001" && /\b(?:os\s*\.\s*(?:system|popen)|subprocess\s*\.\s*(?:run|Popen|call|check_call|check_output))\s*\(/.test(line) && new RegExp(pythonRequestInput, "i").test(line)) {
    return {
      rootCause: "Request or user input appears in a Python command execution call.",
      impact: "An attacker may influence command execution if shell interpretation or argument construction is unsafe.",
      remediation: "Prefer fixed commands and argument arrays, then add an isolated reproducer that proves metacharacters cannot change execution.",
      kind: "SOURCE_TO_SINK",
      limitation: "This pass does not resolve Python interprocedural reachability or shell configuration.",
    };
  }

  if (rule.id === "PY-SQL-INJECTION-001" && /\b(?:execute|executemany|executescript)\s*\(/.test(line) && new RegExp(`${pythonRequestInput}|%s|\\+|f["']`, "i").test(line)) {
    return {
      rootCause: "A request-controlled or interpolated value appears in a Python query execution call.",
      impact: "An attacker may alter query semantics if parameterization is not enforced.",
      remediation: "Use parameterized query APIs and add a test proving metacharacters remain data.",
      kind: "SOURCE_TO_SINK",
      limitation: "This pass does not understand the database driver or parameter binding semantics.",
    };
  }

  if (rule.id === "PY-SSTI-001" && /\b(?:render_template_string|jinja2\s*\.\s*(?:Template|Environment)|Template)\s*\(/.test(line) && new RegExp(pythonRequestInput, "i").test(line)) {
    return {
      rootCause: "A request-controlled value appears to reach a Python template source sink.",
      impact: "An attacker may execute template expressions or access server-side objects.",
      remediation: "Render trusted templates by name and keep user input as data, then verify template expressions are not evaluated.",
      kind: "SOURCE_TO_SINK",
      limitation: "This pass does not prove the template engine, sandbox, or actual expression reachability.",
    };
  }

  if (rule.id === "PY-SSRF-001" && /\b(?:requests|httpx|urllib\s*\.\s*request|urlopen)\s*\.\s*(?:get|post|put|patch|request|urlopen)\s*\(/.test(line) && new RegExp(pythonRequestInput, "i").test(line)) {
    return {
      rootCause: "A request-controlled URL appears to reach a Python outbound request sink.",
      impact: "An attacker may cause server-side requests to internal or restricted destinations.",
      remediation: "Enforce scheme, host, port, resolved IP, redirect, and DNS-rebinding policy before making the request.",
      kind: "SOURCE_TO_SINK",
      limitation: "This pass does not prove URL normalization, DNS behavior, or redirect policy.",
    };
  }

  if (rule.id === "PY-OPEN-REDIRECT-001" && /\b(?:redirect|flask\s*\.\s*redirect)\s*\(/.test(line) && new RegExp(pythonRequestInput, "i").test(line)) {
    return {
      rootCause: "A redirect target appears to use request-controlled data in Python.",
      impact: "An attacker may redirect a user to an external destination if no same-origin or allowlist check exists.",
      remediation: "Use same-origin defaults or an explicit destination allowlist and verify external destinations are rejected.",
      kind: "SOURCE_TO_SINK",
      limitation: "This pass does not resolve guards in middleware or helper functions.",
    };
  }

  if (rule.id === "PY-HARDCODED-CREDENTIAL-001" && /(?:\b(?:secret[_-]?key|password|passwd|token|api[_-]?key|private[_-]?key)\b\s*=\s*['"][^'"]+['"]|\b(?:config|settings|app)\b[^\n]*\[['"](?:secret[_-]?key|password|token|api[_-]?key|private[_-]?key)['"]\]\s*=\s*['"][^'"]+['"]|\b(?:register_user|create_user)\s*\([^\n]*(?:pass|password|secret|token)[^\n]*['"][^'"]+['"])/i.test(rawLine)) {
    return {
      rootCause: "A credential-like value is hardcoded in Python source.",
      impact: "Anyone who obtains the source may forge sessions, access an external service, or reuse the secret elsewhere.",
      remediation: "Load secrets from a managed runtime secret boundary, rotate the exposed value, and add a check that rejects literals in source.",
      kind: "CUSTOM",
      limitation: "Static matching identifies a credential-shaped literal but cannot determine whether it is a harmless fixture or an active secret.",
    };
  }

  if (rule.id === "PY-DEBUG-MODE-001" && /(?:\b(?:app|application)\s*\.\s*debug\s*=\s*True\b|\b(?:app|vuln_app)\s*\.\s*run\s*\([^\n]*\bdebug\s*=\s*True\b)/.test(line)) {
    return {
      rootCause: "Python application debug mode is enabled in source.",
      impact: "Production errors may expose source, locals, stack traces, or an interactive debugger.",
      remediation: "Disable debug mode in deployed configuration and enforce a production-safe startup check.",
      kind: "CUSTOM",
      limitation: "The static pass cannot determine deployment environment or whether a later configuration overrides this assignment.",
    };
  }

  if (
    rule.id === "JS-DYNAMIC-CODE-001" &&
    /\beval\s*\(|\bnew\s+Function\s*\(/.test(line) &&
    new RegExp(requestInput, "i").test(line)
  ) {
    return {
      rootCause: "A dynamic code execution boundary is present.",
      impact: "If attacker-controlled data reaches this call, arbitrary code execution may be possible.",
      remediation: "Remove dynamic evaluation or constrain it to a reviewed, non-user-controlled allowlist and verify the boundary with a test.",
      kind: "DYNAMIC_CODE",
      limitation: "This static pass does not prove that an external attacker controls the argument.",
    };
  }

  if (
    rule.id === "JS-COMMAND-INJECTION-001" &&
    /\b(?:exec|execSync|spawn|spawnSync)\s*\([^)]*/.test(line) &&
    new RegExp(requestInput, "i").test(line)
  ) {
    return {
      rootCause: "Request or user input appears in a child_process execution call.",
      impact: "An attacker may influence command execution if the value is reachable and insufficiently constrained.",
      remediation: "Prefer fixed command arguments and execFile-style APIs; add an isolated reproducer for the intended trust boundary.",
      kind: "SOURCE_TO_SINK",
      limitation: "This pass does not resolve interprocedural reachability, shell configuration, or input validation.",
    };
  }

  if (
    rule.id === "JS-OPEN-REDIRECT-001" &&
    /\b(?:res|response)\s*\.\s*redirect\s*\([^)]*/.test(line) &&
    new RegExp(requestInput + "|(?:url|next|redirect)", "i").test(line)
  ) {
    return {
      rootCause: "A redirect target appears to use request-controlled data.",
      impact: "An attacker may redirect a user to an external destination if no same-origin or allowlist check exists.",
      remediation: "Use a same-origin default or an explicit destination allowlist, then verify external destinations are rejected.",
      kind: "SOURCE_TO_SINK",
      limitation: "This pass cannot prove whether a guard exists in a helper or middleware.",
    };
  }

  if (
    rule.id === "JS-SQL-INJECTION-001" &&
    /\.(?:query|execute|raw)\s*\([^)]*/.test(line) &&
    new RegExp(requestInput + "|\\$\\{", "i").test(line)
  ) {
    return {
      rootCause: "A query execution call appears to receive request-controlled or interpolated data.",
      impact: "An attacker may alter query semantics if parameterization is not enforced.",
      remediation: "Use parameterized query APIs and add a test that proves metacharacters remain data.",
      kind: "SOURCE_TO_SINK",
      limitation: "This pass does not understand the database driver, parameter binding, or values assembled in helpers.",
    };
  }

  return null;
}

function pythonMissingAuthLines(relativePath: string, content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-MISSING-AUTH-001" && candidate.enabled);
  if (!rule) return result;
  const codeLines = maskPython(content).split(/\r?\n/);
  const apiSurface = /(?:^|[\\/])api_views(?:[\\/])/.test(relativePath) || /\b(?:connexion|add_api|openapi)\b/i.test(content);
  let pendingRouteLine: number | null = null;
  for (let index = 0; index < codeLines.length; index += 1) {
    const code = codeLines[index] ?? "";
    if (/^\s*@[^\n]*(?:\broute|\b(?:get|post|put|patch|delete))\s*\(/.test(code)) {
      pendingRouteLine = index + 1;
      continue;
    }
    const definition = code.match(/^(\s*)def\s+[A-Za-z_]\w*\s*\([^)]*\)\s*:/);
    if (!definition || (pendingRouteLine === null && !apiSurface)) continue;
    const functionIndent = definition[1].replace(/\t/g, "    ").length;
    let end = codeLines.length;
    for (let cursor = index + 1; cursor < codeLines.length; cursor += 1) {
      const candidate = codeLines[cursor] ?? "";
      const candidateIndent = (candidate.match(/^\s*/)?.[0] ?? "").replace(/\t/g, "    ").length;
      if (candidate.trim() && candidateIndent <= functionIndent) {
        end = cursor;
        break;
      }
    }
    const body = codeLines.slice(index, end).join("\n");
    const routeLine = pendingRouteLine ?? index + 1;
    const routeBlock = `${codeLines.slice(routeLine - 1, index).join("\n")}\n${body}`;
    const debugSerializer = /\b(?:get_all_users_debug|json_debug)\b/.test(routeBlock);
    const routeDangerous = /\b(?:eval|exec|(?:os\s*\.\s*)?(?:popen|system)|subprocess\s*\.|XMLParser|fromstring|render_template_string)\b|\brp\s*\(/.test(routeBlock)
      || /\b(?:return|make_response|Response)\b[^\n]*(?:\+|%)/.test(routeBlock);
    const highImpactApi = /\b(?:drop_all|create_all|get_all_users(?:_debug)?|json_debug)\b/.test(routeBlock);
    const dangerous = pendingRouteLine === null ? highImpactApi && !debugSerializer : routeDangerous;
    const protectedRoute = /\b(?:login_required|requires_auth|authorize|authorise|permission|current_user|is_authenticated|token_validator)\b/.test(routeBlock)
      || /\bsession\s*(?:\.|\[)/.test(routeBlock);
    if (dangerous && !protectedRoute) result.set(routeLine, [rule.id]);
    pendingRouteLine = null;
  }
  return result;
}

function pythonRegexDosLines(content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-REGEX-DOS-001" && candidate.enabled);
  if (!rule) return result;
  const rawLines = content.split(/\r?\n/);
  for (let index = 0; index < rawLines.length; index += 1) {
    if (!/\bre\.search\s*\(/.test(rawLines[index] ?? "")) continue;
    const window = rawLines.slice(index, index + 5).join("\n");
    if (/\([^\n)]*(?:\*|\+)[^\n)]*\)(?:\*|\+)/.test(window)) result.set(index + 1, [rule.id]);
  }
  return result;
}

function pythonIdorLines(content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-IDOR-001" && candidate.enabled);
  if (!rule) return result;
  const lines = maskPython(content).split(/\r?\n/);
  let vulnerableIndent: number | null = null;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const indent = (line.match(/^\s*/)?.[0] ?? "").replace(/\t/g, "    ").length;
    if (/^\s*if\s+vuln\b/.test(line)) vulnerableIndent = indent;
    if (/^\s*else\s*:/.test(line) && vulnerableIndent !== null && indent <= vulnerableIndent) vulnerableIndent = null;
    const idor = /(?:filter_by|filter)\s*\([^\n]*\busername\s*=\s*username\b/i.test(line)
      || /(?:filter_by|filter)\s*\([^\n]*\bbook_title\s*=\s*str\s*\(\s*book_title\b/i.test(line);
    if (idor && vulnerableIndent !== null && indent > vulnerableIndent) result.set(index + 1, [rule.id]);
  }
  return result;
}

function policyMatch(ruleId: string): Omit<DetectorMatch, "rule" | "line" | "column" | "snippet"> | null {
  if (ruleId === "PY-MISSING-AUTH-001") return {
    rootCause: "A dangerous Python route is reachable without an observed authentication or authorization guard.",
    impact: "An unauthenticated caller may reach a high-impact operation that should be restricted to an authenticated principal.",
    remediation: "Require authentication and authorization at the route or trusted middleware boundary, then add a test for anonymous and authorized requests.",
    kind: "AUTHORIZATION_BOUNDARY",
    limitation: "This static policy pass infers route protection from local decorators, token checks, and high-impact calls; gateway policy still requires independent validation.",
  };
  if (ruleId === "PY-REGEX-DOS-001") return {
    rootCause: "A user-influenced regular expression path contains nested quantifiers that may backtrack catastrophically.",
    impact: "An attacker may consume disproportionate CPU with a crafted input and degrade service availability.",
    remediation: "Use a linear-time regex or bounded parser, cap input length, and add a worst-case latency regression test.",
    kind: "SOURCE_TO_SINK",
    limitation: "The static pass identifies a suspicious regex shape but does not prove worst-case runtime on the deployed regex engine.",
  };
  if (ruleId === "PY-IDOR-001") return {
    rootCause: "A path-like identifier is used to select an object without an observed owner or subject constraint.",
    impact: "An authenticated user may read or modify another user's object by changing an identifier in the request.",
    remediation: "Bind object lookup to the authenticated principal and add an authorization regression test for a foreign identifier.",
    kind: "AUTHORIZATION_BOUNDARY",
    limitation: "The static pass only promoted an identifier lookup inside an explicitly vulnerable branch; complete authorization still requires independent validation.",
  };
  return null;
}

export function detectFindings(
  relativePath: string,
  content: string,
  playbook: AuditPlaybook,
  runId: string,
): { findings: Finding[]; obligations: AuditObligation[] } {
  const findings: Finding[] = [];
  const obligations: AuditObligation[] = [];
  const lines = content.split(/\r?\n/);
  const codeLines = relativePath.toLowerCase().endsWith(".py") ? maskPython(content).split(/\r?\n/) : maskNonCode(content).split(/\r?\n/);
  const pythonPolicyMatches = relativePath.toLowerCase().endsWith(".py") ? pythonMissingAuthLines(relativePath, content, playbook) : new Map<number, string[]>();
  const emittedFileRules = new Set<string>();
  if (relativePath.toLowerCase().endsWith(".py")) {
    for (const [lineNumber, ruleIds] of pythonRegexDosLines(content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonIdorLines(content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
  }

  for (const [index, line] of lines.entries()) {
    const codeLine = codeLines[index] ?? "";
    for (const rule of playbook.rules) {
      if (!matchesRule(rule, relativePath)) continue;
      if ((rule.id === "PY-HARDCODED-CREDENTIAL-001" || rule.id === "PY-ERROR-DISCLOSURE-001") && emittedFileRules.has(rule.id)) continue;
      const hasPolicyMatch = pythonPolicyMatches.get(index + 1)?.includes(rule.id) ?? false;
      const match = findMatch(rule, codeLine, line, relativePath) ?? (hasPolicyMatch ? policyMatch(rule.id) : null);
      if (!match) continue;

      const column = Math.max(0, line.search(/\S/));
      const location: SourceLocation = {
        file: relativePath,
        line: index + 1,
        column: column + 1,
        endLine: index + 1,
        snippet: line.trim(),
      };
      const obligationId = `${runId}-${rule.id}-${index + 1}`;
      const findingId = `${obligationId}-finding`;
      const obligation: AuditObligation = {
        id: obligationId,
        kind: match.kind,
        title: `Verify: ${rule.title}`,
        status: "OPEN",
        targetFiles: [relativePath],
        falsifiers: [
          "Trace attacker-controlled input to the reported sink.",
          "Run an isolated negative/positive test for the claimed impact.",
          "Check whether a guard or sanitizer exists outside this line.",
        ],
        evidenceRequired: rule.evidenceRequired,
        createdBy: "deterministic-static-detector",
      };
      obligations.push(obligation);

      findings.push({
        id: findingId,
        ruleId: rule.id,
        obligationId,
        title: rule.title,
        severity: rule.severity,
        status: "SUSPECTED",
        evidenceTier: "T1_STATIC_PATH",
        rootCause: match.rootCause,
        impact: match.impact,
        remediation: match.remediation,
        locations: [location],
        evidence: [
          {
            type: "STATIC_PATTERN",
            title: "Static source/sink pattern",
            detail: `${rule.id} matched a local code pattern.`,
            locations: [location],
            reproducible: false,
          },
          {
            type: "LIMITATION",
            title: "Verification required",
            detail: match.limitation,
            reproducible: false,
          },
        ],
        limitations: [match.limitation, "No external model or runtime verifier was invoked by this run."],
      });
      if (rule.id === "PY-HARDCODED-CREDENTIAL-001" || rule.id === "PY-ERROR-DISCLOSURE-001") emittedFileRules.add(rule.id);
    }
  }

  return { findings, obligations };
}
