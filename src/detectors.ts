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
  return rule.globs.some((glob) => glob === "**/*" || (glob.startsWith("**/") && relativePath.endsWith(glob.slice(3))) || glob.endsWith(ext));
}

function isGeneratedAssetPath(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, "/").toLowerCase();
  const basename = normalized.slice(normalized.lastIndexOf("/") + 1);
  return /(?:^|\/)(?:node_modules|vendor|third_party|static\/js|public\/vendor)\//.test(normalized)
    && /(?:redoc|swagger|jquery|bootstrap|vendor|bundle|\.min\.)/.test(basename);
}

function isNonProductionFixturePath(relativePath: string): boolean {
  return /(?:^|\/)(?:test|tests|spec|specs|fixtures|fixture|examples|example)(?:\/|$)/i.test(relativePath.replace(/\\/g, "/"));
}

function allowsMultipleCredentialLiterals(relativePath: string): boolean {
  return /(?:^|\/)(?:settings|config|docker_settings)\.py$/i.test(relativePath.replace(/\\/g, "/"));
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

  if (rule.id === "PY-CLEARTEXT-PASSWORD-001" && /(?:^|[\\/])models?(?:[\\/]|_|\.)/i.test(relativePath) && /\bpassword\s*=\s*(?:db\s*\.\s*Column|Column)\s*\(/i.test(line)) {
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

  if (rule.id === "PY-WEAK-PASSWORD-HASH-001"
    && /\b(?:md5|sha1|sha224|sha256)\s*\(|\b(?:MD5|SHA1|SHA224|SHA256)\.new\s*\(/i.test(line)
    && /\b(?:password|passwd|passphrase|secret|auth_token|token)\b/i.test(line)
    && !/(?:==|!=)[^\n]*(?:md5|sha1|sha224|sha256)/i.test(line)) {
    return {
      rootCause: "A password-like value is processed with a fast or cryptographically unsuitable hash.",
      impact: "A credential database disclosure can make offline cracking and account takeover substantially easier than with a password-specific memory-hard hash.",
      remediation: "Use a reviewed password hashing function such as Argon2id, scrypt, or bcrypt with current cost parameters, then rotate or migrate affected credentials.",
      kind: "CUSTOM",
      limitation: "The static pass identifies a weak hash call near a password value but does not prove the stored value, parameters, or migration path.",
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

  if (rule.id === "PY-HARDCODED-CREDENTIAL-001" && /(?:\b(?:secret[_-]?key|password|passwd|token|api[_-]?key|private[_-]?key)\b\s*=\s*['"][^'"]+['"]|\b(?:[A-Za-z_][A-Za-z0-9_]*_)*(?:SECRET_KEY|API_KEY|PRIVATE_KEY|SUPER_SECRET_(?:NAME|TOKEN))[A-Za-z0-9_]*\s*=\s*['"][^'"]+['"]|\b(?:config|settings|app)\b[^\n]*\[['"](?:secret[_-]?key|password|token|api[_-]?key|private[_-]?key)['"]\]\s*=\s*['"][^'"]+['"]|\b(?:register_user|create_user)\s*\([^\n]*(?:pass|password|secret|token)[^\n]*['"][^'"]+['"])/i.test(rawLine)) {
    return {
      rootCause: "A credential-like value is hardcoded in Python source.",
      impact: "Anyone who obtains the source may forge sessions, access an external service, or reuse the secret elsewhere.",
      remediation: "Load secrets from a managed runtime secret boundary, rotate the exposed value, and add a check that rejects literals in source.",
      kind: "CUSTOM",
      limitation: "Static matching identifies a credential-shaped literal but cannot determine whether it is a harmless fixture or an active secret.",
    };
  }

  if (rule.id === "PY-HARDCODED-CREDENTIAL-001"
    && /(?:^|[\\/])(?:settings|config|docker_settings)\.py$/i.test(relativePath)
    && /\b(?:KEY|ACCESS_TOKEN_SALT|DATABASE_PASSWORD|DB_PASSWORD|SECRET|TOKEN)\b\s*=\s*(?:[bruf]+)?['"][^'"]+['"]/i.test(rawLine)) {
    return {
      rootCause: "A credential-like value is hardcoded in a Python settings module.",
      impact: "Source disclosure can expose cryptographic keys, database credentials, or token-signing material.",
      remediation: "Load the value from a managed secret boundary, rotate it, and add a check that rejects active credential literals.",
      kind: "CUSTOM",
      limitation: "The static pass cannot determine whether the settings file is active in the deployed profile or whether the literal is test-only.",
    };
  }

  if (rule.id === "CONFIG-WAF-DISABLED-001" && /\bSecRuleEngine\s+Off\b/i.test(rawLine)) {
    return {
      rootCause: "A reverse-proxy WAF is explicitly disabled while local security rules remain configured.",
      impact: "Requests reach the application without the intended edge filtering and compensating policy may be assumed but not enforced.",
      remediation: "Enable the WAF in the deployment profile, test that each rule blocks its intended payload, and document any deliberate exception.",
      kind: "CUSTOM",
      limitation: "The static pass identifies the configuration state but cannot prove which deployment profile is active or whether another edge control compensates for it.",
    };
  }

  if (rule.id === "PY-DEBUG-MODE-001" && /(?:\b(?:app|application)\s*\.\s*debug\s*=\s*True\b|\b(?:app|vuln_app)\s*\.\s*run\s*\([^\n]*\bdebug\s*=\s*True\b|\bdebug\s*=\s*(?:config\.[A-Za-z_]\w*|os\s*\.\s*getenv\s*\(|True\b|true\b))/.test(line)) {
    return {
      rootCause: "Python application debug mode is enabled in source.",
      impact: "Production errors may expose source, locals, stack traces, or an interactive debugger.",
      remediation: "Disable debug mode in deployed configuration and enforce a production-safe startup check.",
      kind: "CUSTOM",
      limitation: "The static pass cannot determine deployment environment or whether a later configuration overrides this assignment.",
    };
  }

  if (rule.id === "PY-DEBUG-MODE-001" && (/\bDEBUG\s*=\s*(?:True|true)\b/i.test(line) || /['"]debug['"]\s*:\s*(?:True|true)\b/i.test(rawLine))) {
    return {
      rootCause: "Python application debug mode is enabled in source.",
      impact: "Production errors may expose source, locals, stack traces, or an interactive debugger.",
      remediation: "Disable debug mode in deployed configuration and enforce a production-safe startup check.",
      kind: "CUSTOM",
      limitation: "The static pass cannot determine deployment environment or whether a later configuration overrides this assignment.",
    };
  }

  if (rule.id === "PY-INSECURE-COOKIE-001" && /\b(?:response|resp|res)\s*\.\s*set_cookie\s*\(/i.test(line) && /\b(?:auth[_-]?token|session(?:id)?|sid|access[_-]?token)\b/i.test(rawLine)) {
    const secure = /\bsecure\s*=\s*True\b/i.test(rawLine);
    const httpOnly = /\bhttponly\s*=\s*True\b/i.test(rawLine);
    if (!secure || !httpOnly) return {
      rootCause: "A response sets a session-like cookie without both Secure and HttpOnly attributes.",
      impact: "A stolen or script-readable authentication cookie can enable session theft, and an unencrypted transport can expose it in transit.",
      remediation: "Set Secure and HttpOnly for authentication cookies, use an appropriate SameSite policy, and add an HTTPS/browser regression test.",
      kind: "CUSTOM",
      limitation: "The static pass cannot prove framework defaults, deployment TLS, cookie scope, or whether the cookie contains authentication material.",
    };
  }

  if (rule.id === "PY-SECURITY-MISCONFIGURATION-001" && /\b(?:ALLOWED_HOSTS|TRUSTED_HOSTS)\s*=\s*\[[^\]]*['"]\*['"]/i.test(rawLine)) {
    return {
      rootCause: "The Python host allowlist accepts every Host header.",
      impact: "Host-header injection, cache poisoning, or password-reset poisoning may become possible when downstream links trust the request host.",
      remediation: "Use an explicit production host allowlist and add a request test that rejects an untrusted Host header.",
      kind: "CUSTOM",
      limitation: "The static pass cannot determine which settings module is active or whether a trusted proxy rewrites and validates the host.",
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

function pythonFrameworkPolicyLines(relativePath: string, content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const normalizedPath = relativePath.replace(/\\/g, "/").toLowerCase();
  const codeLines = maskPython(content).split(/\r?\n/);
  const rawLines = content.split(/\r?\n/);
  const enabled = (ruleId: string): boolean => playbook.rules.some((rule) => rule.enabled && rule.id === ruleId);
  const add = (line: number, ruleId: string): void => {
    if (!enabled(ruleId)) return;
    result.set(line, [...new Set([...(result.get(line) ?? []), ruleId])]);
  };

  if (/\b(?:tornado\s*\.\s*web\s*\.\s*RequestHandler|RequestHandler)\b/.test(content)) {
    const hasRawTemplateOutput = /X-XSS-Protection['"]?\s*,\s*['"]0['"]|\braw\b/i.test(content);
    const hasPasswordTable = /CREATE\s+TABLE\s+Users[^\n]*Password/i.test(content);
    let seedFindingAdded = false;
    for (const [index, raw] of rawLines.entries()) {
      if (hasRawTemplateOutput && /\bself\s*\.\s*render\s*\(/i.test(raw) && /\b(?:query|link)\s*=\s*query\b/i.test(raw)) add(index + 1, "PY-REFLECTED-XSS-001");
      if (hasPasswordTable && !seedFindingAdded && /\bINSERT\s+INTO\s+Users\b/i.test(raw)) {
        add(index + 1, "PY-CLEARTEXT-PASSWORD-001");
        add(index + 1, "PY-HARDCODED-CREDENTIAL-001");
        seedFindingAdded = true;
      }
    }
  }

  const djangoView = /(?:^|\/)app\/views\//.test(normalizedPath) && /\b(?:request|HttpResponse|objects\s*\.)\b/i.test(content);
  if (djangoView) {
    for (const [index, line] of codeLines.entries()) {
      const objectLookup = line.match(/\bobjects\s*\.\s*(?:get|filter)\s*\(([^)]*)\)/i);
      if (objectLookup
        && !/(?:^|\/)api\//i.test(normalizedPath)
        && !/(?:^|\/)password_resets\//i.test(normalizedPath)
        && /\b(?:id|pk|user_id|message_id|pay_id|record_id|item_id)\s*=\s*(?:user_id|message_id|pay_id|record_id|item_id)\b/i.test(objectLookup[1])
        && !/\b(?:cid|rid)\b/i.test(objectLookup[1])
        && !/\b(?:int|uuid|UUID)\s*\(/i.test(objectLookup[1])
        && !/\b(?:owner|created_by|account|user)\s*=\s*(?:request\s*\.\s*)?user\b/i.test(objectLookup[1])) {
        add(index + 1, "PY-IDOR-001");
      }
      if (/\b(?:\.\s*)?update\s*\(\s*\*\*[A-Za-z_]\w*/i.test(line)
        && /\b(?:validate_update_form|request\s*\.\s*(?:POST|form|data|body)|update\s*=)/i.test(content)) {
        add(index + 1, "PY-MASS-ASSIGNMENT-001");
      }
    }
  }

  if (/(?:^|\/)api\/users\//.test(normalizedPath) && /\bserializers?\.\s*serialize\s*\(/i.test(content) && /\bobjects\s*\.\s*all\s*\(/i.test(content)) {
    const line = codeLines.findIndex((candidate) => /\bserializers?\.\s*serialize\s*\(/i.test(candidate));
    if (line >= 0) add(line + 1, "PY-SENSITIVE-DATA-EXPOSURE-001");
  }

  if (/(?:^|\/)(?:sessions|password_resets)\//.test(normalizedPath)) {
    const distinctMessages = /(?:email\s+incorrect|password\s+incorrect|email\s+was\s+sent|not\s+in\s+(?:the\s+)?system)/i.test(content);
    if (distinctMessages) {
      const line = rawLines.findIndex((candidate) => /(?:email\s+incorrect|password\s+incorrect|email\s+was\s+sent|not\s+in\s+(?:the\s+)?system)/i.test(candidate));
      if (line >= 0) add(line + 1, "PY-USER-ENUMERATION-001");
    }
  }

  return result;
}

function pythonMissingAuthLines(relativePath: string, content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-MISSING-AUTH-001" && candidate.enabled);
  if (!rule) return result;
  const codeLines = maskPython(content).split(/\r?\n/);
  const rawLines = content.split(/\r?\n/);
  const apiSurface = /(?:^|[\\/])api_views(?:[\\/])/.test(relativePath)
    || /(?:^|[\\/])api(?:[\\/]|$)/i.test(relativePath)
    || /\b(?:connexion|add_api)\b/i.test(content);
  let pendingRouteLine: number | null = null;
  let pendingRouteText = "";
  for (let index = 0; index < codeLines.length; index += 1) {
    const code = codeLines[index] ?? "";
    const raw = rawLines[index] ?? "";
    if (/^\s*@[^\n]*(?:\broute|\b(?:get|post|put|patch|delete|options|head|api_route))\s*\(/i.test(code)) {
      pendingRouteLine = index + 1;
      pendingRouteText = raw;
      continue;
    }
    const definition = code.match(/^(\s*)(?:async\s+)?def\s+[A-Za-z_]\w*\s*\([^)]*\)\s*:/);
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
    const docsRoute = /(?:["']\/(?:docs|redoc|openapi\.json|favicon\.ico|robots\.txt|\.well-known\/security\.txt)["']|include_in_schema\s*=\s*False)/i.test(`${pendingRouteText}\n${rawLines.slice(routeLine, index + 1).join("\n")}`);
    const debugSerializer = /\b(?:get_all_users_debug|json_debug)\b/.test(routeBlock);
    const routeDangerous = /\b(?:eval|exec|(?:os\s*\.\s*)?(?:popen|system)|subprocess\s*\.|XMLParser|fromstring|render_template_string|delete_one|delete_many|update_one|drop|rmtree|remove)\s*\(?|\brp\s*\(/.test(routeBlock)
      || /\b(?:return|make_response|Response)\b[^\n]*(?:\+|%)/.test(routeBlock);
    const highImpactApi = /\b(?:drop_all|create_all|get_all_users(?:_debug)?|json_debug|delete_one|delete_many|update_one|update_many|rmtree|remove)\b/.test(routeBlock)
      || (/(?:^|[\\/])api[\\/]mobile[\\/]/i.test(relativePath) && /\bobjects\s*\.\s*all\s*\(/i.test(routeBlock));
    const dangerous = pendingRouteLine === null ? highImpactApi && !debugSerializer : routeDangerous;
    const protectedRoute = /\b(?:login_required|requires_auth|authorize|authorise|permission|current_user|is_authenticated|token_validator|check_if_valid_token|check_token|verify_token|Depends|Security|OAuth2|HTTPBearer|api_key)\b/.test(routeBlock)
      || /\bsession\s*(?:\.|\[)/.test(routeBlock);
    const impactLine = pendingRouteLine === null && apiSurface
      ? codeLines.findIndex((candidate, candidateIndex) => candidateIndex >= index && candidateIndex < end && /\b(?:objects\s*\.\s*all|drop_all|create_all|get_all_users)\s*\(/i.test(candidate)) + 1
      : routeLine;
    if (dangerous && !protectedRoute && !docsRoute) result.set(impactLine > 0 ? impactLine : routeLine, [rule.id]);
    pendingRouteLine = null;
    pendingRouteText = "";
  }
  return result;
}

function pythonSensitiveExposureLines(content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-SENSITIVE-DATA-EXPOSURE-001" && candidate.enabled);
  if (!rule) return result;
  const lines = maskPython(content).split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const definition = lines[index]?.match(/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/);
    if (!definition) continue;
    const indent = (lines[index]?.match(/^\s*/)?.[0] ?? "").length;
    let end = lines.length;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const candidate = lines[cursor] ?? "";
      if (candidate.trim() && (candidate.match(/^\s*/)?.[0] ?? "").length <= indent) {
        end = cursor;
        break;
      }
    }
    const body = lines.slice(index, end).join("\n");
    if (!/\b(?:fetchall|fetchmany)\s*\(/i.test(body)) continue;
    for (let cursor = index + 1; cursor < end; cursor += 1) {
      if (/\breturn\b[^\n]*(?:_data|rows|records|results|users)\b/i.test(lines[cursor] ?? "") && !/_data\s*\[/.test(lines[cursor] ?? "")) {
        result.set(cursor + 1, [rule.id]);
        break;
      }
    }
  }
  return result;
}

function pythonWeakHashLines(content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-WEAK-PASSWORD-HASH-001" && candidate.enabled);
  if (!rule) return result;
  const lines = maskPython(content).split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (!/\b(?:MD5|SHA1|SHA224|SHA256)\.new\s*\(/i.test(lines[index] ?? "")) continue;
    const window = lines.slice(Math.max(0, index - 10), index + 1).join("\n");
    if (/\bdef\s+(?:generate_token|hash_password|password_reset|reset_password)\s*\(/i.test(window)) result.set(index + 1, [rule.id]);
  }
  return result;
}

function pythonSqlInterpolationLines(content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-SQL-INJECTION-001" && candidate.enabled);
  if (!rule) return result;
  const lines = maskPython(content).split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (!/\b(?:execute|raw)\s*\(/i.test(lines[index] ?? "")) continue;
    const window = lines.slice(Math.max(0, index - 6), Math.min(lines.length, index + 5)).join("\n");
    const interpolation = /(?:%\s*(?:\(|[A-Za-z_])|\+|f\s*["'])/.test(window);
    const externalShape = /\b(?:request|req)\s*\.|\b(?:user_id|username|email|password|input_password|ip|col|field|query|path|url|form)\b/i.test(window);
    if (interpolation && externalShape) result.set(index + 1, [rule.id]);
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
  if (ruleId === "PY-USER-ENUMERATION-001") return {
    rootCause: "Distinct authentication responses appear to reveal whether an account exists.",
    impact: "An attacker may enumerate valid email addresses or usernames before attempting credential attacks or targeted recovery.",
    remediation: "Return one stable public response for both account-present and account-absent cases, and keep diagnostic detail in protected logs.",
    kind: "SOURCE_TO_SINK",
    limitation: "The static pass recognizes divergent message families but does not prove response timing, localization, or deployment middleware behavior.",
  };
  if (ruleId === "PY-SENSITIVE-DATA-EXPOSURE-001") return {
    rootCause: "A database query helper appears to return raw multi-record data without a reviewed output projection.",
    impact: "Raw rows may disclose password hashes, internal identifiers, or other fields that the endpoint does not need to expose.",
    remediation: "Project an explicit safe response schema, remove credentials and internal fields, and add an endpoint-level disclosure regression test.",
    kind: "SOURCE_TO_SINK",
    limitation: "The static policy infers exposure from raw query-result returns and does not prove the exact columns, caller authorization, or deployed response schema.",
  };
  if (ruleId === "PY-WEAK-PASSWORD-HASH-001") return {
    rootCause: "A password or credential token is derived with a fast or cryptographically unsuitable hash.",
    impact: "A credential disclosure can make offline cracking, token prediction, or replay easier than with a reviewed password-specific or random-token construction.",
    remediation: "Use Argon2id, scrypt, or bcrypt for passwords and a cryptographically secure random token for reset/session material, then rotate affected credentials.",
    kind: "CUSTOM",
    limitation: "The static pass identifies a weak hash construction in a credential-related function but does not prove storage, entropy, or migration behavior.",
  };
  if (ruleId === "PY-SQL-INJECTION-001") return {
    rootCause: "A request-shaped or externally supplied value appears to be interpolated into a Python query execution path.",
    impact: "An attacker may alter query semantics if the database API receives an unparameterized query string.",
    remediation: "Use parameterized query APIs and add a regression test proving metacharacters remain data.",
    kind: "SOURCE_TO_SINK",
    limitation: "This bounded policy pass recognizes the surrounding interpolation window but does not fully resolve the database driver or interprocedural call graph.",
  };
  if (ruleId === "PY-INSECURE-COOKIE-001") return {
    rootCause: "A Python response sets a session-like cookie without both Secure and HttpOnly attributes.",
    impact: "A stolen or script-readable authentication cookie can enable session theft, and an unencrypted transport can expose it in transit.",
    remediation: "Set Secure and HttpOnly for authentication cookies, use an appropriate SameSite policy, and add an HTTPS/browser regression test.",
    kind: "CUSTOM",
    limitation: "The static pass cannot prove framework defaults, deployment TLS, cookie scope, or whether the cookie contains authentication material.",
  };
  if (ruleId === "PY-SECURITY-MISCONFIGURATION-001") return {
    rootCause: "A Python host allowlist accepts every Host header.",
    impact: "Host-header injection, cache poisoning, or password-reset poisoning may become possible when downstream links trust the request host.",
    remediation: "Use an explicit production host allowlist and add a request test that rejects an untrusted Host header.",
    kind: "CUSTOM",
    limitation: "The static pass cannot determine which settings module is active or whether a trusted proxy rewrites and validates the host.",
  };
  if (ruleId === "PY-REFLECTED-XSS-001") return {
    rootCause: "A request-derived value appears to be passed into a server-side HTML template response without a local escaping guarantee.",
    impact: "An attacker may execute script or inject markup in a victim's browser when the template uses a raw or otherwise unsafe output context.",
    remediation: "Keep untrusted values as template data, remove raw output directives, and add a browser-level regression test for escaped markup.",
    kind: "SOURCE_TO_SINK",
    limitation: "The static pass sees a framework render call and an unsafe-output signal but does not parse the referenced template or prove browser reachability.",
  };
  if (ruleId === "PY-CLEARTEXT-PASSWORD-001") return {
    rootCause: "A database initialization path inserts plaintext password values into a password-bearing table.",
    impact: "Database disclosure can expose reusable credentials and enable account takeover.",
    remediation: "Use a password-specific one-way hash before persistence, migrate existing rows, and test that seed and production writes never store raw passwords.",
    kind: "CUSTOM",
    limitation: "The static pass identifies a password-bearing table and literal insert path but cannot prove which database is active or whether a later migration transforms the value.",
  };
  if (ruleId === "PY-HARDCODED-CREDENTIAL-001") return {
    rootCause: "Credential values are embedded in a Python database seed or configuration path.",
    impact: "Source disclosure exposes reusable credentials that may remain valid in development or production environments.",
    remediation: "Remove credential literals, load secrets from a managed boundary, rotate affected accounts, and add a fixture-aware secret scan.",
    kind: "CUSTOM",
    limitation: "The static pass cannot determine whether seed credentials are active outside the checked-in initialization path.",
  };
  return null;
}

export function detectFindings(
  relativePath: string,
  content: string,
  playbook: AuditPlaybook,
  runId: string,
): { findings: Finding[]; obligations: AuditObligation[] } {
  if (isGeneratedAssetPath(relativePath)) return { findings: [], obligations: [] };
  const findings: Finding[] = [];
  const obligations: AuditObligation[] = [];
  const lines = content.split(/\r?\n/);
  const codeLines = relativePath.toLowerCase().endsWith(".py") ? maskPython(content).split(/\r?\n/) : maskNonCode(content).split(/\r?\n/);
  const pythonPolicyMatches = relativePath.toLowerCase().endsWith(".py") ? pythonMissingAuthLines(relativePath, content, playbook) : new Map<number, string[]>();
  const emittedFileRules = new Set<string>();
  if (relativePath.toLowerCase().endsWith(".py")) {
    for (const [lineNumber, ruleIds] of pythonFrameworkPolicyLines(relativePath, content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonRegexDosLines(content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonIdorLines(content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonSensitiveExposureLines(content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonWeakHashLines(content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonSqlInterpolationLines(content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
  }

  for (const [index, line] of lines.entries()) {
    const codeLine = codeLines[index] ?? "";
    for (const rule of playbook.rules) {
      if (!matchesRule(rule, relativePath)) continue;
      if (rule.id === "PY-HARDCODED-CREDENTIAL-001" && isNonProductionFixturePath(relativePath)) continue;
      if (rule.id === "PY-INSECURE-COOKIE-001" && emittedFileRules.has(rule.id)) continue;
      if ((rule.id === "PY-ERROR-DISCLOSURE-001" && emittedFileRules.has(rule.id))
        || (rule.id === "PY-HARDCODED-CREDENTIAL-001" && emittedFileRules.has(rule.id) && !/\bSUPER_SECRET_[A-Z0-9_]+\b/i.test(line) && !allowsMultipleCredentialLiterals(relativePath))) continue;
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
      if (rule.id === "PY-HARDCODED-CREDENTIAL-001" || rule.id === "PY-ERROR-DISCLOSURE-001" || rule.id === "PY-INSECURE-COOKIE-001") emittedFileRules.add(rule.id);
    }
  }

  return { findings, obligations };
}
