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
  return /(?:^|\/)(?:node_modules|vendor|third_party|static|public)\//.test(normalized)
    && /(?:redoc|swagger|jquery|bootstrap|vendor|bundle|\.min\.)/.test(basename);
}

function isNonProductionFixturePath(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, "/");
  return /(?:^|\/)(?:test|tests|spec|specs|fixtures|fixture|examples|example)(?:\/|$)/i.test(normalized)
    || /(?:^|\/)(?:tests?|specs?|fixtures?|examples?)\.(?:py|js|ts|tsx|jsx)$/i.test(normalized)
    || /(?:^|\/)(?:test_|spec_|fixture_|example_)[^/]+$/i.test(normalized);
}

function allowsMultipleCredentialLiterals(relativePath: string): boolean {
  return /(?:^|\/)(?:settings|config|docker_settings)\.py$/i.test(relativePath.replace(/\\/g, "/"));
}

function isPlaceholderCredentialLine(rawLine: string): boolean {
  return /(?:dev[-_ ]?insecure|change[-_ ]?me|example|placeholder|fixture|dummy|test[-_ ]?(?:key|token|password)|do[-_ ]?not[-_ ]?use)/i.test(rawLine);
}

function hasHardcodedCredentialLiteral(rawLine: string): boolean {
  if (isPlaceholderCredentialLine(rawLine)) return false;
  const literal = "(?:[bruf]+)?['\"][^'\"]+['\"]";
  const exactAssignment = new RegExp(`\\b(?:secret[_-]?key|password|passwd|token|api[_-]?key|private[_-]?key|access[_-]?token|database[_-]?password|db[_-]?password)\\b\\s*=\\s*${literal}\\s*(?:;|#.*)?$`, "i");
  const namedAssignment = new RegExp(`\\b(?:SECRET_KEY|API_KEY|PRIVATE_KEY|ACCESS_TOKEN(?:_SALT)?|DATABASE_PASSWORD|DB_PASSWORD)\\b\\s*=\\s*${literal}\\s*(?:;|#.*)?$`, "i");
  const mappingAssignment = new RegExp(`\\b(?:config|settings|app)\\b[^\\n]*\\[['\"](?:secret[_-]?key|password|token|api[_-]?key|private[_-]?key)['\"]\\]\\s*=\\s*${literal}`, "i");
  const seededUser = /\b(?:register_user|create_user)\s*\([^\n]*(?:pass|password|secret|token)\s*=\s*['"][^'"]+['"]/i;
  return exactAssignment.test(rawLine.trim()) || namedAssignment.test(rawLine) || mappingAssignment.test(rawLine) || seededUser.test(rawLine);
}

function findMatch(rule: PlaybookRule, line: string, rawLine = line, relativePath = ""): Omit<DetectorMatch, "rule" | "line" | "column" | "snippet"> | null {
  if (rule.id === "TEMPLATE-UNSAFE-OUTPUT-001"
    && (/(?:\{\{|\{%).*(?:\|\s*(?:safe|raw)\b)/i.test(rawLine) || /\{%-?\s*autoescape\s+off\b/i.test(rawLine))) {
    if (/\bfield\s*\.\s*help_text\b/i.test(rawLine)) return null;
    return {
      rootCause: "A template explicitly disables the engine's default output escaping for a rendered value.",
      impact: "If the value is attacker-controlled or stored from an untrusted source, a browser may interpret injected markup or script in the victim's origin.",
      remediation: "Remove safe/raw output modes, keep untrusted content escaped, or require a reviewed sanitizer contract with a browser regression test.",
      kind: "SOURCE_TO_SINK",
      limitation: "The static pass does not resolve the value's provenance, sanitizer implementation, template context, or browser execution path.",
    };
  }

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

  if (rule.id === "PY-SQL-INJECTION-001"
    && /\b(?:execute|executemany|executescript)\s*\(/.test(line)
    && new RegExp(`${pythonRequestInput}|%s|\\+|f["']`, "i").test(firstCallArgumentText(callArgumentText(line, line.search(/\b(?:execute|executemany|executescript)\s*\(/)))) ) {
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
    const redirectIndex = line.search(/\b(?:redirect|flask\s*\.\s*redirect)\s*\(/i);
    const redirectArgument = redirectIndex >= 0 ? callArgumentText(line, redirectIndex) : line;
    if (/\b(?:url_for|reverse|redirect_to|build_absolute_uri)\s*\(/i.test(redirectArgument)) return null;
    return {
      rootCause: "A redirect target appears to use request-controlled data in Python.",
      impact: "An attacker may redirect a user to an external destination if no same-origin or allowlist check exists.",
      remediation: "Use same-origin defaults or an explicit destination allowlist and verify external destinations are rejected.",
      kind: "SOURCE_TO_SINK",
      limitation: "This pass does not resolve guards in middleware or helper functions.",
    };
  }

  if (rule.id === "PY-HARDCODED-CREDENTIAL-001" && hasHardcodedCredentialLiteral(rawLine)) {
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
    && !isPlaceholderCredentialLine(rawLine)
    && /\b(?:KEY|SECRET_KEY|ACCESS_TOKEN_SALT|DATABASE_PASSWORD|DB_PASSWORD|SECRET|TOKEN)\b\s*=\s*(?:[bruf]+)?['"][^'"]+['"]/i.test(rawLine)) {
    return {
      rootCause: "A credential-like value is hardcoded in a Python settings module.",
      impact: "Source disclosure can expose cryptographic keys, database credentials, or token-signing material.",
      remediation: "Load the value from a managed secret boundary, rotate it, and add a check that rejects active credential literals.",
      kind: "CUSTOM",
      limitation: "The static pass cannot determine whether the settings file is active in the deployed profile or whether the literal is test-only.",
    };
  }

  if (rule.id === "PY-HARDCODED-CREDENTIAL-001"
    && /(?:^|[\\/])(?:settings|config|docker_settings)\.py$/i.test(relativePath)
    && /\b(?:SECRET_KEY|JWT_SECRET|SESSION_SECRET|SIGNING_KEY)\b\s*=\s*[^\n]*(?:django-insecure|default[-_ ]?secret|insecure[-_ ]?secret|super[-_ ]?secret|dev[-_ ]?secret)/i.test(rawLine)) {
    return {
      rootCause: "A framework or signing secret falls back to a known insecure default in a Python configuration module.",
      impact: "Source disclosure or a predictable deployment default may let an attacker forge sessions, reset tokens, or other signed state.",
      remediation: "Require a high-entropy secret from a managed runtime boundary, reject insecure defaults at startup, and rotate any deployed value.",
      kind: "CUSTOM",
      limitation: "The static pass identifies a known insecure default but cannot determine which environment loads the configuration or whether startup validation overrides it.",
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

  if (rule.id === "PY-DEBUG-MODE-001" && /(?:\b(?:app|application)\s*\.\s*debug\s*=\s*True\b|\b(?:app|vuln_app)\s*\.\s*run\s*\([^\n]*\bdebug\s*=\s*True\b|\b(?:debug|debug_mode)\s*=\s*(?:config\.[A-Za-z_]\w*|os\s*\.\s*getenv\s*\(|True\b|true\b|[^\n]*\bdefault\s*=\s*True\b))/i.test(line)) {
    return {
      rootCause: "Python application debug mode is enabled in source.",
      impact: "Production errors may expose source, locals, stack traces, or an interactive debugger.",
      remediation: "Disable debug mode in deployed configuration and enforce a production-safe startup check.",
      kind: "CUSTOM",
      limitation: "The static pass cannot determine deployment environment or whether a later configuration overrides this assignment.",
    };
  }

  if (rule.id === "PY-DEBUG-MODE-001" && (/\bDEBUG\s*=\s*(?:True|true)\b/i.test(line) || /\bDEBUG\s*=\s*[^\n]*\b(?:default\s*=\s*)?True\b/i.test(rawLine) || /\bconfig\s*\[[^\]]*['"]DEBUG['"]\]\s*=\s*True\b/i.test(rawLine) || /['"]debug['"]\s*:\s*(?:True|true)\b/i.test(rawLine))) {
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

  if (rule.id === "JS-OPEN-REDIRECT-001") {
    const redirectIndex = line.search(/\b(?:res|response)\s*\.\s*redirect\s*\(/i);
    const redirectArgument = redirectIndex >= 0 ? callArgumentText(line, redirectIndex) : "";
    if (redirectIndex >= 0 && new RegExp(requestInput + "|(?:url|next|redirect)", "i").test(redirectArgument)) {
      return {
        rootCause: "A redirect target appears to use request-controlled data.",
        impact: "An attacker may redirect a user to an external destination if no same-origin or allowlist check exists.",
        remediation: "Use a same-origin default or an explicit destination allowlist, then verify external destinations are rejected.",
        kind: "SOURCE_TO_SINK",
        limitation: "This pass cannot prove whether a guard exists in a helper or middleware.",
      };
    }
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
  const massAssignmentSurface = /\b(?:request\s*\.\s*(?:POST|form|data|body|json)|payload\s*\.(?:dict|model_dump)|request_data)\b/i.test(content)
    && /\b(?:update\s*\(\s*\*\*[A-Za-z_]\w*|__dict__\s*\.\s*update\s*\(|setattr\s*\([^\n]*(?:request|payload|data))/.test(content);
  if (djangoView || massAssignmentSurface) {
    for (const [index, line] of codeLines.entries()) {
      const objectLookup = line.match(/\bobjects\s*\.\s*(?:get|filter)\s*\(([^)]*)\)/i);
      if (djangoView && objectLookup
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

interface PythonPolicyBlock {
  name: string;
  startLine: number;
  endLine: number;
  routeLine: number;
  decorators: string;
  body: string;
  rawBody: string;
}

function pythonFunctionHeader(codeLines: string[], index: number): { indent: number; name: string; endLine: number } | null {
  const definition = codeLines[index]?.match(/^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/);
  if (!definition) return null;
  const indent = definition[1].replace(/\t/g, "    ").length;
  let depth = 0;
  let opened = false;
  for (let lineIndex = index; lineIndex < Math.min(codeLines.length, index + 32); lineIndex += 1) {
    const line = codeLines[lineIndex] ?? "";
    for (const current of line) {
      if (current === "(") {
        opened = true;
        depth += 1;
      } else if (current === ")" && opened) {
        depth -= 1;
        if (depth === 0) return { indent, name: definition[2], endLine: lineIndex };
      }
    }
  }
  return null;
}

function pythonPolicyBlocks(content: string): PythonPolicyBlock[] {
  const codeLines = maskPython(content).split(/\r?\n/);
  const rawLines = content.split(/\r?\n/);
  const blocks: PythonPolicyBlock[] = [];
  for (let index = 0; index < codeLines.length; index += 1) {
    const definition = pythonFunctionHeader(codeLines, index);
    if (!definition) continue;
    const indent = definition.indent;
    const bodyStart = definition.endLine + 1;
    let end = codeLines.length;
    for (let cursor = bodyStart; cursor < codeLines.length; cursor += 1) {
      const candidate = codeLines[cursor] ?? "";
      const candidateIndent = (candidate.match(/^\s*/)?.[0] ?? "").replace(/\t/g, "    ").length;
      if (candidate.trim() && candidateIndent <= indent) {
        end = cursor;
        break;
      }
    }
    let cursor = index - 1;
    const decorators: string[] = [];
    let routeLine = index + 1;
    while (cursor >= 0) {
      const decorator = codeLines[cursor] ?? "";
      if (!decorator.trim()) {
        cursor -= 1;
        continue;
      }
      if (!decorator.trim().startsWith("@")) break;
      decorators.unshift(rawLines[cursor] ?? decorator);
      if (/\b(?:route|get|post|put|patch|delete|options|head|api_route)\s*\(/i.test(decorator)) routeLine = cursor + 1;
      cursor -= 1;
    }
    blocks.push({
      name: definition.name,
      startLine: index + 1,
      endLine: end,
      routeLine,
      decorators: decorators.join("\n"),
      body: codeLines.slice(index, end).join("\n"),
      rawBody: rawLines.slice(index, end).join("\n"),
    });
    index = Math.max(index, end - 1);
  }
  return blocks;
}

function pythonRateLimitLines(relativePath: string, content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-RATE-LIMIT-001" && candidate.enabled);
  if (!rule || isNonProductionFixturePath(relativePath)) return result;
  const blocks = pythonPolicyBlocks(content);
  const moduleHasLimiter = /\b(?:flask_limiter|slowapi|Limiter|rate_limit|throttle|lockout|backoff)\b/i.test(content);
  for (const block of blocks) {
    const routeOrName = `${block.decorators}\n${block.name}`;
    const authName = /\b(?:do_login|do_signup|login|signin|sign_in|register|signup|sign_up|reset_password|forgot_password|change_password|verify_email|verify_token|password_reset|request_password_reset|confirm_password_reset)\b/i.test(block.name);
    const authRouteName = /(?:^|\/)\s*(?:login|signin|sign-in|register|signup|sign-up|auth|token|password|reset|verify|mfa|otp)\b/i.test(routeOrName);
    const requestInput = /\b(?:request|req)\s*\.\s*(?:POST|form|json|body|values|data|args|query_params)\b|\bself\s*\.\s*request\s*\.\s*(?:arguments|body|files|query|uri)\b|\bself\s*\.\s*get_argument\s*\(/i.test(block.body);
    const credentialInput = /\b(?:password|passwd|passphrase|pwd|username|uname|email|otp|mfa|credential|api[_-]?key)\b/i.test(block.body);
    const postLike = /\b(?:request|req)\s*\.\s*(?:POST|form|json|body|values|data)\b|\bself\s*\.\s*(?:request\s*\.\s*)?get_argument\s*\(|\b(?:methods|method)\s*=\s*[^\n]*(?:POST|post)/i.test(block.body)
      || /\b(?:methods|method)\s*=\s*[^\n]*(?:POST|post)/i.test(block.decorators);
    const authOperation = /\b(?:authenticate|check_password|check_password_hash|verify_password|login_user|authenticate_user)\s*\(/i.test(block.body);
    const explicitAuthSurface = authName || authRouteName;
    const authContext = explicitAuthSurface || (authOperation && credentialInput);
    const authFlow = authContext && requestInput && (postLike || authName || authRouteName);
    const graphqlMutationAuthFlow = /\bgraphene\s*\.\s*Mutation\b/i.test(content)
      && /^mutate$/i.test(block.name)
      && credentialInput
      && /\b(?:user|account|authenticate|login|token|password)\b/i.test(block.body);
    const requestHandlerAuthFlow = /\b(?:tornado\s*\.\s*web\s*\.\s*RequestHandler|BaseHTTPRequestHandler)\b/i.test(content)
      && /^(?:post|do_POST|do_GET|get)$/i.test(block.name)
      && credentialInput
      && (requestInput || /\b(?:params\s*\.\s*get|\/login|cursor\s*\.\s*execute|authenticate|login)\b/i.test(block.body));
    // A decorated endpoint that merely reads an email/token/profile field is
    // not itself an authentication-attempt surface. Require an explicit auth
    // route/name or an authentication operation before suggesting throttling.
    const routeAuthFlow = explicitAuthSurface && credentialInput && (postLike || (requestInput && authName));
    if (!authFlow && !routeAuthFlow && !graphqlMutationAuthFlow && !requestHandlerAuthFlow) continue;
    if (moduleHasLimiter && /\b(?:limiter|rate_limit|throttle|lockout|backoff|failed_attempt|sleep\s*\()\b/i.test(block.body)) continue;
    if (/\b(?:limiter|rate_limit|throttle|lockout|backoff|failed_attempt|sleep\s*\()\b/i.test(block.body)) continue;
    const handlerRouteOffset = requestHandlerAuthFlow
      ? block.body.split(/\r?\n/).findIndex((line) => /\bpath\s*==\s*['"][^'"]*login[^'"]*['"]|['"]\/login(?:['"]|\/)/i.test(line))
      : -1;
    result.set(handlerRouteOffset >= 0 ? block.startLine + handlerRouteOffset : block.routeLine, [rule.id]);
  }
  return result;
}

function pythonUserEnumerationLines(relativePath: string, content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-USER-ENUMERATION-001" && candidate.enabled);
  if (!rule || isNonProductionFixturePath(relativePath)) return result;
  const normalizedPath = relativePath.replace(/\\/g, "/");
  for (const block of pythonPolicyBlocks(content)) {
    const explicitIdentityName = /(?:^|[_-])(?:identity|account|email|handle|username)(?:[_-]|$)/i.test(block.name);
    const genericIdentityName = /(?:^|[_-])(?:user|member|customer|patient|employee)(?:[_-]|$)/i.test(block.name)
      && /\b(?:known|not\s+in)\b/i.test(block.body);
    const requestBoundary = /\b(?:request|req)\s*\.|\bself\s*\.\s*request\b/i.test(block.body);
    const knownMembership = /\b(?:known|not\s+in)\b/i.test(block.body);
    const identityContext = (explicitIdentityName || genericIdentityName)
      && /\b(?:known|lookup|find|query|filter|exists|not\s+in|one_or_none|first\s*\()\b/i.test(block.body)
      && (requestBoundary || knownMembership);
    const authContext = /\b(?:login|signin|sign_in|register|signup|sign_up|forgot_password|reset_password|password_reset|verify_email|authenticate)\b/i.test(block.name)
      || /(?:^|\/)auth(?:\/|\.py$)/i.test(normalizedPath)
      || identityContext;
    if (!authContext) continue;
    const lookup = /\b(?:exists|is\s+(?:not\s+)?None|find_by_email|find_user|filter(?:_by)?\s*\([^\n]*(?:email|username|handle)|query\s*\([^\n]*(?:email|username|handle)|(?:not\s+in|in)\s+[A-Za-z_]\w*)\b/i.test(block.body);
    if (!lookup) continue;
    const messageLine = block.rawBody.split(/\r?\n/).findIndex((line) => {
      const code = line.replace(/#.*$/, "").trim();
      if (!code) return false;
      if (/\bif\s+(?:that|the)\s+(?:email|user|account)\s+exists\b/i.test(code)
        || /\bexists\s*,\s*(?:a|an|the)\s+(?:reset|verification|confirmation)\s+(?:link|email|message)\b/i.test(code)) return false;
      return /\b(?:return|raise|flash|message|detail|description|error|json|HttpResponse|ValidationError)\b[^\n]*(?:already\s+(?:exists|registered|taken)|(?:user|email|account|handle|username|member|customer)\s+(?:already\s+)?exists|not\s+found|does\s+not\s+exist|unknown\s+(?:user|email|account|handle|username)|no\s+such\s+(?:user|account|handle)|(?:email|username|handle)\s+(?:incorrect|already\s+used))\b/i.test(code);
    });
    if (messageLine < 0) continue;
    result.set(block.startLine + messageLine, [rule.id]);
  }
  return result;
}

function pythonFileUploadLines(relativePath: string, content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-UNRESTRICTED-FILE-UPLOAD-001" && candidate.enabled);
  if (!rule || isNonProductionFixturePath(relativePath)) return result;
  for (const block of pythonPolicyBlocks(content)) {
    const uploadSource = /\b(?:request\s*\.\s*files|UploadFile|uploaded_file|upload(?:ed)?_file|file\s*\.\s*filename)\b/i.test(block.body)
      || (/(?:request\s*\.\s*body|await\s+request\s*\.\s*body\s*\(\))/i.test(block.body)
        && /(?:^|_)(?:upload|uploaded|file|attachment|document|media|shelf|drop|blob|import)(?:_|$)/i.test(block.name));
    const bodyLines = block.body.split(/\r?\n/);
    const uploadSink = (line: string): boolean => {
      if (/\.(?:write_bytes|write_text)\s*\(|\b(?:shutil\s*\.\s*)?copyfileobj\s*\(|\bopen\s*\([^\n]*(?:['"](?:wb|ab|w)['"]|filename|upload|media|attachment)/i.test(line)) return true;
      const save = line.match(/\b([A-Za-z_]\w*)\s*\.\s*(?:save|write)\s*\(/i);
      if (!save) return false;
      return /(?:file|upload|shelf|storage|blob|attachment|media|stream|target|dest)/i.test(save[1])
        || /\b(?:request\s*\.\s*files|drop_blob|uploaded_file|upload(?:ed)?_file|file_obj)\b/i.test(line)
        || /\b(?:doc|document|task)\s*\.\s*save\s*\(/i.test(line)
          && /\brequest\s*\.\s*files\b/i.test(block.body)
          && /\b(?:form|upload_form)\s*\.\s*is_valid\s*\(\s*\)/i.test(block.body)
          && !/\b(?:DocumentVersionUploadForm|SubmissionForm|save_document_version|validate_upload|sanitize_filename)\b/i.test(block.body);
    };
    const lineOffset = bodyLines.findIndex(uploadSink);
    if (!uploadSource || lineOffset < 0 || /\b(?:secure_filename|allowed_extensions?|allowed_file|content_type|mimetype|filetype|magic\.from|validate_file|MAX_CONTENT_LENGTH)\b/i.test(block.body)) continue;
    result.set(block.startLine + Math.max(0, lineOffset), [rule.id]);
  }
  return result;
}

function pythonSessionIntegrityLines(relativePath: string, content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-SESSION-INTEGRITY-001" && candidate.enabled);
  if (!rule || isNonProductionFixturePath(relativePath)) return result;
  for (const block of pythonPolicyBlocks(content)) {
    const cookieSink = /\b(?:response|resp|res)\s*\.\s*set_cookie\s*\(/i.test(block.body);
    if (!cookieSink) continue;
    const sessionCookie = /\b(?:set_cookie\s*\(\s*(?:key\s*=\s*)?['"][^'"]*(?:session|auth|token|sid)[^'"]*['"]|(?:session|auth|token|sid)[_-]?(?:cookie|value)?)\b/i.test(block.rawBody)
      || /\b(?:session|auth|token|sid)\b/i.test(block.rawBody);
    if (!sessionCookie) continue;
    const serialized = /\b(?:base64\s*\.\s*(?:b64encode|urlsafe_b64encode)|urlsafe_b64encode|b64encode)\s*\(/i.test(block.body)
      && /\b(?:json\s*\.\s*dumps|pickle\s*\.\s*dumps|marshal\s*\.\s*dumps|urlencode)\s*\(/i.test(block.body);
    if (!serialized) continue;
    if (/\b(?:hmac|itsdangerous|sign(?:ed|ature)?|jwt\s*\.\s*encode|TimestampSigner|django\s*\.\s*core\s*\.\s*signing|Fernet|SecretBox|encrypt)\b/i.test(block.body)) continue;
    const lineOffset = block.body.split(/\r?\n/).findIndex((line) => /\b(?:response|resp|res)\s*\.\s*set_cookie\s*\(/i.test(line));
    if (lineOffset >= 0) result.set(block.startLine + lineOffset, [rule.id]);
  }
  return result;
}

function pythonWeakRandomnessLines(relativePath: string, content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-WEAK-RANDOMNESS-001" && candidate.enabled);
  if (!rule || isNonProductionFixturePath(relativePath)) return result;
  const codeLines = maskPython(content).split(/\r?\n/);
  const rawLines = content.split(/\r?\n/);
  for (let index = 0; index < codeLines.length; index += 1) {
    const line = codeLines[index] ?? "";
    const localContextLines = codeLines.slice(Math.max(0, index - 2), Math.min(codeLines.length, index + 3));
    const rawContextLines = rawLines.slice(Math.max(0, index - 2), Math.min(rawLines.length, index + 3));
    const localWindow = localContextLines.filter((candidate) => !/^\s*(?:async\s+)?def\s+/.test(candidate)).join("\n");
    const rawLocalWindow = rawContextLines.filter((candidate) => !/^\s*(?:async\s+)?def\s+/.test(candidate)).join("\n");
    let functionName = "";
    for (let cursor = index; cursor >= 0; cursor -= 1) {
      const definition = codeLines[cursor]?.match(/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/);
      if (definition) {
        functionName = definition[1];
        break;
      }
    }
    const weakRandomCall = /\b(?:random|numpy\s*\.\s*random)\s*\.\s*(?:random|randint|randrange|choice|choices|sample|shuffle|getrandbits|uniform)\s*\(/i.test(line)
      || /\brandom\s*\(\s*\)/i.test(line);
    const shortenedUuid = /\b(?:uuid\s*\.\s*)?uuid4\s*\(\s*\)[^\n]*(?:\[\s*\d+\s*:\s*\d+\s*\]|\.\s*hex\s*\[\s*\d+\s*:\s*\d+\s*\])/i.test(line);
    if (!weakRandomCall && !shortenedUuid) continue;
    if (/\b(?:secrets|SystemRandom|os\s*\.\s*urandom|token_urlsafe|token_hex|uuid\s*\.\s*uuid4)\b/i.test(line) && !shortenedUuid) continue;
    const securityContext = /\b(?:session|cookie|csrf|token|secret|api[_-]?key|auth(?:entication)?[_-]?token|nonce|password|reset|invite|private[_-]?key|signing[_-]?key)\b/i.test(localWindow)
      || /\b(?:session|cookie|csrf|token|secret|api[_-]?key|auth(?:entication)?[_-]?token|nonce|password|reset|invite|private[_-]?key|signing[_-]?key)\b/i.test(rawLocalWindow)
      || (/\bkey\s*=/i.test(line) && (/(?:hash|hmac|sign|auth|crypto|secret|session|token)/i.test(localWindow) || /(?:^|[\\/])(?:skey|crypto|auth|security|token)[^\\/]*\.py$/i.test(relativePath)))
      || /\b(?:generate|create|make|build)_[A-Za-z_]*(?:token|session|key|secret|nonce|id|uuid)\b/i.test(functionName)
      || /(?:^|[\\/])(?:rand|random|prng|crypto|security)\.py$/i.test(relativePath)
      || shortenedUuid;
    if (!securityContext) continue;
    result.set(index + 1, [rule.id]);
  }
  return result;
}

function pythonSecurityConfigurationLines(relativePath: string, content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-SECURITY-MISCONFIGURATION-001" && candidate.enabled);
  if (!rule || isNonProductionFixturePath(relativePath)) return result;
  const corsReflection = /\brequest\s*\.\s*headers?\s*\.\s*get\s*\(\s*['"]origin['"]/i.test(content)
    && /Access-Control-Allow-Origin[^\n]*(?:origin|request)/i.test(content)
    && /Access-Control-Allow-Credentials[^\n]*(?:True|true|['"]true['"])/i.test(content);
  if (corsReflection) {
    const lines = content.split(/\r?\n/);
    const block = pythonPolicyBlocks(content).find((candidate) => /request\s*\.\s*headers?\s*\.\s*get\s*\(\s*['"]origin['"]/i.test(candidate.rawBody)
      && /Access-Control-Allow-Origin[^\n]*(?:origin|request)/i.test(candidate.rawBody));
    const line = block?.routeLine ?? lines.findIndex((candidate) => /Access-Control-Allow-Origin/i.test(candidate)) + 1;
    if (line > 0) result.set(line, [rule.id]);
  }
  for (const [index, raw] of content.split(/\r?\n/).entries()) {
    if (/(?:X-XSS-Protection|X-Frame-Options)\s*['"]?\s*[,=]\s*['"]?0\b/i.test(raw)
      || /(?:autoescape|csrf[_-]?middleware|SESSION_COOKIE_(?:SECURE|HTTPONLY)|CSRF_COOKIE_(?:SECURE|HTTPONLY))\s*=\s*(?:False|None)\b/i.test(raw)
      || /(?:OP_NO_SSLv3|OP_NO_COMPRESSION|OP_CIPHER_SERVER_PREFERENCE)\b[^\n]*&=/i.test(raw)
      || /\b(?:ssl\s*\.\s*)?_create_unverified_context\s*\(|\b(?:verify|check_hostname)\s*=\s*False\b|\bCERT_NONE\b/i.test(raw)
      || /\b(?:SECURE_SSL_REDIRECT|SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE)\s*=\s*False\b/i.test(raw)
      || /(?:Access-Control-Allow-Origin|allow_origins)\b[^\n]*(?:\*|request\s*\.\s*headers?)/i.test(raw)
      || /(?:CORS|cors)\s*[^\n]*(?:allow_credentials\s*=\s*True|origins?\s*=\s*\[?\s*['"]\*['"])/i.test(raw)
      || /#\s*[^\n]*csrf[_-]?middleware/i.test(raw)) result.set(index + 1, [rule.id]);
  }
  return result;
}

function pythonSensitiveLogLines(relativePath: string, content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-SENSITIVE-DATA-EXPOSURE-001" && candidate.enabled);
  if (!rule || isNonProductionFixturePath(relativePath)) return result;
  const blocks = pythonPolicyBlocks(content);
  for (const [index, raw] of content.split(/\r?\n/).entries()) {
    const sensitive = /\b(?:password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|auth[_-]?token|authorization|cookie|session|ssn|social[_-]?security|credit[_-]?card)\b/i.test(raw);
    if (!sensitive) continue;
    const loggerCall = /(?:\blogger?|logging|log)\s*\.\s*(?:debug|info|warning|error|exception|critical)\s*\(/i.test(raw);
    const printCall = /\bprint\s*\(/i.test(raw);
    if (!loggerCall && !printCall) continue;
    // A generic CLI/debug print is not a client-facing disclosure. Keep
    // direct logger calls visible, and only promote print() when it is inside
    // an explicitly decorated web handler with a reachable request path.
    if (printCall && !blocks.some((block) => index + 1 >= block.startLine && index + 1 <= block.endLine
      && /@[^\n]*\b(?:route|get|post|put|patch|delete|options|head|api_route)\s*\(/i.test(block.decorators))) continue;
    result.set(index + 1, [rule.id]);
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
    const rawBody = content.split(/\r?\n/).slice(index, end).join("\n");
    if (!/\b(?:fetchall|fetchmany)\s*\(/i.test(body)) continue;
    const returnsRawRows = /\breturn\s+(?:(?:jsonify|JsonResponse|Response)\s*\(\s*)?(?:_data|rows|records|results|users)\b/i.test(body);
    if (!returnsRawRows) continue;
    // A DAO that projects id/name records is not automatically a disclosure.
    // Promote only a raw row return containing sensitive fields, SELECT *, or
    // a route-level response whose schema cannot be seen locally.
    const sensitiveQuery = /\b(?:select\s+\*|password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token|authorization|email|phone|address|ssn|social[_-]?security|credit[_-]?card|role|permission|mfa|salt|hash)\b/i.test(rawBody);
    const routeResponse = /@[^\n]*\b(?:route|get|post|put|patch|delete|options|head|api_route)\s*\(/i.test(rawBody);
    if (!sensitiveQuery && !routeResponse) continue;
    for (let cursor = index + 1; cursor < end; cursor += 1) {
      if (/\breturn\s+(?:(?:jsonify|JsonResponse|Response)\s*\(\s*)?(?:_data|rows|records|results|users)\b/i.test(lines[cursor] ?? "")) {
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

function callArgumentText(line: string, index: number): string {
  const open = line.indexOf("(", index);
  if (open < 0) return "";
  let depth = 0;
  let quote: string | null = null;
  let escaped = false;
  for (let cursor = open; cursor < line.length; cursor += 1) {
    const current = line[cursor];
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
    if (current === "(") depth += 1;
    else if (current === ")") {
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

function pythonSqlInterpolationLines(content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-SQL-INJECTION-001" && candidate.enabled);
  if (!rule) return result;
  const lines = maskPython(content).split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (!/\b(?:execute|raw)\s*\(/i.test(lines[index] ?? "")) continue;
    const window = lines.slice(Math.max(0, index - 6), Math.min(lines.length, index + 5)).join("\n");
    const callIndex = window.search(/\b(?:execute|raw)\s*\(/i);
    const queryArgument = callIndex >= 0 ? firstCallArgumentText(callArgumentText(window, callIndex)) : window;
    const interpolation = /(?:%\s*(?:\(|[A-Za-z_])|\+|f\s*["'])/.test(queryArgument);
    const externalShape = /\b(?:request|req)\s*\.|\b(?:user_id|username|email|password|input_password|ip|col|field|query|path|url|form)\b/i.test(queryArgument);
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

function pythonGraphqlIdorLines(content: string, playbook: AuditPlaybook): Map<number, string[]> {
  const result = new Map<number, string[]>();
  const rule = playbook.rules.find((candidate) => candidate.id === "PY-IDOR-001" && candidate.enabled);
  if (!rule || !/\bgraphene\s*\.\s*Mutation\b/i.test(content)) return result;
  const lines = maskPython(content).split(/\r?\n/);
  const blocks = pythonPolicyBlocks(content);
  for (const block of blocks) {
    if (!/^mutate$/i.test(block.name) || !/\b(?:id|pk|[A-Za-z_]\w*_id)\b/.test(block.body)) continue;
    for (let index = block.startLine - 1; index < block.endLine; index += 1) {
      const line = lines[index] ?? "";
      const lookup = line.match(/\b(?:[A-Za-z_]\w*\s*\.\s*)?(?:objects|query)\s*\.\s*(?:filter_by|filter|get)\s*\(([^)]*)\)/i);
      if (!lookup || !/\b(?:id|pk|[A-Za-z_]\w*_id)\s*=\s*(?:id|pk|[A-Za-z_]\w*_id)\b/i.test(lookup[1])) continue;
      const ownerBinding = /\b(?:owner|author|created_by|user|account|tenant|organization)(?:_id)?\s*=/i.test(lookup[1])
        || /\b(?:owner|author|created_by|user|account|tenant|organization)(?:_id)?\b[^\n]{0,120}\b(?:current_user|info\s*\.\s*context\s*\.\s*user|request\s*\.\s*user|principal)\b/i.test(block.body)
        || /\b(?:current_user|info\s*\.\s*context\s*\.\s*user|request\s*\.\s*user|principal)\b[^\n]{0,120}\b(?:owner|author|created_by|user|account|tenant|organization)(?:_id)?\b/i.test(block.body);
      if (!ownerBinding) {
        result.set(index + 1, [rule.id]);
        break;
      }
    }
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
  if (ruleId === "PY-RATE-LIMIT-001") return {
    rootCause: "An authentication or account-creation handler has no observed local throttling, lockout, or backoff boundary.",
    impact: "Unlimited login, registration, or recovery attempts can enable credential stuffing, enumeration, or resource exhaustion.",
    remediation: "Add endpoint-appropriate rate limits and account backoff/lockout, then test the limit with repeated requests and a legitimate burst.",
    kind: "CUSTOM",
    limitation: "The static pass cannot see gateway, reverse-proxy, distributed rate limits, or account-level controls outside this source snapshot.",
  };
  if (ruleId === "PY-UNRESTRICTED-FILE-UPLOAD-001") return {
    rootCause: "An uploaded file reaches a write or save sink without an observed type, content, or extension policy.",
    impact: "An attacker may persist executable or malicious content, overwrite files, or serve active payloads from an upload path.",
    remediation: "Allowlist type and extension, inspect content, generate server-side names, store outside executable/static paths, and add a malicious-upload regression test.",
    kind: "SOURCE_TO_SINK",
    limitation: "The static pass does not prove storage permissions, web-server execution behavior, or validation performed in an external helper.",
  };
  if (ruleId === "PY-WEAK-RANDOMNESS-001") return {
    rootCause: "A predictable random source appears to generate a security-sensitive value or shortened identifier.",
    impact: "An attacker may predict session, reset, invitation, nonce, or resource identifiers and bypass a boundary that assumes sufficient entropy.",
    remediation: "Use secrets.token_urlsafe/token_hex or another reviewed CSPRNG, retain the full identifier space, rotate affected values, and add a prediction/regression test.",
    kind: "CUSTOM",
    limitation: "The static pass infers security context from nearby names and operations; it does not measure entropy, deployment seeding, or exploitability of the resulting value.",
  };
  if (ruleId === "PY-IDOR-001") return {
    rootCause: "A path-like identifier is used to select an object without an observed owner or subject constraint.",
    impact: "An authenticated user may read or modify another user's object by changing an identifier in the request.",
    remediation: "Bind object lookup to the authenticated principal and add an authorization regression test for a foreign identifier.",
    kind: "AUTHORIZATION_BOUNDARY",
    limitation: "The static pass promotes identifier lookups inside explicit vulnerable branches and Graphene mutations; complete ownership and authorization still require independent validation.",
  };
  if (ruleId === "PY-MASS-ASSIGNMENT-001") return {
    rootCause: "Request-derived fields appear to be expanded into a model update without an observed privileged-field allowlist.",
    impact: "An attacker may modify authorization-relevant, ownership, password, or workflow fields that the endpoint did not intend to expose.",
    remediation: "Use an explicit writable-field allowlist, reject privilege-bearing fields, and add a regression test for every protected attribute.",
    kind: "AUTHORIZATION_BOUNDARY",
    limitation: "The static pass observes the request-to-update shape but cannot prove model binding, serializer allowlists, authorization middleware, or field-level policy outside this snapshot.",
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
  if (ruleId === "PY-SESSION-INTEGRITY-001") return {
    rootCause: "A session-like cookie is assembled from encoded or serialized state without an observed signing or authenticated-encryption boundary.",
    impact: "An attacker may forge or modify client-held session state and impersonate another user if the server trusts the cookie contents.",
    remediation: "Use the framework's signed session facility or authenticated encryption, rotate affected session material, and add a tamper-resistance test.",
    kind: "AUTHORIZATION_BOUNDARY",
    limitation: "The static pass identifies an unsigned serialization pattern but cannot prove which fields are trusted, whether a framework wrapper signs later, or whether the endpoint is reachable.",
  };
  if (ruleId === "PY-SECURITY-MISCONFIGURATION-001") return {
    rootCause: "A Python host allowlist accepts every Host header.",
    impact: "Host-header injection, cache poisoning, or password-reset poisoning may become possible when downstream links trust the request host.",
    remediation: "Use an explicit production host allowlist and add a request test that rejects an untrusted Host header.",
    kind: "CUSTOM",
    limitation: "The static pass cannot determine which settings module is active or whether a trusted proxy, framework default, or edge control compensates for the local configuration.",
  };
  if (ruleId === "PY-REFLECTED-XSS-001") return {
    rootCause: "A request-derived value appears to be passed into a server-side HTML template response without a local escaping guarantee.",
    impact: "An attacker may execute script or inject markup in a victim's browser when the template uses a raw or otherwise unsafe output context.",
    remediation: "Keep untrusted values as template data, remove raw output directives, and add a browser-level regression test for escaped markup.",
    kind: "SOURCE_TO_SINK",
    limitation: "The static pass sees a framework render call and an unsafe-output signal but does not parse the referenced template or prove browser reachability.",
  };
  if (ruleId === "TEMPLATE-UNSAFE-OUTPUT-001") return {
    rootCause: "A Jinja or Django template uses an explicit safe/raw output mode or disables autoescaping.",
    impact: "Untrusted markup may execute in the application's origin when the rendered value is attacker-controlled or stored without a sanitizer contract.",
    remediation: "Use the template engine's default escaping, sanitize only with a reviewed allowlist, and add a browser regression test for script and markup payloads.",
    kind: "SOURCE_TO_SINK",
    limitation: "The static pass does not resolve data provenance, context-sensitive escaping, sanitizer behavior, or browser reachability.",
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
    for (const [lineNumber, ruleIds] of pythonGraphqlIdorLines(content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonSensitiveExposureLines(content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonWeakHashLines(content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonSqlInterpolationLines(content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonRateLimitLines(relativePath, content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonUserEnumerationLines(relativePath, content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonFileUploadLines(relativePath, content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonSessionIntegrityLines(relativePath, content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonWeakRandomnessLines(relativePath, content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonSecurityConfigurationLines(relativePath, content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
    for (const [lineNumber, ruleIds] of pythonSensitiveLogLines(relativePath, content, playbook)) pythonPolicyMatches.set(lineNumber, [...new Set([...(pythonPolicyMatches.get(lineNumber) ?? []), ...ruleIds])]);
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
