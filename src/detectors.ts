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

function findMatch(rule: PlaybookRule, line: string, rawLine = line): Omit<DetectorMatch, "rule" | "line" | "column" | "snippet"> | null {
  if (rule.id === "PY-DYNAMIC-CODE-001" && /\b(?:eval|exec)\s*\(/.test(line) && new RegExp(pythonRequestInput, "i").test(line)) {
    return {
      rootCause: "A Python dynamic code execution boundary is present.",
      impact: "If attacker-controlled data reaches this call, arbitrary Python code execution may be possible.",
      remediation: "Remove eval/exec or constrain it to a reviewed, non-user-controlled allowlist and verify the boundary with an isolated test.",
      kind: "DYNAMIC_CODE",
      limitation: "This static pass does not prove that an external attacker controls the Python argument.",
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

  if (rule.id === "PY-HARDCODED-CREDENTIAL-001" && /\b(?:secret[_-]?key|password|passwd|token|api[_-]?key|private[_-]?key)\b\s*=\s*['"][^'"]+['"]/i.test(rawLine)) {
    return {
      rootCause: "A credential-like value is hardcoded in Python source.",
      impact: "Anyone who obtains the source may forge sessions, access an external service, or reuse the secret elsewhere.",
      remediation: "Load secrets from a managed runtime secret boundary, rotate the exposed value, and add a check that rejects literals in source.",
      kind: "CUSTOM",
      limitation: "Static matching identifies a credential-shaped literal but cannot determine whether it is a harmless fixture or an active secret.",
    };
  }

  if (rule.id === "PY-DEBUG-MODE-001" && /\b(?:app|application)\s*\.\s*debug\s*=\s*True\b/.test(line)) {
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

  for (const [index, line] of lines.entries()) {
    const codeLine = codeLines[index] ?? "";
    for (const rule of playbook.rules) {
      if (!matchesRule(rule, relativePath)) continue;
      const match = findMatch(rule, codeLine, line);
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
    }
  }

  return { findings, obligations };
}
