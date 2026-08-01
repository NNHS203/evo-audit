import type {
  AuditObligation,
  AuditPlaybook,
  Finding,
  PlaybookRule,
  SourceLocation,
} from "./types.js";

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

function findMatch(rule: PlaybookRule, line: string): Omit<DetectorMatch, "rule" | "line" | "column" | "snippet"> | null {
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
  const codeLines = maskNonCode(content).split(/\r?\n/);

  for (const [index, line] of lines.entries()) {
    const codeLine = codeLines[index] ?? "";
    for (const rule of playbook.rules) {
      if (!matchesRule(rule, relativePath)) continue;
      const match = findMatch(rule, codeLine);
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
