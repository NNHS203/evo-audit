import { promises as fs } from "node:fs";
import path from "node:path";
import { applyValidationResult, assertWorkspaceMatchesSnapshot, createValidationRequest } from "./validator.js";
import { runValidationRequest } from "./validation-runner.js";
import type { AuditRun, ValidationResult } from "./types.js";

export interface ProposedValidationOptions {
  validator?: string;
  maxFindings?: number;
  artifactDirectory?: string;
  /** Operator-selected image; model proposals cannot select the runtime. */
  image?: string;
}

export interface ProposedValidationRun {
  run: AuditRun;
  results: ValidationResult[];
  skipped: Array<{ findingId: string; reason: string }>;
}

/**
 * Execute only model-proposed positive/negative controls, and only through
 * the same independent container validator used by `validate-run`.
 *
 * This helper deliberately has no host-execution fallback. A missing runtime,
 * a changed snapshot, or an invalid proposal becomes a recorded skip/block,
 * never a vulnerability verdict.
 */
export async function runProposedValidations(
  initialRun: AuditRun,
  options: ProposedValidationOptions = {},
): Promise<ProposedValidationRun> {
  let run = structuredClone(initialRun);
  const results: ValidationResult[] = [];
  const skipped: ProposedValidationRun["skipped"] = [];
  const validator = options.validator ?? "evo-audit-independent-container-validator";
  const maxFindings = Math.max(0, Math.min(128, Math.floor(options.maxFindings ?? 32)));
  const candidates = run.findings
    .filter((finding) => finding.proposedValidation && !(run.reportableFindingIds ?? []).includes(finding.id))
    .sort((left, right) => {
      const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 } as const;
      return rank[right.severity] - rank[left.severity] || left.id.localeCompare(right.id);
    })
    .slice(0, maxFindings);

  for (const finding of candidates) {
    const proposal = finding.proposedValidation;
    if (!proposal) continue;
    const integrity = await assertWorkspaceMatchesSnapshot(run);
    if (!integrity.ok) {
      skipped.push({ findingId: finding.id, reason: `Workspace changed after snapshot: ${integrity.changed.join(", ")}` });
      break;
    }
    const request = createValidationRequest(run, finding, {
      reproducerCommand: proposal.reproducerCommand,
      negativeControlCommand: proposal.negativeControlCommand,
      timeoutMs: proposal.timeoutMs,
      image: options.image,
    });
    const result = await runValidationRequest(run, request, validator);
    results.push(result);
    run = applyValidationResult(run, result).run;
    if (options.artifactDirectory) {
      const safeId = finding.id.replace(/[^a-zA-Z0-9_.-]/g, "_");
      await fs.mkdir(options.artifactDirectory, { recursive: true });
      await fs.writeFile(path.join(options.artifactDirectory, `${safeId}.json`), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    }
  }
  return { run, results, skipped };
}
