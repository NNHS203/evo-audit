#!/usr/bin/env node
import path from "node:path";
import { compareRuns } from "./compare.js";
import { initWorkspace, persistRunArtifacts, readJson, resolveInput, runAudit, summarizeRun, writeJson } from "./core.js";
import { buildResumePlan } from "./resume.js";
import { toSarif } from "./sarif.js";
import { applyValidationResult, assertWorkspaceMatchesSnapshot, createValidationRequest } from "./validator.js";
import { mergeWorkerResult } from "./workers.js";
import { buildAuditPlan, planSummary } from "./workflow.js";
import type { AuditRun, AuditWorkerResult, ValidationResult } from "./types.js";

function usage(): string {
  return `Evo Audit

Commands:
  init <path>                         Create audit.config.json and audit.playbook.json
  review <path> [--output DIR]        Run the audit core in review mode
  run <path> [--output DIR]           Alias for review
  run <path> --baseline RUN.json      Record semantic delta for worker prioritization
  run <path> --strict                 Show only evidence-policy reportable findings
  verify <run.json> <finding-id>      Create a validator request for one finding
  validate <run.json> <result.json>   Apply an independent validator result
  compare <before.json> <after.json> Compare findings by root cause across runs
  plan <run.json> [--json]            Show prioritized investigation/validation tasks
  status <run.json>                   Show coverage and pending obligations
  resume <run.json> [--output FILE]   Write a resumable pending-work plan
  ingest <run.json> <worker.json>     Merge a Frontier worker result into a saved run
  evolve <run.json> [--output FILE]   Propose playbook improvements from audit gaps
  report <run.json> [--format FORMAT] Print text, json, or sarif

Workers may propose hypotheses, but only an independent validator may create VERIFIED evidence.`;
}

function flag(args: string[], name: string): boolean {
  return args.includes(name);
}

function valueFlag(args: string[], name: string, fallback: string): string {
  const index = args.indexOf(name);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
}

async function main(): Promise<void> {
  const [, , command, input, secondInput] = process.argv;
  const args = process.argv.slice(2);
  if (!command || command === "help" || command === "--help") {
    console.log(usage());
    return;
  }

  const cwd = process.cwd();
  if (command === "init") {
    const target = resolveInput(cwd, input);
    await initWorkspace(target);
    console.log(`Initialized Evo Audit in ${target}`);
    return;
  }

  if (command === "run" || command === "review") {
    const target = resolveInput(cwd, input);
    const output = path.resolve(cwd, valueFlag(args, "--output", "audit-runs"));
    const baselinePath = valueFlag(args, "--baseline", "");
    const baseline = baselinePath ? await readJson<AuditRun>(path.resolve(cwd, baselinePath)) : undefined;
    const strict = flag(args, "--strict");
    const result = await runAudit(target, { output, strict, baseline });
    console.log(summarizeRun(result.run, strict ? { findingIds: result.run.reportableFindingIds, session: result.session } : { session: result.session }));
    console.log(`Artifacts: ${result.artifactDir}`);
    return;
  }

  if (command === "report") {
    if (!input) throw new Error("report requires a path to run.json");
    const run = await readJson<AuditRun>(path.resolve(cwd, input));
    const format = valueFlag(args, "--format", flag(args, "--json") ? "json" : "text");
    if (format === "json") console.log(JSON.stringify(run, null, 2));
    else if (format === "sarif") console.log(JSON.stringify(toSarif(run), null, 2));
    else if (format === "text") console.log(summarizeRun(run, flag(args, "--strict") ? { findingIds: run.reportableFindingIds ?? [] } : {}));
    else throw new Error(`Unknown report format: ${format}`);
    return;
  }

  if (command === "verify") {
    if (!input || !secondInput) throw new Error("verify requires a run.json and finding-id");
    const run = await readJson<AuditRun>(path.resolve(cwd, input));
    const finding = run.findings.find((candidate) => candidate.id === secondInput);
    if (!finding) throw new Error(`Finding not found: ${secondInput}`);
    const reproducerCommand = valueFlag(args, "--command", "");
    const negativeControlCommand = valueFlag(args, "--negative", "");
    if (!reproducerCommand || !negativeControlCommand) throw new Error("verify requires --command and --negative");
    const output = path.resolve(cwd, valueFlag(args, "--output", `validation-${finding.id}.json`));
    await writeJson(output, createValidationRequest(run, finding, { reproducerCommand, negativeControlCommand }));
    console.log(`Validation request: ${output}`);
    return;
  }

  if (command === "validate") {
    if (!input || !secondInput) throw new Error("validate requires a run.json and result.json");
    const runPath = path.resolve(cwd, input);
    const originalRun = await readJson<AuditRun>(runPath);
    const validation = await readJson<ValidationResult>(path.resolve(cwd, secondInput));
    const integrity = await assertWorkspaceMatchesSnapshot(originalRun);
    const checkedResult: ValidationResult = integrity.ok
      ? validation
      : {
          ...validation,
          outcome: "HARNESS_FAILED",
          notes: [...(validation.notes ?? []), `Workspace changed after snapshot: ${integrity.changed.join(", ")}`],
        };
    const applied = applyValidationResult(originalRun, checkedResult);
    const session = await persistRunArtifacts(path.dirname(runPath), applied.run);
    console.log(`${applied.gate.status}: ${applied.gate.reason}`);
    console.log(summarizeRun(applied.run, { session }));
    return;
  }

  if (command === "compare") {
    if (!input || !secondInput) throw new Error("compare requires before.json and after.json");
    const before = await readJson<AuditRun>(path.resolve(cwd, input));
    const after = await readJson<AuditRun>(path.resolve(cwd, secondInput));
    const comparison = compareRuns(before, after);
    if (flag(args, "--json")) console.log(JSON.stringify(comparison, null, 2));
    else {
      console.log(`Compare ${comparison.beforeRunId} -> ${comparison.afterRunId}`);
      console.log(`Coverage: ${comparison.coverage.complete ? "complete" : "unknown"}  ${comparison.coverage.note}`);
      for (const item of comparison.findings) console.log(`- [${item.lifecycle}] ${item.identity}`);
    }
    return;
  }

  if (command === "plan") {
    if (!input) throw new Error("plan requires a run.json");
    const run = await readJson<AuditRun>(path.resolve(cwd, input));
    const workflowPlan = run.plan ?? buildAuditPlan(run);
    if (flag(args, "--json")) {
      console.log(JSON.stringify(workflowPlan, null, 2));
    } else {
      console.log(`Run ${run.runId}`);
      console.log(planSummary(workflowPlan));
      for (const task of workflowPlan.tasks) {
        const context = task.context.files.map((file) => `${file.relation.toLowerCase()}:${file.path}`).join(", ");
        console.log(`- [${task.status}] ${task.phase} priority=${task.priority} budget=${task.budgetTokens} ${task.title}`);
        console.log(`  context: ${context || "none"}`);
      }
    }
    return;
  }

  if (command === "status" || command === "resume") {
    if (!input) throw new Error(`${command} requires a run.json`);
    const run = await readJson<AuditRun>(path.resolve(cwd, input));
    const plan = buildResumePlan(run);
    if (command === "status") {
      if (flag(args, "--json")) console.log(JSON.stringify(plan, null, 2));
      else {
        console.log(`Run ${run.runId}`);
        console.log(`Coverage: ${run.coverage?.complete ? "complete" : "unknown"}  semantic=${run.coverage?.semantic ?? "unknown"}  Pending obligations: ${plan.pendingObligations.length}`);
        console.log(planSummary(run.plan ?? buildAuditPlan(run)));
        for (const obligation of plan.pendingObligations) console.log(`- [${obligation.status}] ${obligation.id}: ${obligation.title}`);
      }
      return;
    }
    const output = path.resolve(cwd, valueFlag(args, "--output", path.join(path.dirname(input), "resume-plan.json")));
    await writeJson(output, plan);
    console.log(`Resume plan: ${output}`);
    return;
  }

  if (command === "ingest") {
    if (!input || !secondInput) throw new Error("ingest requires a run.json and worker.json");
    const runPath = path.resolve(cwd, input);
    const worker = await readJson<AuditWorkerResult>(path.resolve(cwd, secondInput));
    const run = mergeWorkerResult(await readJson<AuditRun>(runPath), worker);
    const session = await persistRunArtifacts(path.dirname(runPath), run);
    console.log(summarizeRun(run, { session }));
    console.log(`Updated: ${runPath}`);
    return;
  }

  if (command === "evolve") {
    if (!input) throw new Error("evolve requires a path to run.json");
    const run = await readJson<AuditRun>(path.resolve(cwd, input));
    const output = path.resolve(cwd, valueFlag(args, "--output", "playbook-proposal.json"));
    const proposal = {
      schemaVersion: 1,
      status: "PROPOSED",
      basedOn: { runId: run.runId, playbook: run.playbook },
      principles: [
        "Promote only findings with reproducible T2 evidence from an independent validator.",
        "Turn every unresolved obligation into a falsifiable verification task.",
        "Use compact evidence summaries before requesting more model context.",
      ],
      changes: run.obligations
        .filter((obligation) => obligation.status !== "SATISFIED")
        .map((obligation) => ({
          kind: "ADD_VALIDATION_REQUIREMENT",
          obligationId: obligation.id,
          title: obligation.title,
          rationale: "The obligation remains open or blocked after this run.",
          falsifiers: obligation.falsifiers,
        })),
      notes: [
        "This file is a reviewable proposal; it is not applied automatically.",
        "A future evaluator/reviser can score this proposal on held-out cases before accepting it.",
      ],
    };
    await writeJson(output, proposal);
    console.log(`Playbook proposal: ${output}`);
    return;
  }

  throw new Error(`Unknown command: ${command}\n\n${usage()}`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
