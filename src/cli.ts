#!/usr/bin/env node
import path from "node:path";
import { initWorkspace, persistRunArtifacts, readJson, resolveInput, runAudit, summarizeRun, writeJson } from "./core.js";
import { mergeWorkerResult } from "./workers.js";
import type { AuditRun, AuditWorkerResult } from "./types.js";

function usage(): string {
  return `Evo Audit\n\nCommands:\n  init <path>                         Create audit.config.json and audit.playbook.json\n  run <path> [--output DIR]           Run the deterministic audit core\n  run <path> --baseline RUN.json       Record semantic file delta for worker prioritization\n  run <path> --strict                  Show only evidence-policy reportable findings\n  ingest <run.json> <worker.json>      Merge a Frontier worker result into a saved run\n  evolve <run.json> [--output FILE]    Propose playbook improvements from audit gaps\n  report <run.json> [--json]           Print a saved audit run\n\nThe first version reports static candidates as SUSPECTED or SUPPORTED.\nOnly an execution-capable worker may promote a finding to VERIFIED.`;
}

function flag(args: string[], name: string): boolean {
  return args.includes(name);
}

function valueFlag(args: string[], name: string, fallback: string): string {
  const index = args.indexOf(name);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
}

async function main(): Promise<void> {
  const [, , command, input, workerInput] = process.argv;
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

  if (command === "run") {
    const target = resolveInput(cwd, input);
    const output = path.resolve(cwd, valueFlag(args, "--output", "audit-runs"));
    const baselinePath = valueFlag(args, "--baseline", "");
    const baseline = baselinePath ? await readJson<AuditRun>(path.resolve(cwd, baselinePath)) : undefined;
    const result = await runAudit(target, { output, strict: flag(args, "--strict"), baseline });
    console.log(summarizeRun(result.run));
    console.log(`Artifacts: ${result.artifactDir}`);
    return;
  }

  if (command === "report") {
    if (!input) throw new Error("report requires a path to run.json");
    const run = await readJson<AuditRun>(path.resolve(cwd, input));
    if (flag(args, "--json")) console.log(JSON.stringify(run, null, 2));
    else console.log(summarizeRun(run));
    return;
  }

  if (command === "ingest") {
    if (!input || !workerInput) throw new Error("ingest requires a run.json and worker.json");
    const runPath = path.resolve(cwd, input);
    const worker = await readJson<AuditWorkerResult>(path.resolve(cwd, workerInput));
    const run = mergeWorkerResult(await readJson<AuditRun>(runPath), worker);
    await persistRunArtifacts(path.dirname(runPath), run);
    console.log(summarizeRun(run));
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
        "Promote only findings with reproducible T2 evidence.",
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
