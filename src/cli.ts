#!/usr/bin/env node
import path from "node:path";
import { compareRuns } from "./compare.js";
import { initWorkspace, persistRunArtifacts, readJson, resolveInput, runAudit, summarizeRun, writeJson } from "./core.js";
import { buildResumePlan } from "./resume.js";
import { toSarif } from "./sarif.js";
import { applyValidationResult, assertWorkspaceMatchesSnapshot, createValidationRequest } from "./validator.js";
import { runValidationRequest } from "./validation-runner.js";
import { mergeWorkerResult } from "./workers.js";
import { buildAuditPlan, planSummary } from "./workflow.js";
import { authorizeModel, loadModelConfig, ModelRegistry } from "./models.js";
import { executeWorkerTask } from "./worker-runner.js";
import { evaluateBenchmark, runBenchmark } from "./benchmark.js";
import { buildRevalidationPlan } from "./revalidation.js";
import { groundTruthLabelsFromValue, scannerFindingsFromBandit, scannerFindingsFromRun, scannerFindingsFromSarif, scoreScannerFindings, type GroundTruthFormat } from "./scoring.js";
import { runRealVuln, runRealVulnAll } from "./realvuln.js";
import type { AuditRun, AuditWorkerResult, ValidationResult } from "./types.js";

function usage(): string {
  return `Evo Audit

Commands:
  init <path>                         Create audit.config.json and audit.playbook.json
  models <path> [--config FILE]       List configured API/OAuth models and credential state
  auth <path> <model-id>               Authorize a configured model with OAuth PKCE
  review <path> [--output DIR]        Run the audit core in review mode
  run <path> [--output DIR]           Alias for review
  run <path> --baseline RUN.json      Record semantic delta for worker prioritization
  run <path> --strict                 Show only evidence-policy reportable findings
  verify <run.json> <finding-id>      Create a validator request for one finding
  validate <run.json> <result.json>   Apply an independent validator result
  validate-run <run.json> <request.json> Execute a request in a container sandbox
  compare <before.json> <after.json> Compare findings by root cause across runs
  revalidate <before.json> <after.json> Build a fix/regression validation plan
  score <ground-truth.json> <run/sarif/bandit> Score normalized scanner output
  plan <run.json> [--json]            Show prioritized investigation/validation tasks
  status <run.json>                   Show coverage and pending obligations
  resume <run.json> [--output FILE]   Write a resumable pending-work plan
  ingest <run.json> <worker.json>     Merge a Frontier worker result into a saved run
  worker <run.json> <task-id>         Run one HUNT/INVESTIGATE task with a configured model
  worker <run.json> --all             Run pending worker tasks with bounded concurrency
  benchmark <cases-dir>               Run benchmark cases (optional --model auto)
  realvuln <benchmark-root> <repo-id>  Clone a pinned RealVuln repo and emit a scored report
  realvuln <benchmark-root> --all       Audit every manifest entry and emit an aggregate
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

function numberFlag(args: string[], name: string): number | undefined {
  const value = valueFlag(args, name, "");
  if (!value) return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw new Error(`${name} requires a numeric value.`);
  return parsed;
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

  if (command === "benchmark") {
    if (!input) throw new Error("benchmark requires a cases directory");
    const requestedModel = valueFlag(args, "--model", "");
    const modelConfig = requestedModel ? await loadModelConfig(cwd, valueFlag(args, "--config", "")) : undefined;
    const report = await runBenchmark(path.resolve(cwd, input), valueFlag(args, "--split", "") || undefined, {
      model: requestedModel || undefined,
      modelConfig,
      maxModelTasks: numberFlag(args, "--max-model-tasks"),
      manifestPath: valueFlag(args, "--manifest", "") || undefined,
      validate: flag(args, "--validate"),
    });
    const acceptance = evaluateBenchmark(report, {
      minCandidateRecall: numberFlag(args, "--min-recall"),
      minCandidatePrecision: numberFlag(args, "--min-precision"),
      maxFalsePositiveRate: numberFlag(args, "--max-fpr"),
      maxUnknownCoverageRate: numberFlag(args, "--max-unknown"),
      minReportableRecall: numberFlag(args, "--min-reportable-recall"),
      maxUnsupportedClaimRate: numberFlag(args, "--max-unsupported-claim-rate"),
    });
    if (flag(args, "--json")) console.log(JSON.stringify(report, null, 2));
    else {
      console.log(`Benchmark ${report.split}: ${report.metrics.cases} cases`);
      console.log(`Candidate recall=${report.metrics.candidateRecall.toFixed(3)} precision=${report.metrics.candidatePrecision.toFixed(3)} false-positive-rate=${report.metrics.falsePositiveRate.toFixed(3)} reportable-recall=${report.metrics.reportableRecall.toFixed(3)} validated-rate=${report.metrics.validatedFindingRate.toFixed(3)} unsupported-claim-rate=${report.metrics.unsupportedClaimRate.toFixed(3)} unknown-coverage=${report.metrics.unknownCoverageRate.toFixed(3)} tokens/case=${report.metrics.tokensPerCase.toFixed(0)} duration/case=${report.metrics.durationMsPerCase.toFixed(0)}ms`);
      for (const item of report.cases) console.log(`- ${item.caseId}: ${item.expectedVulnerable ? "vulnerable" : "safe"} candidate=${item.candidateFound} match=${item.matchingCandidate} reportable=${item.reportableFinding} validation=${item.validationOutcome ?? "not-run"} unknown=${item.coverageUnknown} duration=${item.durationMs}ms`);
      if (acceptance.policy.minCandidateRecall !== undefined || acceptance.policy.minCandidatePrecision !== undefined || acceptance.policy.maxFalsePositiveRate !== undefined || acceptance.policy.maxUnknownCoverageRate !== undefined || acceptance.policy.minReportableRecall !== undefined || acceptance.policy.maxUnsupportedClaimRate !== undefined) {
        console.log(`Acceptance: ${acceptance.accepted ? "PASS" : "FAIL"}`);
        for (const failure of acceptance.failures) console.log(`  - ${failure}`);
      }
    }
    if (!acceptance.accepted) throw new Error(`Benchmark acceptance failed: ${acceptance.failures.join("; ")}`);
    return;
  }

  if (command === "realvuln") {
    if (!input || (!secondInput && !flag(args, "--all"))) throw new Error("realvuln requires the RealVuln checkout root and repo-id or --all");
    if (flag(args, "--all") && secondInput && secondInput !== "--all") throw new Error("realvuln --all cannot be combined with a repo-id");
    if (flag(args, "--all")) {
      const aggregate = await runRealVulnAll(path.resolve(cwd, input), {
        output: path.resolve(cwd, valueFlag(args, "--output", "realvuln-runs")),
        keepCheckout: flag(args, "--keep-checkout"),
      });
      if (flag(args, "--json")) console.log(JSON.stringify(aggregate, null, 2));
      else {
        console.log(`RealVuln aggregate: ${aggregate.completed}/${aggregate.repositories} completed, ${aggregate.blocked} blocked`);
        console.log(`Candidate F3=${aggregate.aggregate.candidate.f3.toFixed(3)} precision=${aggregate.aggregate.candidate.precision.toFixed(3)} recall=${aggregate.aggregate.candidate.recall.toFixed(3)} false-positive-rate=${aggregate.aggregate.candidate.falsePositiveRate.toFixed(3)}`);
        console.log(`Reportable F3=${aggregate.aggregate.reportable.f3.toFixed(3)} precision=${aggregate.aggregate.reportable.precision.toFixed(3)} recall=${aggregate.aggregate.reportable.recall.toFixed(3)}`);
        console.log(`Aggregate report: ${path.join(path.resolve(cwd, valueFlag(args, "--output", "realvuln-runs")), "realvuln-aggregate.json")}`);
      }
      return;
    }
    const report = await runRealVuln(path.resolve(cwd, input), secondInput, {
      output: path.resolve(cwd, valueFlag(args, "--output", "realvuln-runs")),
      keepCheckout: flag(args, "--keep-checkout"),
    });
    if (flag(args, "--json")) console.log(JSON.stringify(report, null, 2));
    else {
      console.log(`RealVuln ${report.repository.id}@${report.repository.commit}`);
      console.log(`Candidate F3=${report.score.candidate.f3.toFixed(3)} precision=${report.score.candidate.precision.toFixed(3)} recall=${report.score.candidate.recall.toFixed(3)} false-positive-rate=${report.score.candidate.falsePositiveRate.toFixed(3)}`);
      console.log(`Reportable F3=${report.score.reportable.f3.toFixed(3)} precision=${report.score.reportable.precision.toFixed(3)} recall=${report.score.reportable.recall.toFixed(3)} findings=${report.score.findings}`);
      console.log(`Report: ${path.join(path.resolve(cwd, valueFlag(args, "--output", "realvuln-runs")), "realvuln-report.json")}`);
    }
    return;
  }

  if (command === "score") {
    if (!input || !secondInput) throw new Error("score requires a ground-truth.json and a run.json or SARIF file");
    const groundTruthFormat = valueFlag(args, "--ground-truth-format", "evo").toUpperCase();
    if (groundTruthFormat !== "EVO" && groundTruthFormat !== "REALVULN") throw new Error("--ground-truth-format must be evo or realvuln.");
    const labels = groundTruthLabelsFromValue(await readJson<unknown>(path.resolve(cwd, input)), groundTruthFormat as GroundTruthFormat);
    const source = await readJson<unknown>(path.resolve(cwd, secondInput));
    const requestedFormat = valueFlag(args, "--format", "auto");
    const sourceRecord = source && typeof source === "object" ? source as Record<string, unknown> : {};
    const isRun = requestedFormat === "run" || (requestedFormat === "auto" && typeof sourceRecord.runId === "string" && Array.isArray(sourceRecord.findings));
    const isBandit = requestedFormat === "bandit";
    const scanner = valueFlag(args, "--scanner", isRun ? "evo-audit" : isBandit ? "bandit" : "sarif-scanner");
    const scannerRoot = valueFlag(args, "--root", "") || undefined;
    const findings = isRun ? scannerFindingsFromRun(source as AuditRun, scanner) : isBandit ? scannerFindingsFromBandit(source, scanner, scannerRoot) : scannerFindingsFromSarif(source, scanner, scannerRoot);
    const run = isRun ? source as AuditRun : undefined;
    const score = scoreScannerFindings(findings, labels, {
      scanner,
      lineTolerance: numberFlag(args, "--line-tolerance"),
      inputTokens: numberFlag(args, "--input-tokens") ?? run?.tokenAccounting.inputTokens,
      outputTokens: numberFlag(args, "--output-tokens") ?? run?.tokenAccounting.outputTokens,
      durationMs: numberFlag(args, "--duration-ms") ?? run?.tokenAccounting.durationMs,
    });
    if (flag(args, "--json")) console.log(JSON.stringify(score, null, 2));
    else {
      console.log(`Score ${score.scanner}: labels=${score.labels} findings=${score.findings}`);
      console.log(`Candidate: precision=${score.candidate.precision.toFixed(3)} recall=${score.candidate.recall.toFixed(3)} false-positive-rate=${score.candidate.falsePositiveRate.toFixed(3)} F3=${score.candidate.f3.toFixed(3)}`);
      console.log(`Reportable: precision=${score.reportable.precision.toFixed(3)} recall=${score.reportable.recall.toFixed(3)} false-positive-rate=${score.reportable.falsePositiveRate.toFixed(3)} F3=${score.reportable.f3.toFixed(3)} tokens/validated=${score.reportable.tokensPerValidatedFinding ?? "n/a"}`);
      console.log(`Unsupported claims: ${score.unsupportedClaimCount} (${score.unsupportedClaimRate.toFixed(3)})  latency=${score.durationMs}ms`);
    }
    return;
  }

  if (command === "models") {
    const target = resolveInput(cwd, input);
    const modelConfig = await loadModelConfig(target, valueFlag(args, "--config", ""));
    const statuses = await new ModelRegistry(modelConfig).statuses();
    if (flag(args, "--json")) console.log(JSON.stringify({ auto: modelConfig.auto, models: statuses }, null, 2));
    else {
      console.log(`Auto model: ${modelConfig.auto.enabled ? "enabled" : "disabled"}`);
      for (const model of statuses) console.log(`- ${model.id} model=${model.model} transport=${model.transport} auth=${model.authMethod} credential=${model.credentialAvailable ? "available" : "missing"} quality=${model.qualityTier}${model.reason ? ` (${model.reason})` : ""}`);
      if (statuses.length === 0) console.log("No models configured. Add audit.models.json or use the environment-backed configuration documented in docs/MODELS.md.");
    }
    return;
  }

  if (command === "auth") {
    if (!input || !secondInput) throw new Error("auth requires a path and model-id");
    const target = resolveInput(cwd, input);
    const modelConfig = await loadModelConfig(target, valueFlag(args, "--config", ""));
    const model = modelConfig.models.find((candidate) => candidate.id === secondInput);
    if (!model) throw new Error(`Model not found: ${secondInput}`);
    const tokenFile = await authorizeModel(model, { openBrowser: !flag(args, "--no-open") });
    console.log(`OAuth token saved to: ${tokenFile}`);
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

  if (command === "validate-run") {
    if (!input || !secondInput) throw new Error("validate-run requires a run.json and request.json");
    const runPath = path.resolve(cwd, input);
    const run = await readJson<AuditRun>(runPath);
    const request = await readJson<import("./types.js").ValidationRequest>(path.resolve(cwd, secondInput));
    const validator = valueFlag(args, "--validator", "evo-audit-container-validator");
    const integrity = await assertWorkspaceMatchesSnapshot(run);
    const validation: ValidationResult = integrity.ok
      ? await runValidationRequest(run, request, validator)
      : {
          schemaVersion: 1,
          validator,
          requestId: request.requestId,
          runId: request.runId,
          findingId: request.findingId,
          outcome: "HARNESS_FAILED",
          baseTreeDigest: run.snapshot.treeDigest,
          sourceFiles: run.files,
          sandbox: { profile: request.sandboxProfile, readOnlySource: true, network: "DENY" },
          reproducer: { command: request.reproducerCommand, exitCode: null, timedOut: false, passed: false, stdoutDigest: "", stderrDigest: "" },
          negativeControl: { command: request.negativeControlCommand, exitCode: null, timedOut: false, passed: false, stdoutDigest: "", stderrDigest: "" },
          notes: [`Workspace changed after snapshot: ${integrity.changed.join(", ")}`],
        };
    const applied = applyValidationResult(run, validation);
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

  if (command === "revalidate") {
    if (!input || !secondInput) throw new Error("revalidate requires before.json and after.json");
    const before = await readJson<AuditRun>(path.resolve(cwd, input));
    const after = await readJson<AuditRun>(path.resolve(cwd, secondInput));
    const plan = buildRevalidationPlan(before, after);
    const output = path.resolve(cwd, valueFlag(args, "--output", path.join(path.dirname(path.resolve(cwd, secondInput)), "revalidation.json")));
    await writeJson(output, plan);
    if (flag(args, "--json")) console.log(JSON.stringify(plan, null, 2));
    else {
      console.log(`Revalidation ${plan.beforeRunId} -> ${plan.afterRunId}: ${plan.status}`);
      console.log(`Actions: ${plan.items.filter((item) => item.action !== "NO_ACTION").length}  blocking=${plan.blockingIdentities.length}`);
      for (const item of plan.items) console.log(`- [${item.action}] ${item.lifecycle} ${item.identity}: ${item.reason}`);
      console.log(`Artifact: ${output}`);
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

  if (command === "worker") {
    if (!input || (!secondInput && !flag(args, "--all"))) throw new Error("worker requires a run.json and task-id, or --all");
    const runPath = path.resolve(cwd, input);
    const run = await readJson<AuditRun>(runPath);
    const modelConfig = await loadModelConfig(run.root, valueFlag(args, "--config", ""));
    const registry = new ModelRegistry(modelConfig);
    const requestedModel = valueFlag(args, "--model", "auto");
    const cacheDirectory = path.join(path.dirname(runPath), "worker-cache");
    if (flag(args, "--all")) {
      const concurrency = Math.max(1, Math.min(8, Number(valueFlag(args, "--concurrency", "2")) || 2));
      const tasks = (run.plan?.tasks ?? []).filter((task) => ["HUNT", "INVESTIGATE"].includes(task.phase) && task.status === "PENDING").sort((left, right) => right.priority - left.priority || left.id.localeCompare(right.id));
      let cursor = 0;
      const results: AuditWorkerResult[] = [];
      const worker = async (): Promise<void> => {
        while (cursor < tasks.length) {
          const task = tasks[cursor++];
          const selected = registry.select({ phase: task.phase, priority: task.priority, estimatedInputTokens: 0, budgetTokens: task.budgetTokens, requiredCapabilities: [task.phase, "JSON"], model: requestedModel });
          try {
            results.push(await executeWorkerTask(run, task, registry, selected.id, { cacheDirectory }));
          } catch (error) {
            results.push({ worker: selected.id, taskId: task.id, error: error instanceof Error ? error.message : String(error), findings: [] });
          }
        }
      };
      await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(1, tasks.length)) }, () => worker()));
      let updated = run;
      for (const result of results.sort((left, right) => (left.taskId ?? "").localeCompare(right.taskId ?? ""))) updated = mergeWorkerResult(updated, result);
      const session = await persistRunArtifacts(path.dirname(runPath), updated);
      console.log(`Workers: ${results.length} tasks  concurrency=${concurrency}`);
      console.log(summarizeRun(updated, { session }));
      console.log(`Updated: ${runPath}`);
      return;
    }
    const task = run.plan?.tasks.find((candidate) => candidate.id === secondInput);
    if (!task) throw new Error(`Task not found: ${secondInput}`);
    if (task.phase === "VALIDATE") throw new Error("worker cannot run VALIDATE tasks; use verify/validate with an independent validator");
    if (["COMPLETED", "BLOCKED", "DEFERRED"].includes(task.status)) throw new Error(`Task ${task.id} is ${task.status} and cannot be run without a new plan/review.`);
    const selected = registry.select({ phase: task.phase, priority: task.priority, estimatedInputTokens: 0, budgetTokens: task.budgetTokens, requiredCapabilities: [task.phase, "JSON"], model: requestedModel });
    let result: AuditWorkerResult;
    try {
      result = await executeWorkerTask(run, task, registry, selected.id, { cacheDirectory });
    } catch (error) {
      result = { worker: selected.id, taskId: task.id, error: error instanceof Error ? error.message : String(error), findings: [] };
    }
    const updated = mergeWorkerResult(run, result);
    const session = await persistRunArtifacts(path.dirname(runPath), updated);
    console.log(`Worker: ${result.worker}  task=${task.id}${result.error ? `  error=${result.error}` : ""}`);
    console.log(summarizeRun(updated, { session }));
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
