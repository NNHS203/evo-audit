import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { detectFindings, maskNonCode } from "../src/detectors.js";
import { compareRuns } from "../src/compare.js";
import { initWorkspace, persistRunArtifacts, readJson, runAudit } from "../src/core.js";
import { defaultPlaybook } from "../src/playbook.js";
import { buildResumePlan } from "../src/resume.js";
import { toSarif } from "../src/sarif.js";
import type { AuditRun } from "../src/types.js";
import { applyValidationResult, assertWorkspaceMatchesSnapshot, validateResultAgainstRun } from "../src/validator.js";
import { mergeWorkerResult } from "../src/workers.js";
import { loadModelConfig, ModelRegistry } from "../src/models.js";
import { executePendingWorkerTasks, workerResultFromCompletion } from "../src/worker-runner.js";
import { runValidationRequest } from "../src/validation-runner.js";
import { deduplicateRun } from "../src/dedup.js";
import { buildRevalidationPlan } from "../src/revalidation.js";
import { evaluateBenchmark, runBenchmark, type BenchmarkReport } from "../src/benchmark.js";
import { groundTruthLabelsFromValue, scannerFindingsFromBandit, scannerFindingsFromSarif, scoreScannerFindings } from "../src/scoring.js";
import { runRealVulnAll } from "../src/realvuln.js";

test("candidate detection masks fixtures, comments, and descriptions but keeps code", () => {
  const source = [
    'const fixture = "eval(req.body.code)";',
    "// eval(req.body.code)",
    "const code = eval(req.body.code);",
  ].join("\n");
  const masked = maskNonCode(source).split(/\r?\n/);

  assert.doesNotMatch(masked[0], /eval\s*\(/);
  assert.doesNotMatch(masked[1], /eval\s*\(/);
  assert.match(masked[2], /eval\s*\(/);
});

test("detector creates a verification obligation without claiming proof", () => {
  const result = detectFindings(
    "src/route.ts",
    "export function run(req) { return exec(req.query.command); }\n",
    defaultPlaybook,
    "test-run",
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].status, "SUSPECTED");
  assert.equal(result.findings[0].evidenceTier, "T1_STATIC_PATH");
  assert.equal(result.obligations[0].status, "OPEN");
  assert.match(result.findings[0].limitations[0], /does not resolve/i);
});

test("run persists replayable evidence artifacts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-"));
  const output = path.join(root, "runs");
  await initWorkspace(root);
  await writeFile(path.join(root, "app.ts"), "export function run(req) { return eval(req.body.code); }\n", "utf8");

  const { run, artifactDir } = await runAudit(root, { output });
  assert.equal(run.schemaVersion, 1);
  assert.equal(run.findings.length, 1);
  assert.equal(run.findings[0].status, "SUSPECTED");
  assert.equal(run.tokenAccounting.source, "DETERMINISTIC");
  assert.equal(run.semanticDelta.basis, "FULL_SCAN");
  assert.deepEqual(run.semanticDelta.changed, ["app.ts"]);
  assert.deepEqual(run.reportableFindingIds, []);

  const initialSession = await readJson<{ total: { totalTokens: number }; runs: unknown[] }>(path.join(output, "session.json"));
  assert.equal(initialSession.total.totalTokens, 0);
  const workerUpdated = mergeWorkerResult(run, {
    worker: "usage-worker",
    findings: [],
    tokenAccounting: { inputTokens: 1200, outputTokens: 300, cachedTokens: 100, estimatedCostUsd: 0.04, durationMs: 40 },
  });
  const sessionAfterWorker = await persistRunArtifacts(artifactDir, workerUpdated);
  assert.equal(sessionAfterWorker.total.totalTokens, 1500);
  assert.equal(sessionAfterWorker.total.durationMs, 40);
  assert.equal(sessionAfterWorker.runs.length, 1);
  const sessionAfterReplay = await persistRunArtifacts(artifactDir, workerUpdated);
  assert.equal(sessionAfterReplay.total.totalTokens, 1500);

  const persisted = await readJson<AuditRun>(path.join(artifactDir, "run.json"));
  assert.equal(persisted.runId, run.runId);
  assert.equal((await readFile(path.join(artifactDir, "manifest.json"), "utf8")).includes(run.runId), true);
  assert.equal((await readFile(path.join(artifactDir, "recon.json"), "utf8")).includes("contextDigest"), true);
  assert.equal((await readFile(path.join(artifactDir, "plan.json"), "utf8")).includes("tokenBudget"), true);
  assert.equal(run.recon?.threatModel?.trustBoundaries.length, 4);
  assert.equal((await readFile(path.join(artifactDir, "threat-model.md"), "utf8")).includes("Threat Model, Trust Boundaries, and Assumptions"), true);
  assert.equal((await readFile(path.join(root, "audit.threat.json"), "utf8")).includes("schemaVersion"), true);
});

test("recon builds bounded graph context and the plan enforces the worker token budget", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-plan-"));
  await initWorkspace(root);
  await mkdir(path.join(root, "src"), { recursive: true });
  await writeFile(path.join(root, "package.json"), JSON.stringify({ scripts: { test: "node --test", build: "tsc" } }), "utf8");
  await writeFile(path.join(root, "src", "route.ts"), 'import { run } from "./danger.js";\nexport function route(req) { return run(req); }\n', "utf8");
  await writeFile(path.join(root, "src", "danger.ts"), "export function run(req) { return eval(req.body.code); }\n", "utf8");

  const config = JSON.parse(await readFile(path.join(root, "audit.config.json"), "utf8")) as { tokenBudget: number };
  config.tokenBudget = 900;
  await writeFile(path.join(root, "audit.config.json"), `${JSON.stringify(config)}\n`, "utf8");

  const { run } = await runAudit(root, { output: path.join(root, "runs") });
  assert.equal(run.recon?.projectKind, "NODE_TYPESCRIPT");
  assert.equal(run.recon?.manifests.includes("package.json"), true);
  assert.equal(run.recon?.moduleGraph.edges.some((edge) => edge.from === "src/route.ts" && edge.to === "src/danger.ts"), true);
  assert.equal(run.coverage.semantic, "STATIC_ONLY");
  assert.equal(run.plan?.tokenBudget, 900);
  assert.equal((run.plan?.allocatedTokens ?? 0) <= 900, true);
  assert.equal(run.plan?.tasks.some((task) => task.phase === "INVESTIGATE" && task.context.files.some((file) => file.path === "src/route.ts")), true);
  assert.equal(run.plan?.tasks.some((task) => task.phase === "VALIDATE" && task.status === "WAITING"), true);
  assert.equal(run.plan?.tasks.some((task) => task.phase === "HUNT" && task.findingId === null), true);
  assert.equal((run.recon?.coverageMatrix?.cells.length ?? 0) > 0, true);
  assert.equal(run.recon?.coverageMatrix?.cells.some((cell) => cell.status === "HUNT_REQUIRED"), true);
  assert.equal(run.plan?.tasks.some((task) => task.phase === "HUNT" && task.coverageCellId), true);

  const overBudget = mergeWorkerResult(run, {
    worker: "over-budget-worker",
    taskId: `investigate:${run.findings[0].id}`,
    findings: [],
    tokenAccounting: { inputTokens: 901, outputTokens: 1 },
  });
  assert.equal(overBudget.plan?.tasks.find((task) => task.id === `investigate:${run.findings[0].id}`)?.status, "BLOCKED");

  const firstWorkerTask = run.plan?.tasks.find((task) => task.phase === "INVESTIGATE" && task.status === "PENDING");
  assert.ok(firstWorkerTask);
  const afterFirstHunt = mergeWorkerResult(run, {
    worker: "budget-worker",
    taskId: firstWorkerTask.id,
    findings: [],
    tokenAccounting: { inputTokens: 400, outputTokens: 100 },
  });
  assert.equal((afterFirstHunt.plan?.allocatedTokens ?? 0) <= 900, true);
  const secondWorkerTask = afterFirstHunt.plan?.tasks.find((task) => ["HUNT", "INVESTIGATE"].includes(task.phase) && task.status === "PENDING");
  if (secondWorkerTask) {
    const afterSecondHunt = mergeWorkerResult(afterFirstHunt, {
      worker: "budget-worker",
      taskId: secondWorkerTask.id,
      findings: [],
      tokenAccounting: { inputTokens: 100, outputTokens: 100 },
    });
    assert.equal((afterSecondHunt.plan?.allocatedTokens ?? 0) <= 900, true);
  }
});

test("AST graph finds an indirect source-to-command-sink path without flagging a fixed command", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-graph-flow-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "indirect.ts"), [
    "import { exec } from 'node:child_process';",
    "export function run(req) {",
    "  const command = req.query.command;",
    "  return exec(command);",
    "}",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "fixed.ts"), "import { exec } from 'node:child_process';\nexport function run() { return exec('echo fixed'); }\n", "utf8");

  const { run } = await runAudit(root, { output: path.join(root, "runs") });
  const flow = run.recon?.codeGraph?.flows ?? [];
  assert.equal(flow.length, 1);
  assert.equal(run.recon?.codeGraph?.stats.flows, 1);
  const graphFinding = run.findings.find((finding) => finding.ruleId === "JS-COMMAND-INJECTION-001");
  assert.ok(graphFinding);
  assert.equal(graphFinding.locations.length, 2);
  assert.equal(graphFinding.locations[0].file, "indirect.ts");
  assert.equal(graphFinding.locations[1].file, "indirect.ts");
  assert.match(graphFinding.evidence[0].title, /AST data-flow/i);
});

test("AST graph resolves imported helper chains without linking unrelated same-name functions", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-graph-imports-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "danger.ts"), [
    "import { exec } from 'node:child_process';",
    "function inner(value) { return exec(value); }",
    "export function runCommand(value) { return inner(value); }",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "safe.ts"), "export function runCommand(value) { return String(value); }\n", "utf8");
  await writeFile(path.join(root, "routes.ts"), [
    "import { runCommand as dangerous } from './danger.js';",
    "import { runCommand as safe } from './safe.js';",
    "export function handler(req) { return dangerous(req.query.command) + safe(req.query.command); }",
  ].join("\n"), "utf8");

  const { run } = await runAudit(root, { output: path.join(root, "runs") });
  const graphFinding = run.findings.find((finding) => finding.ruleId === "JS-COMMAND-INJECTION-001");
  assert.ok(graphFinding);
  assert.equal(run.recon?.codeGraph?.flows.length, 1);
  assert.equal(graphFinding.locations.some((location) => location.file === "danger.ts"), true);
  assert.equal(graphFinding.locations.some((location) => location.file === "routes.ts"), true);
});

test("HUNT completion records unknown coverage and schedules a bounded second pass", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-gapfill-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "safe.ts"), "export const safe = true;\n", "utf8");
  const initial = await runAudit(root, { output: path.join(root, "runs") });
  const hunt = initial.run.plan?.tasks.find((task) => task.phase === "HUNT" && task.status === "PENDING");
  assert.ok(hunt?.coverageCellId);
  const after = mergeWorkerResult(initial.run, { worker: "gapfill-worker", taskId: hunt.id, findings: [] });
  const cell = after.recon?.coverageMatrix?.cells.find((candidate) => candidate.id === hunt.coverageCellId);
  assert.equal(cell?.status, "UNKNOWN");
  assert.equal(cell?.attempts, 1);
  assert.equal(after.plan?.tasks.some((task) => task.phase === "HUNT" && task.coverageCellId === hunt.coverageCellId && task.id.endsWith(":pass:1")), true);
});

test("worker receipts make replayed model output token-idempotent", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-worker-receipt-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "safe.ts"), "export const safe = true;\n", "utf8");
  const initial = await runAudit(root, { output: path.join(root, "runs") });
  const first = mergeWorkerResult(initial.run, {
    worker: "receipt-worker",
    taskId: initial.run.plan?.tasks.find((task) => task.phase === "HUNT")?.id,
    receiptId: "receipt-1",
    findings: [],
    tokenAccounting: { inputTokens: 100, outputTokens: 20, cachedTokens: 0, estimatedCostUsd: 0.01 },
  });
  const replay = mergeWorkerResult(first, {
    worker: "receipt-worker",
    taskId: first.plan?.tasks.find((task) => task.phase === "HUNT")?.id,
    receiptId: "receipt-1",
    findings: [],
    tokenAccounting: { inputTokens: 100, outputTokens: 20, cachedTokens: 0, estimatedCostUsd: 0.01 },
  });
  assert.equal(first.tokenAccounting.inputTokens, 100);
  assert.equal(replay.tokenAccounting.inputTokens, 100);
  assert.equal(replay.workerReceipts?.length, 1);
});

test("model registry loads API/OAuth references and routes auto tasks without exposing secrets", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-models-"));
  const keyName = "EVO_AUDIT_TEST_PROVIDER_KEY";
  process.env[keyName] = "test-secret";
  await writeFile(path.join(root, "audit.models.json"), JSON.stringify({
    schemaVersion: 1,
    auto: { enabled: true, preferred: ["frontier"], minimumQualityTier: 2 },
    models: [
      {
        id: "frontier",
        transport: "OPENAI_COMPATIBLE",
        model: "frontier-test",
        baseUrl: "https://example.invalid/v1",
        auth: { method: "API_KEY", apiKeyEnv: keyName },
        qualityTier: 5,
        capabilities: ["HUNT", "INVESTIGATE", "VALIDATE", "JSON"],
      },
      {
        id: "oauth",
        transport: "OPENAI_COMPATIBLE",
        model: "oauth-test",
        baseUrl: "https://example.invalid/v1",
        auth: { method: "OAUTH", tokenFile: path.join(root, "missing-token.json"), oauth: { authorizationUrl: "https://example.invalid/authorize", tokenUrl: "https://example.invalid/token", clientId: "client", scopes: [] } },
        qualityTier: 4,
        capabilities: ["HUNT", "INVESTIGATE", "JSON"],
      },
    ],
  }, null, 2), "utf8");
  try {
    const config = await loadModelConfig(root);
    const registry = new ModelRegistry(config);
    const statuses = await registry.statuses();
    assert.equal(statuses.find((model) => model.id === "frontier")?.credentialAvailable, true);
    assert.equal(statuses.find((model) => model.id === "oauth")?.credentialAvailable, false);
    assert.equal(registry.select({ phase: "HUNT", priority: 100, estimatedInputTokens: 500, budgetTokens: 4000 }).id, "frontier");
    await registry.assertReady("frontier");
    await assert.rejects(() => registry.assertReady("oauth"), /No usable credential/i);
  } finally {
    delete process.env[keyName];
  }

  await writeFile(path.join(root, "invalid.models.json"), JSON.stringify({
    schemaVersion: 1,
    auto: { enabled: true },
    models: [{ id: "unsafe", transport: "OPENAI_COMPATIBLE", model: "x", baseUrl: "https://example.invalid", auth: { method: "API_KEY", apiKey: "raw-secret" }, qualityTier: 1, capabilities: ["HUNT", "JSON"] }],
  }), "utf8");
  await assert.rejects(() => loadModelConfig(root, "invalid.models.json"), /raw credential/i);
});

test("worker protocol rejects malformed model JSON and blocks the task", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-worker-protocol-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "safe.ts"), "export const safe = true;\n", "utf8");
  const { run } = await runAudit(root, { output: path.join(root, "runs") });
  const task = run.plan?.tasks.find((candidate) => candidate.phase === "HUNT" && candidate.status === "PENDING");
  assert.ok(task);
  const result = workerResultFromCompletion({
    requestId: "malformed-1",
    modelId: "test-model",
    providerModel: "test",
    text: "not json",
    usage: { inputTokens: 20, outputTokens: 4, cachedTokens: 0, estimatedCostUsd: 0, source: "WORKER_REPORTED" },
  }, task);
  assert.match(result.error ?? "", /valid JSON/i);
  const blocked = mergeWorkerResult(run, result);
  assert.equal(blocked.plan?.tasks.find((candidate) => candidate.id === task.id)?.status, "BLOCKED");
});

test("worker validation proposals remain inert and bounded", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-worker-proposal-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "safe.ts"), "export const safe = true;\n", "utf8");
  const { run } = await runAudit(root, { output: path.join(root, "runs") });
  const task = run.plan?.tasks.find((candidate) => candidate.phase === "HUNT" && candidate.status === "PENDING");
  assert.ok(task);
  const result = workerResultFromCompletion({
    requestId: "proposal-1",
    modelId: "test-model",
    providerModel: "test",
    text: JSON.stringify({ findings: [{
      ruleId: "MODEL-CANDIDATE-001",
      title: "Model candidate",
      status: "VERIFIED",
      evidenceTier: "T2_REPRODUCIBLE",
      locations: [{ file: "safe.ts", line: 1, column: 1, endLine: 1, snippet: "export const safe = true;" }],
      proposedValidation: { reproducerCommand: "node -e \"process.exit(0)\"", negativeControlCommand: "node -e \"process.exit(0)\"", timeoutMs: 500 },
    }] }),
    usage: { inputTokens: 20, outputTokens: 12, cachedTokens: 0, estimatedCostUsd: 0, source: "WORKER_REPORTED" },
  }, task);
  const merged = mergeWorkerResult(run, result);
  assert.equal(merged.findings.some((finding) => finding.proposedValidation?.reproducerCommand.includes("process.exit(0)")), true);
  assert.equal(merged.findings.some((finding) => finding.status === "VERIFIED"), false);

  const bounded = workerResultFromCompletion({
    requestId: "proposal-2",
    modelId: "test-model",
    providerModel: "test",
    text: JSON.stringify({ findings: [{
      ruleId: "MODEL-CANDIDATE-002",
      title: "Oversized proposal",
      status: "SUSPECTED",
      evidenceTier: "T0_HYPOTHESIS",
      proposedValidation: { reproducerCommand: "x".repeat(4_001), negativeControlCommand: "node -e \"process.exit(0)\"" },
    }] }),
    usage: { inputTokens: 20, outputTokens: 12, cachedTokens: 0, estimatedCostUsd: 0, source: "WORKER_REPORTED" },
  }, task);
  assert.equal(bounded.findings[0].proposedValidation, undefined);

  const impossible = workerResultFromCompletion({
    requestId: "proposal-3",
    modelId: "test-model",
    providerModel: "test",
    text: JSON.stringify({ findings: [{
      ruleId: "MODEL-CANDIDATE-003",
      title: "Impossible location",
      status: "SUPPORTED",
      evidenceTier: "T1_STATIC_PATH",
      locations: [{ file: "safe.ts", line: 99, column: 1, endLine: 99, snippet: "not in snapshot" }],
    }] }),
    usage: { inputTokens: 20, outputTokens: 12, cachedTokens: 0, estimatedCostUsd: 0, source: "WORKER_REPORTED" },
  }, task);
  const sanitized = mergeWorkerResult(run, impossible);
  const impossibleFinding = sanitized.findings.find((finding) => finding.ruleId === "MODEL-CANDIDATE-003");
  assert.ok(impossibleFinding);
  assert.deepEqual(impossibleFinding.locations, []);
  assert.match(impossibleFinding.limitations.join(" "), /outside the fingerprinted snapshot|line count/i);
});

test("pending worker queue runs HUNT before a bounded INVESTIGATE pass", async () => {
  const server = createServer((_request, response) => {
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ id: "queue-worker", choices: [{ message: { content: "{\"findings\":[],\"notes\":[\"no candidate\"]}" }, finish_reason: "stop" }], usage: { prompt_tokens: 20, completion_tokens: 5 } }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-worker-queue-"));
  try {
    await initWorkspace(root);
    await writeFile(path.join(root, "safe.ts"), "export const safe = true;\n", "utf8");
    const { run } = await runAudit(root, { output: path.join(root, "runs") });
    const registry = new ModelRegistry({
      schemaVersion: 1,
      auto: { enabled: true, preferred: ["local"], minimumQualityTier: 1 },
      models: [{ id: "local", transport: "OPENAI_COMPATIBLE", model: "test", baseUrl: `http://127.0.0.1:${address.port}`, auth: { method: "NONE" }, qualityTier: 3, capabilities: ["HUNT", "INVESTIGATE", "JSON"] }],
    });
    const queued = await executePendingWorkerTasks(run, registry, { model: "local", maxTasks: 2, concurrency: 2, cacheDirectory: path.join(root, "cache") });
    assert.equal(queued.results.length, 2);
    assert.equal(queued.results.every((item) => !item.error), true);
    assert.equal(queued.run.tokenAccounting.inputTokens, 40);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("OpenAI-compatible provider normalizes completion text and token usage", async () => {
  const server = createServer((_request, response) => {
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ id: "provider-test-1", choices: [{ message: { content: "{\"findings\":[]}" }, finish_reason: "stop" }], usage: { prompt_tokens: 40, completion_tokens: 12, prompt_tokens_details: { cached_tokens: 8 } } }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    const registry = new ModelRegistry({
      schemaVersion: 1,
      auto: { enabled: true, preferred: ["local"], minimumQualityTier: 1 },
      models: [{ id: "local", transport: "OPENAI_COMPATIBLE", model: "test", baseUrl: `http://127.0.0.1:${address.port}`, auth: { method: "NONE" }, qualityTier: 3, capabilities: ["HUNT", "JSON"] }],
    });
    const response = await registry.complete({ phase: "HUNT", priority: 80, estimatedInputTokens: 20, budgetTokens: 400, messages: [{ role: "user", content: "test" }] });
    assert.equal(response.text, "{\"findings\":[]}");
    assert.equal(response.requestId, "provider-test-1");
    assert.deepEqual({ ...response.usage, durationMs: undefined }, { inputTokens: 40, outputTokens: 12, cachedTokens: 8, estimatedCostUsd: 0, durationMs: undefined, source: "WORKER_REPORTED" });
    assert.equal(typeof response.usage.durationMs, "number");
    assert.equal(response.usage.durationMs! >= 0, true);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("validation runner fails closed for an unsupported sandbox profile", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-validation-runner-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "safe.ts"), "export const safe = true;\n", "utf8");
  const { run } = await runAudit(root, { output: path.join(root, "runs") });
  const result = await runValidationRequest(run, {
    schemaVersion: 1,
    requestId: "invalid-sandbox-1",
    runId: run.runId,
    findingId: "missing",
    baseTreeDigest: run.snapshot.treeDigest,
    targetFiles: [],
    reproducerCommand: "echo should-not-run",
    negativeControlCommand: "echo should-not-run",
    timeoutMs: 1000,
    sandboxProfile: "HOST_UNSAFE" as never,
  }, "test-validator");
  assert.equal(result.outcome, "HARNESS_FAILED");
  assert.match(result.notes?.[0] ?? "", /Unsupported sandbox/i);
});

test("dedup keeps the strongest finding and closes only the duplicate obligation", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-dedup-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "app.ts"), "export function run(req) { return eval(req.body.code); }\n", "utf8");
  const { run } = await runAudit(root, { output: path.join(root, "runs") });
  const original = run.findings[0];
  const duplicate = structuredClone(original);
  duplicate.id = `${original.id}-worker-copy`;
  duplicate.obligationId = `${original.obligationId}-worker-copy`;
  duplicate.status = "SUPPORTED";
  run.findings.push(duplicate);
  run.obligations.push({ ...run.obligations[0], id: duplicate.obligationId, status: "OPEN" });
  run.reportableFindingIds = [original.id, duplicate.id];

  const deduped = deduplicateRun(run);
  assert.equal(deduped.dedup?.groups.length, 1);
  assert.equal(deduped.dedup?.groups[0].canonicalFindingId, duplicate.id);
  assert.equal(deduped.findings.find((finding) => finding.id === original.id)?.status, "DUPLICATE");
  assert.equal(deduped.findings.find((finding) => finding.id === duplicate.id)?.status, "SUPPORTED");
  assert.equal(deduped.obligations.find((obligation) => obligation.id === original.obligationId)?.status, "REJECTED");
  assert.deepEqual(deduped.reportableFindingIds, [duplicate.id]);
});

test("strict mode does not promote static candidates", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-strict-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "app.ts"), "export function run(req) { return eval(req.body.code); }\n", "utf8");

  const { run } = await runAudit(root, { output: path.join(root, "runs"), strict: true });
  assert.equal(run.findings.length, 1);
  assert.deepEqual(run.reportableFindingIds, []);
});

test("worker ingestion requires reproducible evidence before VERIFIED", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-worker-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "app.ts"), "export function run(req) { return eval(req.body.code); }\n", "utf8");

  const { run } = await runAudit(root, { output: path.join(root, "runs") });
  const candidate = run.findings[0];
  const unsupported = mergeWorkerResult(run, {
    worker: "mock-frontier",
    findings: [
      {
        ruleId: candidate.ruleId,
        obligationId: candidate.obligationId,
        title: candidate.title,
        status: "VERIFIED",
        evidenceTier: "T2_REPRODUCIBLE",
        locations: candidate.locations,
        evidence: [
          {
            type: "TRACE",
            title: "Worker trace",
            detail: "The value reaches eval.",
            reproducible: false,
          },
        ],
      },
    ],
  });
  assert.equal(unsupported.findings[0].status, "SUPPORTED");
  assert.equal(unsupported.plan?.tasks.find((task) => task.phase === "INVESTIGATE" && task.findingId === candidate.id)?.status, "COMPLETED");
  assert.equal(unsupported.plan?.tasks.find((task) => task.phase === "VALIDATE" && task.findingId === candidate.id)?.status, "PENDING");

  const workerClaim = mergeWorkerResult(unsupported, {
    worker: "mock-frontier",
    findings: [
      {
        ruleId: candidate.ruleId,
        obligationId: candidate.obligationId,
        title: candidate.title,
        status: "VERIFIED",
        evidenceTier: "T2_REPRODUCIBLE",
        locations: candidate.locations,
        evidence: [
          {
            type: "REPRODUCER",
            title: "Isolated reproducer",
            detail: "The isolated test demonstrates code execution from the request body.",
            reproducible: true,
          },
        ],
      },
    ],
    tokenAccounting: { inputTokens: 1200, outputTokens: 300, cachedTokens: 100, estimatedCostUsd: 0.04 },
  });
  assert.equal(workerClaim.findings[0].status, "SUPPORTED");
  assert.notEqual(workerClaim.findings[0].evidenceTier, "T2_REPRODUCIBLE");
  assert.equal(workerClaim.tokenAccounting.inputTokens, 1200);
  assert.equal(workerClaim.tokenAccounting.source, "WORKER_REPORTED");

  const validation = applyValidationResult(workerClaim, {
    schemaVersion: 1 as const,
    validator: "mock-validator",
    requestId: "validation-1",
    runId: workerClaim.runId,
    findingId: candidate.id,
    outcome: "VERIFIED",
    baseTreeDigest: workerClaim.snapshot.treeDigest,
    sourceFiles: workerClaim.files,
    sandbox: { profile: "READ_ONLY_NO_NETWORK", readOnlySource: true, network: "DENY" },
    reproducer: {
      command: "node isolated-reproducer.js",
      exitCode: 0,
      timedOut: false,
      passed: true,
      stdoutDigest: "stdout-digest",
      stderrDigest: "stderr-digest",
    },
    negativeControl: {
      command: "node isolated-negative-control.js",
      exitCode: 1,
      timedOut: false,
      passed: true,
      stdoutDigest: "negative-stdout",
      stderrDigest: "negative-stderr",
    },
  });
  assert.equal(validation.gate.accepted, true);
  assert.equal(validation.run.findings[0].status, "VERIFIED");
  assert.equal(validation.run.obligations.find((obligation) => obligation.id === candidate.obligationId)?.status, "SATISFIED");
  assert.equal(validation.run.plan?.tasks.find((task) => task.phase === "VALIDATE" && task.findingId === candidate.id)?.status, "COMPLETED");
  assert.equal(validation.run.recon?.coverageMatrix?.cells.some((cell) => cell.ruleId === candidate.ruleId && cell.status === "VALIDATED"), true);

  const hallucinated = mergeWorkerResult(validation.run, {
    worker: "hallucinating-worker",
    findings: [
      {
        ruleId: "FAKE-LOCATION-001",
        title: "Unmapped worker claim",
        status: "VERIFIED",
        evidenceTier: "T2_REPRODUCIBLE",
        locations: [{ file: "missing.ts", line: 1, column: 1, endLine: 1, snippet: "missing" }],
        evidence: [
          {
            type: "REPRODUCER",
            title: "Claimed reproducer",
            detail: "The worker claims a reproducer outside the scanned scope.",
            reproducible: true,
          },
        ],
      },
    ],
  });
  assert.equal(hallucinated.findings.at(-1)?.status, "SUSPECTED");
});

test("baseline runs expose a semantic file delta without narrowing coverage", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-delta-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "app.ts"), "export const safe = true;\n", "utf8");
  const first = await runAudit(root, { output: path.join(root, "runs-first") });

  await writeFile(path.join(root, "app.ts"), "export const safe = false;\n", "utf8");
  await writeFile(path.join(root, "new.ts"), "export const added = true;\n", "utf8");
  const second = await runAudit(root, { output: path.join(root, "runs-second"), baseline: first.run });

  assert.equal(second.run.semanticDelta.basis, "BASELINE_RUN");
  assert.deepEqual(second.run.semanticDelta.changed, ["app.ts"]);
  assert.deepEqual(second.run.semanticDelta.added, ["new.ts"]);
  assert.deepEqual(second.run.semanticDelta.removed, []);
  assert.equal(second.run.files.length, 2);
});

test("validator independence and evidence locations are enforced", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-validator-boundary-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "app.ts"), "export function run(req) { return eval(req.body.code); }\n", "utf8");
  const initial = await runAudit(root, { output: path.join(root, "runs") });
  const workerRun = mergeWorkerResult(initial.run, {
    worker: "mock-worker",
    findings: [
      {
        ruleId: initial.run.findings[0].ruleId,
        obligationId: initial.run.findings[0].obligationId,
        title: initial.run.findings[0].title,
        status: "SUPPORTED",
        evidenceTier: "T1_STATIC_PATH",
        locations: initial.run.findings[0].locations,
      },
    ],
  });
  const valid = {
    schemaVersion: 1 as const,
    validator: "independent-validator",
    requestId: "boundary-1",
    runId: workerRun.runId,
    findingId: workerRun.findings[0].id,
    outcome: "VERIFIED" as const,
    baseTreeDigest: workerRun.snapshot.treeDigest,
    sourceFiles: workerRun.files,
    sandbox: { profile: "READ_ONLY_NO_NETWORK" as const, readOnlySource: true, network: "DENY" as const },
    reproducer: { command: "reproduce", exitCode: 0, timedOut: false, passed: true, stdoutDigest: "a", stderrDigest: "b" },
    negativeControl: { command: "negative", exitCode: 1, timedOut: false, passed: true, stdoutDigest: "c", stderrDigest: "d" },
  };
  assert.equal(validateResultAgainstRun(workerRun, valid).accepted, true);
  assert.equal(validateResultAgainstRun(workerRun, { ...valid, validator: "mock-worker" }).accepted, false);
  assert.equal(validateResultAgainstRun(workerRun, {
    ...valid,
    evidence: [{ type: "TRACE", title: "out of scope", detail: "outside", reproducible: false, locations: [{ file: "outside.ts", line: 1, column: 1, endLine: 1, snippet: "outside" }] }],
  }).accepted, false);
});

test("validator rejects stale snapshots before a claim can become VERIFIED", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-stale-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "app.ts"), "export function run(req) { return eval(req.body.code); }\n", "utf8");
  const { run } = await runAudit(root, { output: path.join(root, "runs") });
  await writeFile(path.join(root, "app.ts"), "export const changed = true;\n", "utf8");

  const validationResult = {
    schemaVersion: 1,
    validator: "stale-validator",
    requestId: "stale-1",
    runId: run.runId,
    findingId: run.findings[0].id,
    outcome: "VERIFIED",
    baseTreeDigest: run.snapshot.treeDigest,
    sourceFiles: run.files,
    sandbox: { profile: "READ_ONLY_NO_NETWORK", readOnlySource: true, network: "DENY" },
    reproducer: { command: "reproduce", exitCode: 0, timedOut: false, passed: true, stdoutDigest: "a", stderrDigest: "b" },
    negativeControl: { command: "negative", exitCode: 1, timedOut: false, passed: true, stdoutDigest: "c", stderrDigest: "d" },
  } as const;
  const integrity = await assertWorkspaceMatchesSnapshot(run);
  assert.equal(integrity.ok, false);
  assert.deepEqual(integrity.changed, ["app.ts"]);
  const applied = applyValidationResult(run, {
    ...validationResult,
    outcome: "HARNESS_FAILED",
    notes: [`Workspace changed after snapshot: ${integrity.changed.join(", ")}`],
  });
  assert.equal(applied.run.findings[0].status, "HARNESS_FAILED");
});

test("compare, SARIF, and resume artifacts preserve audit state", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-reporting-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "app.ts"), "export function run(req) { return eval(req.body.code); }\n", "utf8");
  const before = await runAudit(root, { output: path.join(root, "runs-before") });
  await writeFile(path.join(root, "app.ts"), "export const safe = true;\n", "utf8");
  const after = await runAudit(root, { output: path.join(root, "runs-after"), baseline: before.run });

  const comparison = compareRuns(before.run, after.run);
  assert.equal(comparison.findings[0].lifecycle, "RESOLVED");
  const verifiedBefore = applyValidationResult(before.run, {
    schemaVersion: 1,
    validator: "independent-validator",
    requestId: "compare-validation",
    runId: before.run.runId,
    findingId: before.run.findings[0].id,
    outcome: "VERIFIED",
    baseTreeDigest: before.run.snapshot.treeDigest,
    sourceFiles: before.run.files,
    sandbox: { profile: "READ_ONLY_NO_NETWORK", readOnlySource: true, network: "DENY" },
    reproducer: { command: "reproduce", exitCode: 0, timedOut: false, passed: true, stdoutDigest: "a", stderrDigest: "b" },
    negativeControl: { command: "negative", exitCode: 1, timedOut: false, passed: true, stdoutDigest: "c", stderrDigest: "d" },
  });
  assert.equal(compareRuns(verifiedBefore.run, after.run).findings[0].lifecycle, "UNKNOWN");
  const sarif = toSarif(before.run) as { runs: Array<{ results: Array<{ level: string; properties: { reportable: boolean } }> }> };
  assert.equal(sarif.runs[0].results.length, 1);
  assert.equal(sarif.runs[0].results[0].level, "note");
  assert.equal(sarif.runs[0].results[0].properties.reportable, false);
  const plan = buildResumePlan(before.run);
  assert.equal(plan.pendingObligations.length, 1);
  assert.equal(plan.findingsToValidate.length, 1);
});

test("revalidation keeps a disappeared verified finding actionable", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-revalidation-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "app.ts"), "export function run(req) { return eval(req.body.code); }\n", "utf8");
  const before = await runAudit(root, { output: path.join(root, "before") });
  const verified = applyValidationResult(before.run, {
    schemaVersion: 1,
    validator: "independent-validator",
    requestId: "revalidation-before",
    runId: before.run.runId,
    findingId: before.run.findings[0].id,
    outcome: "VERIFIED",
    baseTreeDigest: before.run.snapshot.treeDigest,
    sourceFiles: before.run.files,
    sandbox: { profile: "READ_ONLY_NO_NETWORK", readOnlySource: true, network: "DENY" },
    reproducer: { command: "reproduce", exitCode: 0, timedOut: false, passed: true, stdoutDigest: "a", stderrDigest: "b" },
    negativeControl: { command: "negative", exitCode: 1, timedOut: false, passed: true, stdoutDigest: "c", stderrDigest: "d" },
  });
  await writeFile(path.join(root, "app.ts"), "export const safe = true;\n", "utf8");
  const after = await runAudit(root, { output: path.join(root, "after"), baseline: before.run });
  const plan = buildRevalidationPlan(verified.run, after.run);
  assert.equal(plan.status, "ACTION_REQUIRED");
  assert.equal(plan.items.some((item) => item.lifecycle === "UNKNOWN" && item.action === "REVALIDATE"), true);
  assert.equal(plan.requiredFindingIds.includes(before.run.findings[0].id), true);
});

test("benchmark acceptance gate is explicit about metric regressions", () => {
  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    split: "development",
    cases: [],
    metrics: {
      cases: 2,
      expectedVulnerable: 1,
      candidateRecall: 1,
      candidatePrecision: 0.5,
      falsePositiveRate: 0.5,
      matchingCandidateRecall: 1,
      reportableRecall: 0,
      validatedFindingRate: 0,
      unsupportedClaimRate: 0,
      unknownCoverageRate: 1,
      tokensPerCase: 0,
      tokensPerValidatedFinding: null,
      durationMsPerCase: 10,
    },
    notes: [],
  } satisfies BenchmarkReport;
  assert.equal(evaluateBenchmark(report, { minCandidateRecall: 1, minCandidatePrecision: 0.9, maxFalsePositiveRate: 0, minReportableRecall: 1 }).accepted, false);
  assert.equal(evaluateBenchmark(report, { minCandidateRecall: 1, minCandidatePrecision: 0.5, maxFalsePositiveRate: 0.5 }).accepted, true);
});

test("model-backed benchmark reuses the same bounded worker protocol", async () => {
  const server = createServer((_request, response) => {
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ id: "benchmark-worker", choices: [{ message: { content: "{\"findings\":[],\"notes\":[\"no candidate\"]}" }, finish_reason: "stop" }], usage: { prompt_tokens: 30, completion_tokens: 6 } }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    const report = await runBenchmark(path.join(process.cwd(), "benchmark", "cases"), "development", {
      model: "local",
      maxModelTasks: 1,
      modelConfig: {
        schemaVersion: 1,
        auto: { enabled: true, preferred: ["local"], minimumQualityTier: 1 },
        models: [{ id: "local", transport: "OPENAI_COMPATIBLE", model: "test", baseUrl: `http://127.0.0.1:${address.port}`, auth: { method: "NONE" }, qualityTier: 3, capabilities: ["HUNT", "INVESTIGATE", "JSON"] }],
      },
    });
    assert.equal(report.notes.some((note) => /model-backed worker mode/i.test(note)), true);
    assert.equal(report.cases.every((item) => item.tokenTotal > 0), true);
    assert.equal(report.metrics.reportableRecall, 0);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("scanner scoring separates candidate and evidence-gated reportable performance", () => {
  const labels = [
    { id: "vuln-1", vulnerable: true, file: "src/app.ts", startLine: 10, ruleIds: ["RULE-1"] },
    { id: "trap-1", vulnerable: false, file: "src/app.ts", startLine: 30, ruleIds: ["RULE-1"] },
  ];
  const sarif = {
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "external-scanner" } }, results: [
      { ruleId: "RULE-1", locations: [{ physicalLocation: { artifactLocation: { uri: "src/app.ts" }, region: { startLine: 10 } } }], properties: { reportable: true } },
      { ruleId: "RULE-1", locations: [{ physicalLocation: { artifactLocation: { uri: "src/app.ts" }, region: { startLine: 30 } } }], properties: { reportable: false } },
    ] }],
  };
  const findings = scannerFindingsFromSarif(sarif);
  const score = scoreScannerFindings(findings, labels, { inputTokens: 100, outputTokens: 20, durationMs: 50 });
  assert.equal(score.candidate.truePositive, 1);
  assert.equal(score.candidate.falsePositive, 1);
  assert.equal(score.candidate.recall, 1);
  assert.equal(score.reportable.truePositive, 1);
  assert.equal(score.reportable.falsePositive, 0);
  assert.equal(score.reportable.tokensPerValidatedFinding, 120);
  const realVulnLabels = groundTruthLabelsFromValue({ findings: [{ id: "rv-1", is_vulnerable: true, file: "src/app.ts", location: { start_line: 10, end_line: 12 }, primary_cwe: "CWE-79", acceptable_cwes: ["CWE-79", "CWE-80"] }] }, "REALVULN");
  assert.deepEqual(realVulnLabels[0], { id: "rv-1", vulnerable: true, file: "src/app.ts", startLine: 10, endLine: 12, ruleIds: ["CWE-79", "CWE-80"] });
  const alternateLocation = groundTruthLabelsFromValue({ findings: [{ id: "rv-2", is_vulnerable: true, file: "src/app.ts", location: { start_line: 10 }, acceptable_locations: [{ file: "src/model.ts", start_line: 26, end_line: 30 }] }] }, "REALVULN");
  const alternateFinding = scannerFindingsFromSarif({ version: "2.1.0", runs: [{ results: [{ ruleId: "RULE-2", locations: [{ physicalLocation: { artifactLocation: { uri: "src/model.ts" }, region: { startLine: 27 } } }], properties: { reportable: true } }] }] });
  assert.equal(scoreScannerFindings(alternateFinding, alternateLocation).candidate.truePositive, 1);
  const banditFindings = scannerFindingsFromBandit({ results: [{ filename: path.join(process.cwd(), "app.py"), line_number: 16, line_range: [16], test_id: "B608", issue_cwe: { id: 89 } }] }, "bandit", process.cwd());
  assert.deepEqual(banditFindings[0]?.ruleIds, ["B608", "CWE-89"]);
  assert.equal(scoreScannerFindings(banditFindings, [{ id: "sql", vulnerable: true, file: "app.py", startLine: 16, ruleIds: ["CWE-89"] }]).candidate.truePositive, 1);
  const collisionLabels = [
    { id: "xxe", vulnerable: true, file: "app.py", startLine: 157, ruleIds: ["CWE-611", "CWE-306"] },
    { id: "auth", vulnerable: true, file: "app.py", startLine: 152, ruleIds: ["CWE-306", "CWE-862"] },
  ];
  const collisionFindings = [
    { id: "auth-finding", scanner: "evo-audit", ruleId: "PY-MISSING-AUTH-001", ruleIds: ["PY-MISSING-AUTH-001", "CWE-306", "CWE-862"], locations: [{ file: "app.py", startLine: 152, endLine: 152 }], reportable: false, unsupportedClaim: false },
    { id: "xxe-finding", scanner: "evo-audit", ruleId: "PY-XXE-001", ruleIds: ["PY-XXE-001", "CWE-611"], locations: [{ file: "app.py", startLine: 157, endLine: 157 }], reportable: false, unsupportedClaim: false },
  ];
  const collisionScore = scoreScannerFindings(collisionFindings, collisionLabels);
  assert.equal(collisionScore.candidate.truePositive, 2);
  assert.equal(collisionScore.candidate.falsePositive, 0);
});

test("RealVuln aggregate records malformed manifest entries as blocked", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-realvuln-aggregate-"));
  await writeFile(path.join(root, "benchmark-manifest.json"), JSON.stringify({
    schema_version: "1",
    benchmark_version: "2.0.0",
    repos: { malformed: { repo_url: "https://example.invalid/repo", commit_sha: "short" } },
  }), "utf8");

  const aggregate = await runRealVulnAll(root, { output: path.join(root, "runs") });
  assert.equal(aggregate.repositories, 1);
  assert.equal(aggregate.completed, 0);
  assert.equal(aggregate.blocked, 1);
  assert.equal(aggregate.entries[0]?.status, "BLOCKED");
  assert.match(aggregate.entries[0]?.error ?? "", /full commit SHA/i);
  assert.equal((await readFile(path.join(root, "runs", "realvuln-aggregate.json"), "utf8")).includes('"status": "BLOCKED"'), true);
});

test("benchmark runner can audit a pinned-style local checkout source", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-benchmark-checkout-"));
  const casesDirectory = path.join(root, "cases");
  const checkout = path.join(root, "checkout");
  await mkdir(casesDirectory, { recursive: true });
  await mkdir(checkout, { recursive: true });
  await writeFile(path.join(checkout, "app.ts"), "export function run(req) { return eval(req.body.code); }\n", "utf8");
  execFileSync("git", ["init", "-q"], { cwd: checkout, stdio: "ignore" });
  execFileSync("git", ["-c", "user.name=Evo Audit Test", "-c", "user.email=evo-audit@example.invalid", "add", "app.ts"], { cwd: checkout, stdio: "ignore" });
  execFileSync("git", ["-c", "user.name=Evo Audit Test", "-c", "user.email=evo-audit@example.invalid", "commit", "-qm", "fixture"], { cwd: checkout, stdio: "ignore" });
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: checkout, encoding: "utf8" }).trim();
  await writeFile(path.join(casesDirectory, "checkout-case.json"), JSON.stringify({
    schemaVersion: 1,
    caseId: "local-checkout-001",
    split: "development",
    language: "typescript",
    source: { kind: "CHECKOUT", path: "../checkout", repository: "local-fixture", commit },
    property: "A checkout source remains auditable without embedding its code in the case JSON.",
    expected: { vulnerable: true, ruleId: "JS-DYNAMIC-CODE-001" },
  }), "utf8");
  const report = await runBenchmark(casesDirectory, "development");
  assert.equal(report.cases[0].sourceKind, "CHECKOUT");
  assert.equal(report.cases[0].sourceTreeDigest.length, 64);
  assert.equal(report.cases[0].candidateFound, true);
});

test("Python graph tracks local assignments and helper summaries without flagging fixed commands", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-python-graph-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "app.py"), [
    "from flask import request",
    "import subprocess",
    "",
    "def run(value):",
    "    return subprocess.run(value, shell=True)",
    "",
    "def route():",
    "    command = request.args.get('command')",
    "    return run(command)",
    "",
    "def safe():",
    "    return subprocess.run(['echo', 'fixed'], check=True)",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "utility.py"), "import os\nvalue = os.environ.get('PATH')\nsite = '/tmp/' + value\n", "utf8");
  await writeFile(path.join(root, "safe.py"), [
    "from flask import redirect, request, url_for",
    "import sqlite3",
    "def safe():",
    "    query = 'SELECT id FROM users WHERE id = ?'",
    "    sqlite3.connect(':memory:').execute(query, (request.args.get('id'),))",
    "    return redirect(url_for('detail', id=request.args.get('id'))) ",
  ].join("\n"), "utf8");
  const result = await runAudit(root, { output: path.join(root, "runs") });
  assert.equal(result.run.recon?.projectKind, "PYTHON");
  assert.equal(result.run.recon?.codeGraph?.flows.some((flow) => flow.reason.includes("Python helper")), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-COMMAND-INJECTION-001"), true);
  assert.equal(result.run.findings.some((finding) => finding.locations.some((location) => location.line === 11)), false);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-SQL-INJECTION-001" && finding.locations.some((location) => location.file === "safe.py")), false);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-OPEN-REDIRECT-001" && finding.locations.some((location) => location.file === "safe.py")), false);
});

test("Python graph keeps bound SQL parameters and browser clients out of server-side injection findings", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-safe-boundary-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "app.py"), [
    "from flask import request",
    "@app.post('/profile')",
    "def update_profile():",
    "    data = request.json",
    "    allowed_updates = ['email', 'country']",
    "    updates = {key: value for key, value in data.items() if key in allowed_updates}",
    "    update_query = 'UPDATE users SET ' + ', '.join([f'{key} = ?' for key in updates.keys()]) + ' WHERE id = ?'",
    "    cursor.execute(update_query, list(updates.values()) + [1])",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "client.ts"), [
    "export async function load(url: string) {",
    "  return fetch(url);",
    "}",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "multiline.py"), [
    "from flask import request",
    "@app.post('/email')",
    "def update_email():",
    "    email = request.form['email']",
    "    query = \"\"\"UPDATE users SET email = ? WHERE id = ?\"\"\"",
    "    cursor.execute(query, (email, 1))",
  ].join("\n"), "utf8");
  const result = await runAudit(root, { output: path.join(root, "runs") });
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-SQL-INJECTION-001"), false);
  assert.equal(result.run.findings.some((finding) => finding.ruleId.includes("SSRF") && finding.locations.some((location) => location.file === "client.ts")), false);
});

test("Python sensitive-record exposure requires a raw sensitive response", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-sensitive-projection-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "safe.py"), [
    "def list_students(conn):",
    "    query = 'SELECT id, name FROM students'",
    "    rows = conn.execute(query).fetchall()",
    "    return [row['name'] for row in rows]",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "unsafe.py"), [
    "@app.get('/users')",
    "def list_users(conn):",
    "    rows = conn.execute('SELECT id, email, password FROM users').fetchall()",
    "    return rows",
  ].join("\n"), "utf8");
  const result = await runAudit(root, { output: path.join(root, "runs") });
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-SENSITIVE-DATA-EXPOSURE-001" && finding.locations.some((location) => location.file === "safe.py")), false);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-SENSITIVE-DATA-EXPOSURE-001" && finding.locations.some((location) => location.file === "unsafe.py")), true);
});

test("Python property graph separates HTML output, password storage, and protected routes", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-python-properties-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "app.py"), [
    "from flask import request",
    "from flask_login import login_required",
    "",
    "@app.route('/unsafe')",
    "def unsafe():",
    "    name = request.form['name']",
    "    user = User(password=request.form['password'])",
    "    return '<p>' + name + '</p>'",
    "",
    "@app.route('/protected')",
    "@login_required",
    "def protected():",
    "    return eval(request.form['expression'])",
  ].join("\n"), "utf8");
  const result = await runAudit(root, { output: path.join(root, "runs") });
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-REFLECTED-XSS-001"), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-CLEARTEXT-PASSWORD-001"), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-MISSING-AUTH-001" && finding.locations.some((location) => location.line === 4)), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-MISSING-AUTH-001" && finding.locations.some((location) => location.line === 10)), false);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-REFLECTED-XSS-001" && finding.locations.some((location) => location.file === "utility.py")), false);
});

test("FastAPI route parameters preserve scalar-vs-object semantics and split shared sink flows", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-fastapi-graph-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "main.py"), [
    "from fastapi import FastAPI, Request",
    "from fastapi.responses import HTMLResponse",
    "app = FastAPI(docs_url=None)",
    "",
    "def run_query(query):",
    "    return db.execute(query)",
    "",
    "def find_users(query):",
    "    return users.find(query)",
    "",
    "@app.get('/select')",
    "async def select(username: str):",
    "    return run_query(f'SELECT * FROM users WHERE username = \"{username}\"')",
    "",
    "@app.get('/find')",
    "async def fixed_find(username: str):",
    "    return find_users({'username': username})",
    "",
    "@app.post('/find')",
    "async def object_find(request: Request):",
    "    query = await request.json()",
    "    return find_users(query)",
    "",
    "@app.post('/reset')",
    "async def reset():",
    "    remove('db.sqlite')",
    "",
    "@app.get('/docs', include_in_schema=False)",
    "def docs():",
    "    return HTMLResponse('<html>docs</html>')",
  ].join("\n"), "utf8");
  const result = await runAudit(root, { output: path.join(root, "runs") });
  const sql = result.run.findings.filter((finding) => finding.ruleId === "PY-SQL-INJECTION-001");
  const nosql = result.run.findings.filter((finding) => finding.ruleId === "PY-NOSQL-INJECTION-001");
  assert.equal(sql.length, 1);
  assert.equal(nosql.length, 1);
  assert.equal(nosql[0]?.locations.some((location) => location.line === 21), true);
  assert.equal(result.run.findings.filter((finding) => finding.ruleId === "PY-MISSING-AUTH-001").length, 1);
  assert.equal(result.run.findings.some((finding) => finding.locations.some((location) => location.line === 28)), false);
  await writeFile(path.join(root, "Caddyfile"), "waf {\n    coraza_waf {\n        directives `SecRuleEngine Off`\n    }\n}\n", "utf8");
  await mkdir(path.join(root, "tests"), { recursive: true });
  await writeFile(path.join(root, "tests", "test_secrets.py"), "API_KEY = 'fixture-only'\\n", "utf8");
  const configResult = await runAudit(root, { output: path.join(root, "runs-config") });
  assert.equal(configResult.run.findings.some((finding) => finding.ruleId === "CONFIG-WAF-DISABLED-001"), true);
  assert.equal(configResult.run.findings.some((finding) => finding.locations.some((location) => location.file === "tests/test_secrets.py")), false);
});

test("Python framework policies distinguish deployment settings, auth cookies, and object ownership", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-python-framework-policies-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "settings.py"), [
    "DEBUG = True",
    "ALLOWED_HOSTS = ['*']",
    "KEY = b'1234567890'",
    "SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-demo')",
  ].join("\n"), "utf8");
  await mkdir(path.join(root, "app", "views", "sessions"), { recursive: true });
  await mkdir(path.join(root, "app", "views", "work_info"), { recursive: true });
  await writeFile(path.join(root, "app", "views", "sessions", "views.py"), [
    "def login(response, token):",
    "    response.set_cookie('auth_token', token)",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "app", "views", "work_info", "views.py"), [
    "def work_info(request, user_id):",
    "    return User.objects.get(id=user_id)",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "auth.py"), [
    "from flask import request",
    "@app.post('/login')",
    "def login():",
    "    return authenticate(request.form['username'], request.form['password'])",
    "",
    "@app.get('/login')",
    "def login_page():",
    "    return render_template('login.html')",
    "",
    "def authenticate_helper(input_email, input_password):",
    "    return User.find_by_email(input_email)",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "uploads.py"), [
    "from flask import request",
    "@app.post('/upload')",
    "def upload():",
    "    uploaded_file = request.files['file']",
    "    uploaded_file.save('/srv/uploads/' + uploaded_file.filename)",
    "",
    "async def raw_upload(",
    "    request: Request,",
    "    name: str = 'raw.bin',",
    "):",
    "    body = await request.body()",
    "    target = Path('/srv/uploads') / name",
    "    target.write_bytes(body)",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "logging.py"), "import logging\nlogging.info('password=%s token=%s', password, token)\n", "utf8");
  await writeFile(path.join(root, "enum.py"), [
    "from flask import request",
    "@app.post('/register')",
    "def register():",
    "    email = request.form['email']",
    "    if User.query.filter_by(email=email).first():",
    "        return {'error': 'Email already exists'}",
    "    return {'ok': True}",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "identity.py"), [
    "def identity_hint(request):",
    "    handle = request.GET.get('handle', '')",
    "    known = {'north': '4812'}",
    "    if handle not in known:",
    "        return JsonResponse({'detail': 'unknown handle'}, status=404)",
    "    return JsonResponse({'status': 'queued'})",
  ].join("\n"), "utf8");
  await mkdir(path.join(root, "app", "views"), { recursive: true });
  await writeFile(path.join(root, "app", "views", "mass.py"), [
    "def update_profile(request, user):",
    "    data = request.POST.dict().copy()",
    "    user.update(**data)",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "randomness.py"), [
    "import random",
    "import secrets",
    "import uuid",
    "def create_session_token():",
    "    return ''.join(random.sample('abcdef0123456789', 12))",
    "",
    "def create_short_id():",
    "    return str(uuid.uuid4())[0:6]",
    "",
    "def pick_benefit_index():",
    "    return random.randint(0, 3)",
    "",
    "def create_secure_token():",
    "    return secrets.token_urlsafe(24)",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "session_integrity.py"), [
    "import base64",
    "import json",
    "def create(response, username):",
    "    session = base64.b64encode(json.dumps({'username': username}).encode())",
    "    response.set_cookie('vulpy_session', session)",
    "    return response",
    "",
    "def create_signed(response, username, signer):",
    "    session = base64.b64encode(json.dumps({'username': username}).encode())",
    "    signed = signer.sign(session)",
    "    response.set_cookie('signed_session', signed)",
    "    return response",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "unsafe_config.py"), [
    "DEBUG = _env_bool('DJANGO_DEBUG', default=True)",
    "def after_request(response):",
    "    origin = request.headers.get('Origin')",
    "    response.headers['Access-Control-Allow-Origin'] = origin",
    "    response.headers['Access-Control-Allow-Credentials'] = 'true'",
    "    return response",
    "",
    "def fetch(url):",
    "    return requests.get(url, verify=False)",
  ].join("\n"), "utf8");
  await writeFile(path.join(root, "rand.py"), [
    "import random",
    "def do_random():",
    "    return str(random.uniform(0, 1))",
  ].join("\n"), "utf8");
  await mkdir(path.join(root, "templates"), { recursive: true });
  await writeFile(path.join(root, "templates", "unsafe.html"), "<p>{{ message | safe }}</p>\n", "utf8");
  await writeFile(path.join(root, "templates", "escaped.html"), "<p>{{ message }}</p>\n", "utf8");
  const result = await runAudit(root, { output: path.join(root, "runs") });
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-DEBUG-MODE-001"), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-SECURITY-MISCONFIGURATION-001"), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-HARDCODED-CREDENTIAL-001"), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-INSECURE-COOKIE-001"), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-SESSION-INTEGRITY-001" && finding.locations.some((location) => location.file === "session_integrity.py" && location.line === 5)), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-SESSION-INTEGRITY-001" && finding.locations.some((location) => location.file === "session_integrity.py" && location.line === 11)), false);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-DEBUG-MODE-001" && finding.locations.some((location) => location.file === "unsafe_config.py" && location.line === 1)), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-SECURITY-MISCONFIGURATION-001" && finding.locations.some((location) => location.file === "unsafe_config.py")), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-HARDCODED-CREDENTIAL-001" && finding.locations.some((location) => location.file === "settings.py" && location.line === 4)), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-WEAK-RANDOMNESS-001" && finding.locations.some((location) => location.file === "rand.py")), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "TEMPLATE-UNSAFE-OUTPUT-001" && finding.locations.some((location) => location.file === "templates/unsafe.html")), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "TEMPLATE-UNSAFE-OUTPUT-001" && finding.locations.some((location) => location.file === "templates/escaped.html")), false);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-IDOR-001"), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-RATE-LIMIT-001" && finding.locations.some((location) => location.file === "auth.py")), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-RATE-LIMIT-001" && finding.locations.some((location) => location.file === "auth.py" && location.line >= 7)), false);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-UNRESTRICTED-FILE-UPLOAD-001" && finding.locations.some((location) => location.file === "uploads.py")), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-SENSITIVE-DATA-EXPOSURE-001" && finding.locations.some((location) => location.file === "logging.py")), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-USER-ENUMERATION-001" && finding.locations.some((location) => location.file === "enum.py")), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-USER-ENUMERATION-001" && finding.locations.some((location) => location.file === "identity.py")), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-MASS-ASSIGNMENT-001" && finding.locations.some((location) => location.file === "app/views/mass.py" && location.line === 3)), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-WEAK-RANDOMNESS-001" && finding.locations.some((location) => location.file === "randomness.py" && location.line === 5)), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-WEAK-RANDOMNESS-001" && finding.locations.some((location) => location.file === "randomness.py" && location.line === 8)), true);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-WEAK-RANDOMNESS-001" && finding.locations.some((location) => location.file === "randomness.py" && location.line === 11)), false);
  assert.equal(result.run.findings.some((finding) => finding.ruleId === "PY-WEAK-RANDOMNESS-001" && finding.locations.some((location) => location.file === "randomness.py" && location.line === 14)), false);
});
