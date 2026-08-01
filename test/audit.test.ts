import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
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
  assert.deepEqual(run.reportableFindingIds, [run.findings[0].id]);

  const initialSession = await readJson<{ total: { totalTokens: number }; runs: unknown[] }>(path.join(output, "session.json"));
  assert.equal(initialSession.total.totalTokens, 0);
  const workerUpdated = mergeWorkerResult(run, {
    worker: "usage-worker",
    findings: [],
    tokenAccounting: { inputTokens: 1200, outputTokens: 300, cachedTokens: 100, estimatedCostUsd: 0.04 },
  });
  const sessionAfterWorker = await persistRunArtifacts(artifactDir, workerUpdated);
  assert.equal(sessionAfterWorker.total.totalTokens, 1500);
  assert.equal(sessionAfterWorker.runs.length, 1);
  const sessionAfterReplay = await persistRunArtifacts(artifactDir, workerUpdated);
  assert.equal(sessionAfterReplay.total.totalTokens, 1500);

  const persisted = await readJson<AuditRun>(path.join(artifactDir, "run.json"));
  assert.equal(persisted.runId, run.runId);
  assert.equal((await readFile(path.join(artifactDir, "manifest.json"), "utf8")).includes(run.runId), true);
  assert.equal((await readFile(path.join(artifactDir, "recon.json"), "utf8")).includes("contextDigest"), true);
  assert.equal((await readFile(path.join(artifactDir, "plan.json"), "utf8")).includes("tokenBudget"), true);
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

  const overBudget = mergeWorkerResult(run, {
    worker: "over-budget-worker",
    taskId: `investigate:${run.findings[0].id}`,
    findings: [],
    tokenAccounting: { inputTokens: 901, outputTokens: 1 },
  });
  assert.equal(overBudget.plan?.tasks.find((task) => task.id === `investigate:${run.findings[0].id}`)?.status, "BLOCKED");
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
  const sarif = toSarif(before.run) as { runs: Array<{ results: unknown[] }> };
  assert.equal(sarif.runs[0].results.length, 1);
  const plan = buildResumePlan(before.run);
  assert.equal(plan.pendingObligations.length, 1);
  assert.equal(plan.findingsToValidate.length, 1);
});
