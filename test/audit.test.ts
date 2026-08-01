import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { detectFindings, maskNonCode } from "../src/detectors.js";
import { compareRuns } from "../src/compare.js";
import { initWorkspace, readJson, runAudit } from "../src/core.js";
import { defaultPlaybook } from "../src/playbook.js";
import { buildResumePlan } from "../src/resume.js";
import { toSarif } from "../src/sarif.js";
import type { AuditRun } from "../src/types.js";
import { applyValidationResult, assertWorkspaceMatchesSnapshot } from "../src/validator.js";
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

  const persisted = await readJson<AuditRun>(path.join(artifactDir, "run.json"));
  assert.equal(persisted.runId, run.runId);
  assert.equal((await readFile(path.join(artifactDir, "manifest.json"), "utf8")).includes(run.runId), true);
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
    schemaVersion: 1,
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
  const sarif = toSarif(before.run) as { runs: Array<{ results: unknown[] }> };
  assert.equal(sarif.runs[0].results.length, 1);
  const plan = buildResumePlan(before.run);
  assert.equal(plan.pendingObligations.length, 1);
  assert.equal(plan.findingsToValidate.length, 1);
});
