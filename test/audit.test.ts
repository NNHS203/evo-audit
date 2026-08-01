import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { detectFindings, maskNonCode } from "../src/detectors.js";
import { initWorkspace, readJson, runAudit } from "../src/core.js";
import { defaultPlaybook } from "../src/playbook.js";
import type { AuditRun } from "../src/types.js";
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

  const persisted = await readJson<AuditRun>(path.join(artifactDir, "run.json"));
  assert.equal(persisted.runId, run.runId);
  assert.equal((await readFile(path.join(artifactDir, "manifest.json"), "utf8")).includes(run.runId), true);
});

test("strict mode does not promote static candidates", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "evo-audit-strict-"));
  await initWorkspace(root);
  await writeFile(path.join(root, "app.ts"), "export function run(req) { return eval(req.body.code); }\n", "utf8");

  const { run } = await runAudit(root, { output: path.join(root, "runs"), strict: true });
  assert.equal(run.findings.length, 0);
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

  const verified = mergeWorkerResult(unsupported, {
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
  assert.equal(verified.findings[0].status, "VERIFIED");
  assert.equal(verified.obligations[0].status, "SATISFIED");
  assert.equal(verified.tokenAccounting.inputTokens, 1200);
  assert.equal(verified.tokenAccounting.source, "WORKER_REPORTED");

  const hallucinated = mergeWorkerResult(verified, {
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
