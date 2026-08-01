# Evo Audit

Evo Audit is a CLI-first, evidence-gated AI code-auditing kernel. It composes
Frontier audit workers, but does not allow a model to grade its own homework.

The core workflow is:

```text
snapshot -> obligations -> worker hypotheses -> independent validator -> finding
```

Static detectors create hypotheses and falsifiable obligations. A worker may
propose an attack path or a validation request, but only an independent
validator can create `T2_REPRODUCIBLE` evidence and `VERIFIED` status.

## Quick start

```bash
npm install
npm test
npm run build

node dist/src/cli.js init ./example
node dist/src/cli.js review ./example --output ./audit-runs
node dist/src/cli.js report ./audit-runs/<run-id>/run.json --format sarif
```

The package installs as `evo-audit` when linked or published.

## CLI workflow

```bash
# Review a repository and persist a replayable run.
evo-audit review .

# Preserve full coverage while exposing changed files to workers.
evo-audit review . --baseline ./audit-runs/<previous-run>/run.json

# Create a validation request for a candidate finding.
evo-audit verify ./audit-runs/<run>/run.json <finding-id> \
  --command "node isolated-reproducer.js" \
  --negative "node isolated-negative-control.js"

# Apply a result produced by an independent validator.
evo-audit validate ./audit-runs/<run>/run.json ./validation-result.json

# Track root causes across scans, without treating incomplete coverage as clean.
evo-audit compare ./before/run.json ./after/run.json

# Inspect or resume pending obligations.
evo-audit status ./audit-runs/<run>/run.json
evo-audit resume ./audit-runs/<run>/run.json
```

Reports support `text`, `json`, and `sarif` formats. SARIF results include
stable root-cause fingerprints so downstream code-scanning systems can track
findings even when line numbers move.

## Evidence contract

`AuditRun` records a file manifest, tree digest, coverage state, semantic delta,
obligations, findings, and token accounting. A validator result must identify
the run and finding, match the snapshot digest and source fingerprints, and
declare an approved sandbox policy.

For `VERIFIED`, the validator must provide:

- a passing reproducer with exit code and output digests;
- a passing negative control;
- read-only source execution in a no-network or allowlisted sandbox;
- evidence mapped to files in the audited snapshot.

If the workspace changes after the run, validation fails closed. An empty
finding list or incomplete coverage is never represented as proof of safety.

## Frontier worker boundary

Workers are interchangeable investigators. They can be backed by Codex,
OpenCode, Claude, a local model, CodeQL, Semgrep, or a custom harness. Their
results are ingested through the JSON protocol:

```bash
evo-audit ingest ./audit-runs/<run>/run.json ./worker-result.json
```

Worker claims are deliberately downgraded to hypotheses/supporting evidence.
The validator-owned ledger is the only path to `VERIFIED`.

## Research direction

The next depth layer is a code graph for TypeScript/JavaScript: imports,
symbols, calls, source-to-sink flows, authorization boundaries, sanitizers, and
tests. Workers should receive compact graph slices instead of entire
repositories. Playbook changes should be evaluated on held-out cases before
they are accepted.

The benchmark contract is documented in [`benchmark/README.md`](benchmark/README.md).

## Safety boundary

Evo Audit is local-first and model-agnostic. It does not execute production
commands, automatically modify source, or treat model confidence as proof.
Any execution-capable validator must provide its own sandbox, resource limits,
network policy, and credential isolation.
