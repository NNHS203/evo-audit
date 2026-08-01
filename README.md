# Evo Audit

Evo Audit is a CLI-first, evidence-gated AI code-auditing kernel. It composes
Frontier audit workers, but does not allow a model to grade its own homework.

The core workflow is:

```text
snapshot -> recon/context slices -> prioritized plan -> worker hypotheses -> independent validator -> finding
```

Static detectors create hypotheses and falsifiable obligations. A worker may
propose an attack path or a validation request, but only an independent
validator can create `T2_REPRODUCIBLE` evidence and `VERIFIED` status.

Every review also produces a deterministic `recon.json` and `plan.json`.
Recon records manifests, useful package scripts, likely entrypoints, security
surfaces, and a lightweight module graph. The plan gives each obligation a
priority, a bounded context slice, and a token allocation. This prevents the
worker from receiving the whole repository by default and makes token budget a
workflow constraint rather than a config value that is merely recorded.

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

# Or execute the request in a Docker/Podman sandbox (never on the host).
evo-audit validate-run ./audit-runs/<run>/run.json ./validation-request.json

# Track root causes across scans, without treating incomplete coverage as clean.
evo-audit compare ./before/run.json ./after/run.json

# Inspect the prioritized investigation and validation queue.
evo-audit plan ./audit-runs/<run>/run.json

# Inspect or resume pending obligations.
evo-audit status ./audit-runs/<run>/run.json
evo-audit resume ./audit-runs/<run>/run.json
```

Reports support `text`, `json`, and `sarif` formats. SARIF results include
stable root-cause fingerprints so downstream code-scanning systems can track
findings even when line numbers move.

## Token usage

An audit session is the output directory (`audit-runs/` by default). Evo Audit
persists `session.json` there and prints both the current run usage and the
session total after `review`, `ingest`, and `validate`:

```text
Tokens: current total=1500 (input=1200, output=300, cached=100)
Session total: total=1500 (...) across 1 run(s)
```

Updating the same run replaces its previous contribution, so replaying an
ingest or validation does not double-count tokens. `totalTokens` is defined as
input plus output; cached tokens are shown separately for transparency.

## Optimized worker loop

Workers should consume one plan task at a time:

1. Read the task's target files and compact context slice. `HUNT` tasks exist
   even when the static detector found no match.
2. Trace the suspected source, sink, guard, and impact boundary.
3. Expand context only along imports, importers, changed files, or an identified
   authorization/entrypoint surface.
4. Return supporting evidence and a falsifier; never return `VERIFIED` as a
   final authority.
5. Let the independent validator run the positive reproducer and negative
   control against the pinned snapshot.

`STATIC_ONLY`, `PARTIAL_WORKER`, and `VALIDATED` describe semantic coverage;
`PENDING`, `WAITING`, and `DEFERRED` are workflow states, not security
verdicts. A deferred task means the worker budget was exhausted; it does not
mean the code was reviewed or safe. Recon now also contains a TypeScript/
JavaScript AST graph with local source/sink flow facts. Those facts improve
candidate discovery and context selection but remain possible paths until an
independent validator proves reachability and impact.

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
`validate-run` uses a read-only source mount, disabled network, dropped Linux
capabilities, no-new-privileges, a PID/memory/CPU limit, and a writable
no-exec `/tmp`. If Docker/Podman is unavailable, the result is `BLOCKED`; the
command is never executed directly on the developer host.

## Frontier worker boundary

Workers are interchangeable investigators. They can be backed by Codex,
OpenCode, Claude, a local model, CodeQL, Semgrep, or a custom harness. Their
results are ingested through the JSON protocol:

```bash
evo-audit ingest ./audit-runs/<run>/run.json ./worker-result.json
```

When a worker consumes a planned task, it should include that task's `taskId`
and token accounting. The ingest step marks the task complete only within its
allocation; an over-budget task is recorded as `BLOCKED` and never becomes
proof by itself.

Worker claims are deliberately downgraded to hypotheses/supporting evidence.
The validator-owned ledger is the only path to `VERIFIED`.

## Bring your own model

Models can be loaded through an API-key environment variable or a PKCE OAuth
flow. Configure `audit.models.json`, inspect credential state with
`evo-audit models .`, and run `evo-audit auth . <model-id>` for a configured
OAuth provider. `auto` routing is capability- and budget-aware, but model
selection never replaces source evidence or independent validation. See
[`docs/MODELS.md`](docs/MODELS.md).

## Research direction

The next depth layer is interprocedural graph expansion: resolved symbols,
cross-function data-flow, authorization boundaries, sanitizers, tests, and
framework entrypoint adapters. Workers already receive compact AST graph
slices instead of entire repositories. Playbook changes should be evaluated on
held-out cases before they are accepted.

The benchmark contract is documented in [`benchmark/README.md`](benchmark/README.md).
The workflow rationale and research references are documented in
[`docs/WORKFLOW.md`](docs/WORKFLOW.md).

## Safety boundary

Evo Audit is local-first and model-agnostic. It does not execute production
commands, automatically modify source, or treat model confidence as proof.
Any execution-capable validator must provide its own sandbox, resource limits,
network policy, and credential isolation.
