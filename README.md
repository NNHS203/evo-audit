# Evo Audit

Evo Audit is a CLI-first, evidence-gated AI code auditing core. It is designed
to compose existing Frontier audit workers rather than hide the audit process
inside a single model.

The first slice is intentionally small and deterministic:

1. discover the audit scope;
2. create semantic-audit obligations from code facts;
3. detect high-risk source/sink patterns;
4. emit evidence-tiered candidate findings;
5. persist a replayable run artifact;
6. expose a semantic file delta for token-aware worker scheduling;
7. leave a stable protocol for Frontier workers and reviewable playbook evolution.

The built-in detector never upgrades a static suspicion into a verified
vulnerability. A finding is `SUSPECTED` until an execution-capable worker adds
reproducible evidence.

## Quick start

```bash
npm install
npm run build
node dist/src/cli.js init ./example
node dist/src/cli.js run ./example --output ./audit-runs
```

The CLI also installs as `evo-audit` when this package is linked or published.

## Current protocol

- `AuditObligation`: a property or risk boundary that should be checked.
- `Finding`: a root-cause hypothesis plus evidence and its limitations.
- `EvidenceTier`: `T0_HYPOTHESIS`, `T1_STATIC_PATH`, or `T2_REPRODUCIBLE`.
- `FindingStatus`: `SUSPECTED`, `SUPPORTED`, `VERIFIED`, `NOT_TESTED`, or
  `HARNESS_FAILED`.
- `AuditRun`: immutable run metadata, file fingerprints, obligations, findings,
  semantic delta, and token accounting.

## Frontier worker boundary

The CLI is the audit kernel; a model is an interchangeable investigator. A
worker writes a JSON object with `worker`, `findings`, optional evidence, and
optional token accounting, then it can be merged without changing the core:

```bash
node dist/src/cli.js ingest \
  ./audit-runs/<run-id>/run.json \
  ./worker-result.json
```

The merge layer deduplicates by obligation or source location, records the
worker identity, accumulates token accounting, and gates `VERIFIED` behind a
reproducible `T2_REPRODUCER`. A model cannot promote its own unsupported claim.

For an incremental run, keep the full scan for coverage but give workers the
semantic delta:

```bash
node dist/src/cli.js run ./example \
  --baseline ./audit-runs/<previous-run-id>/run.json
```

To generate a reviewable (not automatically applied) playbook proposal from
open obligations:

```bash
node dist/src/cli.js evolve ./audit-runs/<run-id>/run.json
```

The benchmark contract is documented in [`benchmark/README.md`](benchmark/README.md).

## Design boundary

The core is local-first and model-agnostic. It does not execute production
commands or treat a model's confidence as proof. Frontier adapters can add
runtime evidence through the protocol without changing the CLI or detector.

The product thesis is therefore not “pick a better model.” It is an evidence
kernel around existing Frontier workers: open the right obligations, allocate
context from semantic deltas, ask for falsifiable evidence, and evolve the
procedure only through replayable holdout evaluation.
