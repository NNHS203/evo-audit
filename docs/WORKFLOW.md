# Evo Audit workflow

This document explains the workflow boundary that makes Evo Audit useful as a
researchable open-source audit harness. The goal is not to make a model sound
confident. The goal is to spend expensive reasoning only where it can close a
falsifiable security obligation and to preserve uncertainty when coverage is
incomplete.

## Pipeline

```text
snapshot
   |
   v
recon (deterministic) --> compact context slices --> prioritized plan
                                                        |
                                                        v
                         HUNT ----> INVESTIGATE ----> VALIDATE
                           |             |               |
                           +-------------+---------------+
                                         v
                                  report / SARIF
                                         |
                                         v
                                  revalidate / evolve
```

### 1. Snapshot

Pin the source file manifest and tree digest before a model or validator sees
the code. A validation result from another snapshot is a harness failure, not
a security verdict.

### 2. Recon

Recon is cheap and deterministic. It records manifests, useful package scripts,
likely entrypoints, security-relevant surfaces, a lexical module graph, and a
TypeScript/JavaScript AST graph with local source/sink flow facts. The AST flow
is candidate evidence, not semantic proof: cross-function reachability,
deployment conditions, sanitizer completeness, and exploitability still need
the worker and independent validator. Compact graph slices are injected into
worker tasks instead of the whole repository.

### 3. Plan

The plan converts the playbook into executable work:

- `HUNT` tasks are created when a rule has no static match. No match is a
  coverage gap, not a clean result.
- `INVESTIGATE` tasks trace a specific candidate through source, guard, sink,
  and impact.
- `VALIDATE` tasks are blocked until investigation produces a falsifiable
  path. They must use an independent validator, a positive reproducer, and a
  negative control.

Each investigation task receives a bounded context slice and a token
allocation. The worker must return its `taskId` and token accounting. Results
that exceed the allocation are recorded as `BLOCKED`; they do not silently
expand the budget. Before the provider request, the prompt builder reserves
output tokens and deterministically compacts the graph/source slice so the
estimated input plus output stays inside the task allocation. A provider call
is rejected when the input estimate leaves no safe output reserve.

Recon also emits an area-by-attack-class coverage matrix. Empty cells create
small HUNT tasks; a completed no-match task becomes `UNKNOWN` and can receive a
bounded second pass, never a clean verdict. Worker receipts make replay and
local prompt/model cache hits idempotent. Deterministic dedup clusters only
matching source snippets and keeps distinct sink instances separate.

`review --model auto` executes this queue end to end: it completes HUNT tasks,
rebuilds the plan, and then runs INVESTIGATE tasks with bounded concurrency.
Workers can return a `proposedValidation` pair, but the proposal is inert until
the operator supplies `--auto-validate`. That opt-in sends only the positive
and negative controls to the independent read-only, no-network container
validator; a model response alone never becomes proof. The operator chooses
the container image (`--validation-image`); model output cannot choose the
runtime or widen the sandbox.

If workers were run separately, `validate-proposed <run.json>` replays the
saved proposals without making another model call. This is the token-efficient
continuation of the same evidence gate, not a second authority.

Model locations are checked against both the file fingerprint and the actual
snippet in the pinned source. Evidence locations go through the same check;
stale, out-of-scope, or hallucinated snippets are dropped and recorded as a
limitation. Receipts retain the provider model, request ID, prompt hash, finish
reason, cache state, and usage so a result can be replayed and its token cost
audited. External results that omit a receipt ID receive a deterministic
derived receipt from the immutable snapshot/task/payload identity, preserving
session accounting across replayed imports.

### 4. Evidence state

The state machine is intentionally conservative:

```text
SUSPECTED -> SUPPORTED -> VERIFIED
     |          |           |
     +------> REJECTED   REVALIDATED
```

`UNKNOWN`, `WAITING`, `DEFERRED`, and `HARNESS_FAILED` are operational states,
not claims that the code is safe. A worker cannot create `VERIFIED`. The
validator also cannot validate the same worker that produced the finding, and
validator evidence locations must remain inside the pinned snapshot.

## Why this ordering

The workflow is based on several independent findings from recent systems and
benchmarks:

- OpenAI's Codex Security describes identification, isolated validation,
  remediation, human review, and revalidation as a closed loop. See
  <https://help.openai.com/en/articles/20001107-codex-security>.
- Cloudflare's harness separates Recon, Hunt, and Validate, keeps state outside
  the agent, and uses a Validator that cannot file its own findings. Its
  released single-repository skill also adds independent verification and
  machine-readable output. See
  <https://blog.cloudflare.com/build-your-own-vulnerability-harness/> and
  <https://github.com/cloudflare/security-audit-skill>.
- Deepsec reports that compact project-specific context is injected into every
  batch and explicitly warns that verbose context dilutes signal. It also
  resumes interrupted work and separates fast matching from AI processing and
  revalidation. See <https://github.com/vercel-labs/deepsec>.
- RepoAudit combines agent memory with data-flow facts and a validator that
  checks feasible paths and path conditions, addressing repository-scale
  context and hallucination problems. See
  <https://proceedings.mlr.press/v267/guo25n.html>.
- A comparative study of LLM agents for false-positive filtering reports that
  gains depend on the model and CWE, and that aggressive noise reduction can
  suppress true vulnerabilities. This is why Evo Audit keeps HUNT tasks and
  does not turn a rejected candidate into global safety. See
  <https://arxiv.org/abs/2601.22952>.
- EvoHunt treats the playbook as an inspectable, versioned procedure and uses
  discovery, evaluation, revision, replay, and held-out cases. See
  <https://arxiv.org/html/2606.16420v1>.

## Metrics

Do not optimize for the number of model findings. Track the following per
playbook revision and per model/harness adapter:

1. **Obligation recall** — expected security obligations that were opened.
2. **Closure recall** — obligations that reached reproducible T2 evidence.
3. **Report precision** — findings surviving independent or human review.
4. **Unsupported-claim rate** — worker `VERIFIED` claims rejected by the gate.
5. **Unknown rate** — unresolved cases caused by incomplete coverage or a
   broken validator.
6. **Tokens per closed obligation** — spend efficiency, not raw token volume.
7. **Revalidation survival** — findings whose root cause remains fixed after a
   proposed patch is tested.
8. **Replay/cache rate** - worker receipts reused without new provider calls.

RealVuln is a useful external benchmark design reference because it releases
ground truth, scanner outputs, and scoring code, and gives recall-weighted F3
with unfinished repositories counted as misses:
<https://realvuln.kolega.dev/>.

`revalidate before.json after.json` materializes the comparison as a release
decision artifact. New findings require validation, previously verified
findings that disappear remain `UNKNOWN` until the after run proves validated
semantic coverage, and a still-verified finding is marked as a blocking
regression. The artifact also exposes `fixConfirmationRate`,
`fixRegressionRate`, verified counts before/after, and the number of findings
that still require revalidation.

The worker protocol also quarantines rule IDs that are not present in the
versioned playbook as `UNKNOWN`. This keeps model creativity from silently
creating an unbenchmarked reporting class; a new rule must be added to the
playbook and evaluated on held-out cases first.

## Current implementation boundary

The repository currently implements the snapshot, recon, AST/data-flow graph
(including import-aware cross-file helper summaries), Python property-flow
semantics for Flask/FastAPI/Django/Tornado patterns, coverage matrix, plan,
evidence gate, compare, SARIF, resumable state, model provider, container
validation, benchmark acceptance, and revalidation layers. The remaining
safety-critical research layer is broader framework/template resolution plus a
held-out model-backed evaluator and independent validation across the full
external corpus. Neither recall nor false-negative performance should be
claimed complete from the pinned observations alone.
