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
likely entrypoints, security-relevant surfaces, and a lexical module graph.
This is context routing metadata, not semantic proof. It is deliberately
small enough to be injected into every worker task.

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
expand the budget.

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

RealVuln is a useful external benchmark design reference because it releases
ground truth, scanner outputs, and scoring code, and gives recall-weighted F3
with unfinished repositories counted as misses:
<https://realvuln.kolega.dev/>.

## Current implementation boundary

The repository currently implements the snapshot, recon, plan, evidence gate,
compare, SARIF, and resumable state layers. The module graph is lexical and the
validator consumes an independent result JSON; an execution-capable Docker or
microVM runner is the next safety-critical layer. The next research layer is a
TypeScript/JavaScript AST plus call/data-flow graph, followed by a held-out
playbook evaluator. Neither layer should be claimed complete until it has
reproducible benchmark results.
