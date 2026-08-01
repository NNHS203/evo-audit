# Evo Audit benchmark protocol

This directory is a format and evaluation contract, not a claimed score.
Cases should be split before tuning into `train`, `development`, and
`holdout`; the holdout must not be used to evolve a playbook.

Each case records:

- the code snapshot and its provenance;
- the expected security property, root cause, and impact;
- required evidence for a reportable result;
- negative controls and known ambiguities;
- token and wall-clock budgets.

The primary metrics are deliberately separate:

1. report precision: how many reported findings survive human verification;
2. obligation recall: how many expected security obligations are opened;
3. closure recall: how many expected obligations reach reproducible T2 evidence;
4. unsupported-claim rate: how often a worker claims `VERIFIED` without a
   reproducible reproducer;
5. token efficiency: input/output tokens per closed obligation.

An empty report is not a pass. A case is only closed when the audit artifact
contains the required evidence and a negative control where applicable.

The workflow plan is part of the artifact contract: a rule with no static
match should produce a `HUNT` task, and a `STATIC_ONLY` run must not be scored
as semantically complete. This prevents a detector's blind spot from being
mistaken for a true negative.

The intended research loop is: run a frozen playbook on train cases, propose a
reviewable playbook revision, evaluate it on development cases, then report
once on holdout. This makes improvements in the audit procedure measurable
instead of conflating them with a larger model or a longer prompt.

## Local runner

Run the deterministic baseline over the checked-in cases:

```bash
evo-audit benchmark ./benchmark/cases
evo-audit benchmark ./benchmark/cases --split development --json
evo-audit benchmark ./benchmark/cases --split development \
  --manifest ./benchmark/benchmark-manifest.json \
  --min-recall 1 --min-precision 1 --max-fpr 0

# Framework holdout: FastAPI, Django, Flask, Express, plus safe controls.
evo-audit benchmark ./benchmark/cases --split framework-holdout \
  --manifest ./benchmark/benchmark-manifest.json

# Optional: run the same cases through a configured API/OAuth model worker.
evo-audit benchmark ./benchmark/cases --split development \
  --model auto --config ./audit.models.json --max-model-tasks 8

# Optional: run case-declared reproducers in Docker/Podman isolation.
evo-audit benchmark ./benchmark/cases --split development \
  --validate

# Proof track used by CI; requires a running Docker or Podman daemon.
npm run benchmark:validator-ci

# External reproducibility track; RealVuln is intentionally not vendored.
git clone --depth 1 https://github.com/kolega-ai/Real-Vuln-Benchmark.git ./Real-Vuln-Benchmark
evo-audit realvuln ./Real-Vuln-Benchmark \
  realvuln-damn-vulnerable-flask-application --output ./realvuln-runs
```

The checked-in development track covers JavaScript/TypeScript and Python
source-to-sink cases, including explicit safe traps. The separate `validator`
split currently covers JavaScript dynamic code execution, Python command
injection, and Python SQL injection, each with a positive reproducer and a
negative control. The runner creates an isolated temporary workspace for each
case, records the
candidate result, and removes that workspace after the case. It reports
candidate recall/precision, false-positive rate on explicitly labeled safe
traps, unknown-coverage rate, and tokens per case. These are discovery metrics;
they are not a claim of real-world vulnerability recall. A later model-backed
runner must preserve the same case IDs and add validator evidence before
reporting validated metrics.

The `validator` split is intentionally separate from discovery CI. Its
acceptance gate requires an actual `VERIFIED` finding with
`reportableRecall=1`; unavailable Docker/Podman produces `BLOCKED` and fails
that proof job rather than being counted as safe.

Threshold flags turn the discovery metrics into a CI acceptance gate and exit
non-zero on regression. The gate intentionally does not assert that unknown
coverage is safe; use `--max-unknown` only when a benchmark has an explicit
coverage-completion contract.

The report also exposes `reportableRecall`, `validatedFindingRate`,
`unsupportedClaimRate`, and `tokensPerValidatedFinding`. The deterministic
runner is expected to report zero reportable recall until an independent
validator result is applied; that zero is a useful guard against accidentally
scoring static candidates as closed vulnerabilities.

Model-backed mode reuses the same task protocol, local prompt cache, receipt
deduplication, and global token budget as a normal review. It still does not
turn worker output into a reportable vulnerability: a separate validator run
is required for `T2_REPRODUCIBLE` evidence.

Cases may declare a `validation` block with a `findingRuleId`, positive
`reproducerCommand`, negative control, timeout, and container image. With
`--validate`, the runner uses the independent container validator and records
`VERIFIED`, `REJECTED`, or `BLOCKED`; `BLOCKED` is never converted into a safe
result.

`benchmark/benchmark-manifest.json` pins every checked-in case by SHA-256,
split, and case ID. Passing `--manifest` makes accidental case drift fail
closed before metrics are computed.

`realvuln` reads the upstream manifest, clones the selected repository at its
full commit SHA, verifies the checkout before auditing, and writes
`realvuln-report.json` with the ground-truth hash, tree digest, audit artifact
path, candidate score, and evidence-gated reportable score. A failed clone or
revision mismatch is an error; it is never silently scored as a clean
repository.
