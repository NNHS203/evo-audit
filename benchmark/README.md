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
```

The runner creates an isolated temporary workspace for each case, records the
candidate result, and removes that workspace after the case. It reports
candidate recall/precision, false-positive rate on explicitly labeled safe
traps, unknown-coverage rate, and tokens per case. These are discovery metrics;
they are not a claim of real-world vulnerability recall. A later model-backed
runner must preserve the same case IDs and add validator evidence before
reporting validated metrics.
