# Benchmark tracks and comparison protocol

Evo Audit keeps discovery and proof as separate scores. A static candidate can
count toward candidate recall, but it cannot count toward reportable recall or
validated-finding rate until an independent validator records `T2_REPRODUCIBLE`
evidence.

## Tracks

### Local JS/TS track

`benchmark/cases` is the fast, dependency-free development/holdout track. It
contains synthetic source-to-sink and lookalike cases, and
`benchmark/benchmark-manifest.json` pins case content by SHA-256. CI gates
candidate recall, candidate precision, and false-positive rate; it intentionally
does not claim that an unvalidated candidate is a closed vulnerability.

Use the optional model-backed mode to measure the same workflow with a real
API/OAuth model:

```bash
evo-audit benchmark ./benchmark/cases \
  --manifest ./benchmark/benchmark-manifest.json \
  --model auto --config ./audit.models.json
```

### Real-world external track

[RealVuln](https://realvuln.kolega.dev/) is a useful external comparison because
it publishes ground truth, false-positive traps, pinned repository commits,
scanner adapters, and scoring code. Its current v2.0 track is Python-focused;
it should be treated as an external, version-pinned comparison rather than
silently mixed into the JS/TS score. The [upstream repository](https://github.com/kolega-ai/Real-Vuln-Benchmark)
must be used with its own manifest and scorer. Scores from different benchmark
versions are not interchangeable.

The repository provides a reproducible adapter for one selected upstream
repository:

```bash
git clone --depth 1 https://github.com/kolega-ai/Real-Vuln-Benchmark.git ./Real-Vuln-Benchmark
evo-audit realvuln ./Real-Vuln-Benchmark \
  realvuln-damn-vulnerable-flask-application --output ./realvuln-runs
```

To audit the complete manifest and emit one aggregate report, run:

```bash
evo-audit realvuln ./Real-Vuln-Benchmark --all --output ./realvuln-runs
```

Each manifest entry is isolated in its own output directory. Clone failures,
missing upstream repositories, malformed pins, and ground-truth failures are
recorded as `BLOCKED`; they are excluded from score denominators but never
treated as safe. The aggregate is therefore useful for reproducible coverage
accounting as well as detection scoring.

The adapter verifies the manifest's full checkout commit and records the
ground-truth SHA-256, audited tree digest, and run artifact. It does not claim
that one repository is a benchmark-wide score; use the same command for each
selected pinned repository and aggregate only after fixing the benchmark
version and execution policy.

The checked-in pinned observations are deliberately marked `OBSERVED_HOLDOUT`,
not CI gates. They are candidate-discovery measurements; without an independent
runtime validator their reportable recall is zero by policy.

| Repository | Framework | Vulnerable / safe labels | Candidate precision | Candidate recall | FPR | F3 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| [Damn Vulnerable Flask](../benchmark/results/realvuln-damn-vulnerable-flask-v2-20260801.json) | Flask | 15 / 4 | 1.000 | 1.000 | 0.000 | 1.000 |
| [VAmPI](../benchmark/results/realvuln-vampi-v2-20260801.json) | Flask | 15 / 4 | 1.000 | 1.000 | 0.000 | 1.000 |
| [VFAPI](../benchmark/results/realvuln-vfapi-v2-20260801.json) | FastAPI | 9 / 2 | 1.000 | 1.000 | 0.000 | 1.000 |
| [Python insecure app](../benchmark/results/realvuln-python-insecure-app-v2-20260801.json) | FastAPI | 8 / 2 | 1.000 | 1.000 | 0.000 | 1.000 |
| [DjanGoat](../benchmark/results/realvuln-djangoat-v2-20260801.json) | Django | 52 / 6 | 0.962 | 0.481 | 0.143 | 0.506 |
| [Vulnerable Tornado App](../benchmark/results/realvuln-vulnerable-tornado-app-v2-20260801.json) | Tornado | 14 / 3 | 1.000 | 0.571 | 0.000 | 0.597 |

The four perfect results are four pinned repositories, not a benchmark-wide
or frontier-wide superiority claim. The Django and Tornado rows are retained
as coverage evidence rather than hidden: they show that framework semantics,
template resolution, and access-control policies remain the main recall gap.
The Tornado run improved from 1/14 with one false positive to 8/14 with zero
false positives after adding `get_argument`/RequestHandler sources, bounded
multiline call context, write-vs-read file semantics, and same-source sink
deduplication. DjanGoat's remaining single false positive is a published
ground-truth location mismatch for the pay-record deletion described at the
actual sink line; it is preserved in the score rather than silently corrected.

The first full-manifest run is checked in separately as an observed corpus
baseline: [RealVuln v2 aggregate](../benchmark/results/realvuln-v2-aggregate-20260801.json).
It completed 62/66 manifest entries and blocked four entries whose published
GitHub URLs were no longer available. Across the 2,018 labels in completed
repositories, candidate precision was `0.464`, candidate recall `0.174`, FPR
`0.592`, and F3 `0.186`; reportable recall was `0.000` because no independent
runtime validator was supplied. This is the honest current corpus result,
not a claim of superiority over OpenAI, Cloudflare, or research baselines.
The gap makes framework coverage, candidate ranking, and independent
model-backed/runtime validation the next optimization targets.

The checked-in records include the full upstream commit, ground-truth hash,
audited tree digest, line tolerance, scanner commit, and the separate
evidence-gated channel. Re-run the adapter after changing any of those inputs.

For a local pinned checkout, a case can use a source reference instead of
embedding code:

```json
{
  "schemaVersion": 1,
  "caseId": "project-001",
  "split": "holdout",
  "language": "typescript",
  "source": {
    "kind": "CHECKOUT",
    "path": "../pinned-project",
    "repository": "https://github.com/example/project",
    "commit": "<full commit SHA>"
  },
  "expected": { "vulnerable": true, "ruleId": "RULE-ID" }
}
```

The runner verifies the checkout HEAD, copies it read-only into an isolated
temporary case workspace, excludes `.git`, dependencies, build output, and
audit configuration, then records the resulting source tree digest.

[RepoAudit](https://arxiv.org/abs/2501.18160) is an important research baseline:
it combines repository exploration, data-flow facts, path-condition checks, and
a validator. Its published numbers are paper-reported reference points, not
claims independently reproduced by this repository.

## Comparison rules

1. Freeze the benchmark version, case/repository commit, playbook revision,
   model identifier, prompt hash, and sandbox profile.
2. Normalize scanner output into rule/CWE, file, line, root cause, status, and
   evidence tier without upgrading a scanner's claim.
3. Score candidate recall/precision separately from reportable recall,
   validated-finding rate, unsupported-claim rate, tokens per validated
   finding, and wall-clock latency.
4. Count incomplete coverage as `UNKNOWN`, never as a true negative.
5. Report multi-run mean and variance for nondeterministic models, and keep
   holdout cases out of prompt, detector, or routing changes.

For cases that declare a validator command, `benchmark --validate` runs the
positive and negative controls through the same read-only, no-network
container boundary as normal audit validation. A missing Docker/Podman runtime
produces `BLOCKED`, not a clean result.

The public CI keeps this as a separate proof track:

```bash
npm run benchmark:validator-ci
```

It runs the `validator` split in Docker/Podman and requires
`reportableRecall=1`; discovery recall cannot satisfy that gate.

## Repair-regression track

The revalidation suite is a release gate, not a disappearance counter. The
checked-in test `revalidation keeps a disappeared verified finding actionable`
creates a verified finding, applies a proposed fix, rescans the after snapshot,
and asserts that the missing root cause becomes `UNKNOWN`/`REVALIDATE` until
validated semantic coverage is available. The CLI equivalent is:

```bash
evo-audit revalidate ./before/run.json ./after/run.json \
  --output ./after/revalidation.json
```

The plan also marks a still-`VERIFIED` root cause as `BLOCKING_REGRESSION` and
keeps new findings as `VALIDATE_NEW`. This prevents a patch from “passing” by
silencing the detector, changing the snapshot, or exploiting incomplete
coverage. Future benchmark releases can aggregate this same lifecycle over a
larger patch corpus as `revalidation survival` and `blocking regression rate`.

This protocol is the basis for a future cross-language adapter; it prevents a
larger model, looser evidence policy, or unfinished scan from looking like a
performance win.

The local scorer is available without external services:

```bash
evo-audit score ./ground-truth.json ./audit-runs/<run>/run.json --format run
evo-audit score ./ground-truth.json ./semgrep.sarif --format sarif
evo-audit score ./realvuln-ground-truth.json ./scanner.sarif \
  --format sarif --ground-truth-format realvuln
evo-audit score ./realvuln-ground-truth.json ./bandit.json \
  --format bandit --root ./pinned-project --ground-truth-format realvuln
# Checked-in smoke example:
evo-audit score ./benchmark/ground-truth.example.json \
  ./benchmark/scanner.example.sarif --format sarif
```

SARIF results are normalized by rule ID, file, and line range. Ground-truth
labels are one-to-one; unmatched scanner findings are false positives, while
unmatched vulnerable labels are false negatives. This is intentionally close
to the matching discipline used by public scanner benchmarks, while keeping
Evo Audit's reportable channel tied to independent evidence.

The `realvuln` ground-truth adapter understands per-repository labels with
`is_vulnerable`, `file`, `location.start_line/end_line`, `primary_cwe`, and
`acceptable_cwes` fields. It does not download or execute the external
benchmark; the user must pin and verify that checkout separately.
