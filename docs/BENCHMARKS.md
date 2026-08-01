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

The adapter verifies the manifest's full checkout commit and records the
ground-truth SHA-256, audited tree digest, and run artifact. It does not claim
that one repository is a benchmark-wide score; use the same command for each
selected pinned repository and aggregate only after fixing the benchmark
version and execution policy.

One pinned observed snapshot is checked in at
[`benchmark/results/realvuln-damn-vulnerable-flask-v2-20260801.json`](../benchmark/results/realvuln-damn-vulnerable-flask-v2-20260801.json).
It is deliberately marked `OBSERVED_BASELINE`, not a CI gate: on the same
15-vulnerability/4-trap Flask checkout, Evo Audit measured candidate
precision 1.000, recall 0.333, FPR 0, F3 0.357; Bandit 1.9.4 measured precision
0.200, recall 0.067, FPR 0.500, F3 0.071. Neither result counts as reportable
without independent validation.

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
