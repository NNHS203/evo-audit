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

This protocol is the basis for a future cross-language adapter; it prevents a
larger model, looser evidence policy, or unfinished scan from looking like a
performance win.
