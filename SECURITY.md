# Security policy

Evo Audit is a security-auditing tool, not a proof that a repository is safe.
Findings marked `SUSPECTED` or `SUPPORTED` require independent validation.
Incomplete coverage and an empty report must remain visible as unknown risk.

## Reporting a vulnerability in Evo Audit

Please report vulnerabilities in Evo Audit itself through a private GitHub
Security Advisory when available. Do not include credentials, private source
code, or live exploit data in a public issue.

When reporting, include the commit, platform, command, configuration, and a
minimal reproduction. Redact secrets and use synthetic data whenever possible.

## Validator safety boundary

Validator commands can execute code from the repository under review. Run them
in an isolated Docker/Podman environment with a read-only source mount, no
network, resource limits, and credentials kept outside the sandbox. The
`validate-run` command enforces this boundary and returns `BLOCKED` when no
container runtime is available. Do not run untrusted validation commands
directly on a developer workstation or weaken the isolation flags to force a
result.
