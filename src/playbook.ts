import type { AuditPlaybook, AuditConfig, PlaybookRule } from "./types.js";

export const defaultConfig: AuditConfig = {
  schemaVersion: 1,
  ignore: ["node_modules", ".git", "dist", "build", "coverage", "audit-runs"],
  includeExtensions: [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"],
  playbook: "audit.playbook.json",
  tokenBudget: 12000,
};

const defaultRules: PlaybookRule[] = [
  {
    id: "JS-DYNAMIC-CODE-001",
    title: "Dynamic code execution from a JavaScript/TypeScript call site",
    description:
      "eval() and new Function() create a code execution boundary. Reachability and input control must be verified before this can be reported as a vulnerability.",
    severity: "CRITICAL",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.mjs", "**/*.cjs"],
    enabled: true,
  },
  {
    id: "JS-COMMAND-INJECTION-001",
    title: "Request or user input reaches a command execution API",
    description:
      "A request-controlled value appears in a child_process execution call. A verifier must prove attacker reachability and command impact.",
    severity: "CRITICAL",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.mjs", "**/*.cjs"],
    enabled: true,
  },
  {
    id: "JS-OPEN-REDIRECT-001",
    title: "Request-controlled redirect target",
    description:
      "A redirect target appears to use request-controlled data. Verify whether an allowlist or same-origin constraint exists.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.mjs", "**/*.cjs"],
    enabled: true,
  },
  {
    id: "JS-SQL-INJECTION-001",
    title: "Request-controlled value reaches a query execution call",
    description:
      "A request-controlled value appears in a query or execute call. Parameterization and actual reachability must be verified.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.mjs", "**/*.cjs"],
    enabled: true,
  },
  {
    id: "PY-DYNAMIC-CODE-001",
    title: "Dynamic code execution from a Python call site",
    description:
      "eval() and exec() create a Python code execution boundary. Reachability and input control must be verified before this can be reported as a vulnerability.",
    severity: "CRITICAL",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-REFLECTED-XSS-001",
    title: "Request-controlled value reaches an HTML response construction path in Python",
    description:
      "An external value appears to be concatenated or formatted into HTML. Output encoding and the actual response context must be independently verified.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-MISSING-AUTH-001",
    title: "Dangerous Python route lacks an observed authentication boundary",
    description:
      "A Flask route containing a high-impact operation has no local authentication or authorization guard. Middleware and deployment policy must be checked before closure.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-CLEARTEXT-PASSWORD-001",
    title: "Request-controlled password reaches Python storage",
    description:
      "A request-controlled password appears to be assigned to a persistence object without an observed one-way hash boundary.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-SENSITIVE-DATA-EXPOSURE-001",
    title: "Python response exposes sensitive or debug data",
    description:
      "A response path uses a debug serializer or sensitive record shape. Endpoint reachability and authorization must be verified independently.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-ERROR-DISCLOSURE-001",
    title: "Python response exposes internal validation detail",
    description:
      "Validation exception detail appears to flow into a client-facing response.",
    severity: "MEDIUM",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-MASS-ASSIGNMENT-001",
    title: "Request-controlled data reaches a privileged Python attribute",
    description:
      "A privilege-bearing field appears to be accepted from a request body without an observed field allowlist.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-IDOR-001",
    title: "Python object lookup uses a caller-controlled identifier without an owner constraint",
    description:
      "A path-like identifier appears to select an object without binding the query to the authenticated subject.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-USER-ENUMERATION-001",
    title: "Python authentication flow reveals account existence",
    description:
      "Distinct authentication responses may reveal whether a username or account exists.",
    severity: "MEDIUM",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-RATE-LIMIT-001",
    title: "Python API surface lacks an observed rate-limiting boundary",
    description:
      "An API registration call has no local rate-limiting evidence; gateway and deployment controls must be checked.",
    severity: "MEDIUM",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-REGEX-DOS-001",
    title: "User-influenced Python regex may backtrack catastrophically",
    description:
      "A regex with nested quantifiers appears on a request-processing path and may enable denial of service.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-COMMAND-INJECTION-001",
    title: "Request or user input reaches a Python command execution API",
    description:
      "A request-controlled value appears in os.system, os.popen, or subprocess execution. A verifier must prove attacker reachability and command impact.",
    severity: "CRITICAL",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-SQL-INJECTION-001",
    title: "Request-controlled value reaches a Python query execution call",
    description:
      "A request-controlled value appears in a database execute call. Parameterization and actual reachability must be independently verified.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-SSTI-001",
    title: "Request-controlled template source in Python",
    description:
      "User-controlled data appears to reach a server-side template source. A validator must demonstrate template expression impact.",
    severity: "CRITICAL",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-SSRF-001",
    title: "Request-controlled URL reaches a Python outbound request API",
    description:
      "A request-controlled URL appears to reach an outbound request sink. Scheme, host, port, DNS, and redirect policy require verification.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-OPEN-REDIRECT-001",
    title: "Request-controlled redirect target in Python",
    description:
      "A redirect target appears to use request-controlled data. Same-origin and allowlist constraints require verification.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-XXE-001",
    title: "Untrusted XML reaches an unsafe Python parser",
    description:
      "Request-controlled XML reaches an XML parser or entity-capable configuration. External entities and network access require independent validation.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-UNSAFE-DESERIALIZATION-001",
    title: "Untrusted data reaches unsafe Python deserialization",
    description:
      "User-controlled bytes reach pickle, marshal, or an unsafe YAML loader. A validator must prove object construction or execution impact.",
    severity: "CRITICAL",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-PATH-TRAVERSAL-001",
    title: "Request-controlled path reaches a Python file sink",
    description:
      "An external path reaches open or file-serving code without a proven containment policy.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-HARDCODED-CREDENTIAL-001",
    title: "Credential-like literal in Python source",
    description:
      "Secret-shaped literals in Python source may be active credentials. Rotate and verify their deployment boundary before closing the obligation.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-DEBUG-MODE-001",
    title: "Python application debug mode enabled",
    description:
      "Debug mode can expose stack traces and interactive tooling. Deployment configuration must be checked before treating this as exploitable.",
    severity: "MEDIUM",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
];

export const defaultPlaybook: AuditPlaybook = {
  schemaVersion: 1,
  id: "evo-audit-default",
  version: "0.1.0",
  evidencePolicy: {
    reportableTiers: ["T2_REPRODUCIBLE"],
    neverTreatNoMatchAsSafe: true,
  },
  rules: defaultRules,
};
