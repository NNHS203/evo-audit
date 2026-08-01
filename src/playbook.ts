import type { AuditPlaybook, AuditConfig, PlaybookRule } from "./types.js";

export const defaultConfig: AuditConfig = {
  schemaVersion: 1,
  ignore: ["node_modules", ".git", "dist", "build", "coverage", "audit-runs"],
  includeExtensions: [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".html", ".htm", ".jinja", ".jinja2"],
  playbook: "audit.playbook.json",
  tokenBudget: 12000,
};

const defaultRules: PlaybookRule[] = [
  {
    id: "CONFIG-WAF-DISABLED-001",
    title: "Reverse-proxy WAF is disabled",
    description:
      "A deployment configuration disables a WAF engine while retaining local security rules. The active profile and compensating controls require verification.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/Caddyfile", "Caddyfile", "**/*.conf"],
    enabled: true,
  },
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
    id: "TEMPLATE-UNSAFE-OUTPUT-001",
    title: "Template renders a value through an unsafe output mode",
    description:
      "A Jinja or Django template explicitly disables escaping for a value. The value's provenance and sanitizer contract must be verified before closure.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.html", "**/*.htm", "**/*.jinja", "**/*.jinja2"],
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
    id: "PY-NOSQL-INJECTION-001",
    title: "Structured request data reaches a Python NoSQL query",
    description:
      "A raw request object appears to reach a Mongo-like query API. Fixed-key scalar lookups are kept separate from operator-bearing query objects.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-WEAK-PASSWORD-HASH-001",
    title: "Password processed with a weak or fast hash",
    description:
      "A password-like value is passed to a general-purpose hash such as MD5 or SHA-1 instead of a password-specific memory-hard function.",
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
    id: "PY-UNRESTRICTED-FILE-UPLOAD-001",
    title: "Uploaded Python file reaches storage without a content policy",
    description:
      "An uploaded file reaches a save or write sink without an observed type, content, or extension allowlist.",
    severity: "HIGH",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-WEAK-RANDOMNESS-001",
    title: "Non-cryptographic randomness used for a security value",
    description:
      "A predictable random source appears to generate a session, token, secret, nonce, or shortened identifier.",
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
  {
    id: "PY-INSECURE-COOKIE-001",
    title: "Python response sets an authentication cookie without transport flags",
    description:
      "A response sets a session or authentication cookie without an observed Secure or HttpOnly attribute. Deployment and framework defaults must be verified before closure.",
    severity: "MEDIUM",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-SESSION-INTEGRITY-001",
    title: "Python session cookie is derived without an observed integrity boundary",
    description:
      "A session-like cookie appears to carry merely encoded or serialized client-controlled state without a signing or authenticated-encryption boundary. Runtime exploitability and framework defaults must be verified before closure.",
    severity: "CRITICAL",
    evidenceRequired: "T2_REPRODUCIBLE",
    globs: ["**/*.py"],
    enabled: true,
  },
  {
    id: "PY-SECURITY-MISCONFIGURATION-001",
    title: "Python security configuration weakens a host or debug boundary",
    description:
      "A Python deployment setting accepts arbitrary hosts or otherwise weakens a security boundary. The active environment and compensating controls require verification.",
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
