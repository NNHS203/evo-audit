export type FindingStatus =
  | "SUSPECTED"
  | "SUPPORTED"
  | "VERIFIED"
  | "NOT_TESTED"
  | "HARNESS_FAILED";

export type EvidenceTier =
  | "T0_HYPOTHESIS"
  | "T1_STATIC_PATH"
  | "T2_REPRODUCIBLE";

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ObligationStatus = "OPEN" | "SATISFIED" | "BLOCKED";

export interface AuditConfig {
  schemaVersion: 1;
  ignore: string[];
  includeExtensions: string[];
  playbook: string;
  tokenBudget: number;
}

export interface PlaybookRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  evidenceRequired: EvidenceTier;
  globs: string[];
  enabled: boolean;
}

export interface AuditPlaybook {
  schemaVersion: 1;
  id: string;
  version: string;
  evidencePolicy: {
    reportableTiers: EvidenceTier[];
    neverTreatNoMatchAsSafe: boolean;
  };
  rules: PlaybookRule[];
}

export interface SourceLocation {
  file: string;
  line: number;
  column: number;
  endLine: number;
  snippet: string;
}

export interface EvidenceItem {
  type: "STATIC_PATTERN" | "TRACE" | "REPRODUCER" | "TOOL_RESULT" | "LIMITATION";
  title: string;
  detail: string;
  locations?: SourceLocation[];
  reproducible: boolean;
}

export interface AuditObligation {
  id: string;
  kind: "SOURCE_TO_SINK" | "AUTHORIZATION_BOUNDARY" | "DYNAMIC_CODE" | "CUSTOM";
  title: string;
  status: ObligationStatus;
  targetFiles: string[];
  falsifiers: string[];
  evidenceRequired: EvidenceTier;
  createdBy: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  obligationId: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  evidenceTier: EvidenceTier;
  rootCause: string;
  impact: string;
  remediation: string;
  locations: SourceLocation[];
  evidence: EvidenceItem[];
  limitations: string[];
  worker?: string;
}

export interface FileFingerprint {
  path: string;
  sha256: string;
  bytes: number;
}

export interface SemanticDelta {
  basis: "FULL_SCAN" | "BASELINE_RUN";
  changed: string[];
  added: string[];
  removed: string[];
  unchanged: string[];
  workerHint: string;
}

export interface TokenAccounting {
  inputTokens: number;
  outputTokens: number;
  cachedTokens: number;
  estimatedCostUsd: number;
  source: "DETERMINISTIC" | "WORKER_REPORTED" | "UNKNOWN";
}

export interface AuditRun {
  schemaVersion: 1;
  runId: string;
  startedAt: string;
  completedAt: string;
  root: string;
  baseline: string | null;
  head: string | null;
  mode: "WORKTREE" | "DIFF" | "PATH";
  playbook: Pick<AuditPlaybook, "id" | "version">;
  files: FileFingerprint[];
  semanticDelta: SemanticDelta;
  obligations: AuditObligation[];
  findings: Finding[];
  tokenAccounting: TokenAccounting;
  notes: string[];
}

export interface AuditWorkerContext {
  run: AuditRun;
  playbook: AuditPlaybook;
  obligation: AuditObligation;
  workspaceRoot: string;
}

export interface AuditWorkerResult {
  worker: string;
  findings: Array<
    Partial<Finding> & {
      ruleId: string;
      title: string;
      status: FindingStatus;
      evidenceTier: EvidenceTier;
    }
  >;
  tokenAccounting?: Partial<TokenAccounting>;
  notes?: string[];
}

export interface AuditWorker {
  id: string;
  capabilities: string[];
  investigate(context: AuditWorkerContext): Promise<AuditWorkerResult>;
}
