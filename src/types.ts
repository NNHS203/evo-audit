export type FindingStatus =
  | "SUSPECTED"
  | "SUPPORTED"
  | "VERIFIED"
  | "REJECTED"
  | "DUPLICATE"
  | "UNKNOWN"
  | "NOT_TESTED"
  | "HARNESS_FAILED";

export type EvidenceTier =
  | "T0_HYPOTHESIS"
  | "T1_STATIC_PATH"
  | "T2_REPRODUCIBLE";

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ObligationStatus = "OPEN" | "SATISFIED" | "BLOCKED" | "REJECTED" | "UNKNOWN";

export interface AuditConfig {
  schemaVersion: 1;
  ignore: string[];
  includeExtensions: string[];
  playbook: string;
  tokenBudget: number;
}

export type ModelTransport = "OPENAI_COMPATIBLE" | "ANTHROPIC";
export type ModelAuthMethod = "API_KEY" | "OAUTH" | "NONE";
export type ModelCapability = "HUNT" | "INVESTIGATE" | "VALIDATE" | "JSON";

export interface OAuthModelConfig {
  authorizationUrl: string;
  tokenUrl: string;
  clientId: string;
  scopes: string[];
  redirectUri?: string;
  accessTokenEnv?: string;
  tokenFile?: string;
  clientSecretEnv?: string;
  extraAuthorizationParams?: Record<string, string>;
}

export interface ModelAuthConfig {
  method: ModelAuthMethod;
  apiKeyEnv?: string;
  accessTokenEnv?: string;
  tokenFile?: string;
  oauth?: OAuthModelConfig;
}

export interface ModelDefinition {
  id: string;
  transport: ModelTransport;
  model: string;
  baseUrl: string;
  auth: ModelAuthConfig;
  qualityTier: number;
  capabilities: ModelCapability[];
  maxContextTokens?: number;
  pricing?: {
    inputPerMillionUsd: number;
    outputPerMillionUsd: number;
  };
  enabled?: boolean;
}

export interface AutoModelPolicy {
  enabled: boolean;
  preferred?: string[];
  minimumQualityTier?: number;
  maxCostPerRunUsd?: number;
}

export interface AuditModelConfig {
  schemaVersion: 1;
  models: ModelDefinition[];
  auto: AutoModelPolicy;
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

export interface AuditSnapshot {
  treeDigest: string;
  revision: string | null;
  capturedAt: string;
  files: FileFingerprint[];
}

export interface AuditCoverage {
  complete: boolean;
  strategy: "FULL_SCAN" | "DIFF" | "PARTIAL";
  semantic: "STATIC_ONLY" | "PARTIAL_WORKER" | "VALIDATED";
  filesReviewed: string[];
  unknownReason?: string;
}

export type WorkflowTaskStatus = "PENDING" | "WAITING" | "COMPLETED" | "BLOCKED" | "DEFERRED";

export interface ModuleGraphEdge {
  from: string;
  to: string;
  specifier: string;
}

export interface AuditRecon {
  schemaVersion: 1;
  projectKind: "NODE_TYPESCRIPT" | "NODE_JAVASCRIPT" | "UNKNOWN";
  ruleInventory: Array<{ id: string; title: string; severity: Severity; evidenceRequired: EvidenceTier }>;
  manifests: string[];
  scripts: Record<string, string>;
  entrypoints: string[];
  securitySurface: Array<{ file: string; signals: string[] }>;
  moduleGraph: {
    nodes: number;
    edgeCount: number;
    unresolvedImports: number;
    edges: ModuleGraphEdge[];
  };
  codeGraph?: import("./graph.js").AuditCodeGraph;
  coverageMatrix?: AuditCoverageMatrix;
  focusFiles: string[];
  contextDigest: string;
  notes: string[];
}

export interface AuditContextSlice {
  targetFiles: string[];
  files: Array<{
    path: string;
    relation: "TARGET" | "IMPORTS" | "IMPORTED_BY" | "CHANGED" | "SURFACE";
    distance: number;
  }>;
  truncated: boolean;
  rationale: string[];
}

export type CoverageCellStatus = "HUNT_REQUIRED" | "CANDIDATE" | "VALIDATED" | "UNKNOWN";

export interface AuditCoverageCell {
  id: string;
  area: string;
  ruleId: string;
  files: string[];
  status: CoverageCellStatus;
  evidence: string[];
}

export interface AuditCoverageMatrix {
  schemaVersion: 1;
  cells: AuditCoverageCell[];
  unknownCells: number;
  digest: string;
  notes: string[];
}

export interface AuditTask {
  id: string;
  phase: "HUNT" | "INVESTIGATE" | "VALIDATE";
  findingId: string | null;
  obligationId: string | null;
  ruleId?: string;
  title: string;
  priority: number;
  status: WorkflowTaskStatus;
  budgetTokens: number;
  context: AuditContextSlice;
  dependsOn: string[];
  rationale: string[];
  coverageCellId?: string;
}

export interface AuditPlan {
  schemaVersion: 1;
  runId: string;
  tokenBudget: number;
  allocatedTokens: number;
  unallocatedTokens: number;
  tasks: AuditTask[];
  notes: string[];
}

export interface TokenAccounting {
  inputTokens: number;
  outputTokens: number;
  cachedTokens: number;
  estimatedCostUsd: number;
  source: "DETERMINISTIC" | "WORKER_REPORTED" | "UNKNOWN";
}

export interface TokenUsageTotals {
  inputTokens: number;
  outputTokens: number;
  cachedTokens: number;
  totalTokens: number;
  estimatedCostUsd: number;
}

export interface AuditSessionUsage {
  schemaVersion: 1;
  sessionId: string;
  root: string;
  startedAt: string;
  updatedAt: string;
  total: TokenUsageTotals;
  runs: Array<{
    runId: string;
    usage: TokenUsageTotals;
  }>;
}

export interface AuditRun {
  schemaVersion: 1;
  runId: string;
  startedAt: string;
  completedAt: string;
  root: string;
  sessionId?: string;
  baseline: string | null;
  head: string | null;
  mode: "WORKTREE" | "DIFF" | "PATH";
  playbook: Pick<AuditPlaybook, "id" | "version">;
  files: FileFingerprint[];
  snapshot: AuditSnapshot;
  coverage: AuditCoverage;
  recon?: AuditRecon;
  plan?: AuditPlan;
  semanticDelta: SemanticDelta;
  obligations: AuditObligation[];
  findings: Finding[];
  reportableFindingIds: string[];
  tokenAccounting: TokenAccounting;
  notes: string[];
}

export interface AuditWorkerContext {
  run: AuditRun;
  playbook: AuditPlaybook;
  obligation?: AuditObligation;
  workspaceRoot: string;
  context?: AuditContextSlice;
  task?: AuditTask;
}

export interface AuditWorkerResult {
  worker: string;
  taskId?: string;
  error?: string;
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

export interface ValidationRequest {
  schemaVersion: 1;
  requestId: string;
  runId: string;
  findingId: string;
  baseTreeDigest: string;
  targetFiles: string[];
  reproducerCommand: string;
  negativeControlCommand: string;
  timeoutMs: number;
  sandboxProfile: "READ_ONLY_NO_NETWORK" | "READ_ONLY_ALLOWLIST";
  image?: string;
}

export interface ValidationCommandResult {
  command: string;
  exitCode: number | null;
  timedOut: boolean;
  passed: boolean;
  stdoutDigest: string;
  stderrDigest: string;
}

export interface ValidationResult {
  schemaVersion: 1;
  validator: string;
  requestId: string;
  runId: string;
  findingId: string;
  outcome: "VERIFIED" | "REJECTED" | "BLOCKED" | "HARNESS_FAILED";
  baseTreeDigest: string;
  sourceFiles: FileFingerprint[];
  sandbox: {
    profile: "READ_ONLY_NO_NETWORK" | "READ_ONLY_ALLOWLIST" | "HOST_UNSAFE";
    readOnlySource: boolean;
    network: "DENY" | "ALLOWLIST" | "UNRESTRICTED";
  };
  reproducer: ValidationCommandResult;
  negativeControl: ValidationCommandResult;
  evidence?: EvidenceItem[];
  notes?: string[];
}

export interface AuditWorker {
  id: string;
  capabilities: string[];
  investigate(context: AuditWorkerContext): Promise<AuditWorkerResult>;
}
