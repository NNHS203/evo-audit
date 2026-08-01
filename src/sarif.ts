import { findingIdentity } from "./compare.js";
import type { AuditRun, Finding } from "./types.js";

function level(finding: Finding): "error" | "warning" | "note" {
  if (finding.severity === "CRITICAL" || finding.severity === "HIGH") return "error";
  if (finding.severity === "MEDIUM") return "warning";
  return "note";
}

export function toSarif(run: AuditRun): Record<string, unknown> {
  const rules = new Map(run.findings.map((finding) => [finding.ruleId, finding]));
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "evo-audit",
            version: run.playbook.version,
            rules: [...rules.values()].map((finding) => ({
              id: finding.ruleId,
              name: finding.title,
              shortDescription: { text: finding.title },
              help: { text: finding.remediation },
            })),
          },
        },
        automationDetails: { id: `evo-audit/${run.runId}` },
        results: run.findings.map((finding) => {
          const location = finding.locations[0];
          return {
            ruleId: finding.ruleId,
            level: level(finding),
            message: { text: `${finding.rootCause} ${finding.impact}` },
            locations: location
              ? [{ physicalLocation: { artifactLocation: { uri: location.file }, region: { startLine: location.line, startColumn: location.column } } }]
              : [],
            fingerprints: { "evo-audit/identity": findingIdentity(finding) },
            properties: {
              status: finding.status,
              evidenceTier: finding.evidenceTier,
              obligationId: finding.obligationId,
              limitations: finding.limitations,
            },
          };
        }),
      },
    ],
  };
}
