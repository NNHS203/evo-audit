import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import type { AuditRun, AuditSessionUsage, TokenAccounting, TokenUsageTotals } from "./types.js";

function nonNegative(value: number): number {
  return Number.isFinite(value) && value >= 0 ? value : 0;
}

export function tokenUsageTotals(accounting: TokenAccounting): TokenUsageTotals {
  const inputTokens = nonNegative(accounting.inputTokens);
  const outputTokens = nonNegative(accounting.outputTokens);
  return {
    inputTokens,
    outputTokens,
    cachedTokens: nonNegative(accounting.cachedTokens),
    totalTokens: inputTokens + outputTokens,
    estimatedCostUsd: nonNegative(accounting.estimatedCostUsd),
  };
}

function zeroUsage(): TokenUsageTotals {
  return { inputTokens: 0, outputTokens: 0, cachedTokens: 0, totalTokens: 0, estimatedCostUsd: 0 };
}

function sumUsage(usages: TokenUsageTotals[]): TokenUsageTotals {
  return usages.reduce(
    (total, usage) => ({
      inputTokens: total.inputTokens + usage.inputTokens,
      outputTokens: total.outputTokens + usage.outputTokens,
      cachedTokens: total.cachedTokens + usage.cachedTokens,
      totalTokens: total.totalTokens + usage.totalTokens,
      estimatedCostUsd: total.estimatedCostUsd + usage.estimatedCostUsd,
    }),
    zeroUsage(),
  );
}

async function readSession(file: string): Promise<AuditSessionUsage | null> {
  try {
    return JSON.parse(await fs.readFile(file, "utf8")) as AuditSessionUsage;
  } catch {
    return null;
  }
}

export async function recordSessionUsage(sessionDirectory: string, run: AuditRun): Promise<AuditSessionUsage> {
  const file = path.join(sessionDirectory, "session.json");
  const existing = await readSession(file);
  const now = new Date().toISOString();
  const sessionId = existing?.sessionId ?? randomUUID();
  const usage = tokenUsageTotals(run.tokenAccounting);
  const runs = [...(existing?.runs ?? []).filter((item) => item.runId !== run.runId), { runId: run.runId, usage }]
    .sort((left, right) => left.runId.localeCompare(right.runId));
  const session: AuditSessionUsage = {
    schemaVersion: 1,
    sessionId,
    root: existing && existing.root !== run.root ? "<multiple-roots>" : run.root,
    startedAt: existing?.startedAt ?? now,
    updatedAt: now,
    total: sumUsage(runs.map((item) => item.usage)),
    runs,
  };
  await fs.mkdir(sessionDirectory, { recursive: true });
  await fs.writeFile(file, `${JSON.stringify(session, null, 2)}\n`, "utf8");
  return session;
}

export function formatTokenUsage(usage: TokenUsageTotals): string {
  return `total=${usage.totalTokens} (input=${usage.inputTokens}, output=${usage.outputTokens}, cached=${usage.cachedTokens})`;
}
