#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { groundTruthLabelsFromValue, scannerFindingsFromRun } from "../dist/src/scoring.js";

const aggregatePath = process.argv[2];
if (!aggregatePath) {
  console.error("Usage: node scripts/realvuln-gaps.mjs <realvuln-aggregate.json>");
  process.exit(2);
}
const focusRule = process.argv[3];

const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const aggregate = readJson(path.resolve(aggregatePath));
const aggregateDir = path.dirname(path.resolve(aggregatePath));

function normalizedFile(value) {
  return String(value).replace(/^file:\/\//i, "").replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\/+/, "");
}

function expectedLocations(label) {
  return [{ file: label.file, startLine: label.startLine, endLine: label.endLine }, ...(label.alternateLocations ?? [])];
}

function locationMatches(finding, label) {
  return expectedLocations(label).some((expected) => finding.locations.some((location) => {
    if (normalizedFile(location.file) !== normalizedFile(expected.file)) return false;
    const expectedStart = Math.max(1, Math.floor(expected.startLine));
    const expectedEnd = Math.max(expectedStart, Math.floor(expected.endLine ?? expected.startLine));
    const actualStart = Math.max(1, Math.floor(location.startLine));
    const actualEnd = Math.max(actualStart, Math.floor(location.endLine ?? location.startLine));
    return actualStart <= expectedEnd + 10 && actualEnd >= expectedStart - 10;
  }));
}

function matches(finding, label) {
  if (label.ruleIds?.length) {
    const findingRuleIds = new Set([finding.ruleId, ...(finding.ruleIds ?? [])]);
    if (!label.ruleIds.some((ruleId) => findingRuleIds.has(ruleId))) return false;
  }
  return locationMatches(finding, label);
}

function specificity(finding, label) {
  if (!label.ruleIds?.length) return 0;
  const findingRuleIds = new Set([finding.ruleId, ...(finding.ruleIds ?? [])]);
  if (findingRuleIds.has(label.ruleIds[0])) return 2;
  return label.ruleIds.some((ruleId) => findingRuleIds.has(ruleId)) ? 1 : -1;
}

function locationDistance(finding, label) {
  let best = Number.POSITIVE_INFINITY;
  for (const expected of expectedLocations(label)) {
    for (const actual of finding.locations) {
      if (normalizedFile(actual.file) !== normalizedFile(expected.file)) continue;
      const expectedStart = Math.max(1, Math.floor(expected.startLine));
      const expectedEnd = Math.max(expectedStart, Math.floor(expected.endLine ?? expected.startLine));
      const actualStart = Math.max(1, Math.floor(actual.startLine));
      const actualEnd = Math.max(actualStart, Math.floor(actual.endLine ?? actual.startLine));
      const distance = actualStart <= expectedEnd && actualEnd >= expectedStart
        ? 0
        : Math.min(Math.abs(actualStart - expectedEnd), Math.abs(expectedStart - actualEnd));
      best = Math.min(best, distance);
    }
  }
  return best;
}

function increment(map, key) {
  map[key] = (map[key] ?? 0) + 1;
}

function top(map, limit = 30) {
  return Object.entries(map)
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, limit)
    .map(([key, count]) => ({ key, count }));
}

const falseNegativeCwe = {};
const falseNegativeClass = {};
const falseNegativeFramework = {};
const falsePositiveRule = {};
const falsePositiveFramework = {};
const truePositiveRule = {};
const truePositiveExamples = {};
const falsePositiveExamples = {};
const falseNegativeExamples = {};
let totalFindings = 0;
let totalLabels = 0;
let truePositive = 0;
let falsePositive = 0;
let falseNegative = 0;

for (const entry of (aggregate.entries ?? []).filter((item) => item.status === "COMPLETED")) {
  const report = readJson(path.resolve(aggregateDir, entry.report));
  const reportDir = path.dirname(path.resolve(aggregateDir, entry.report));
  const run = readJson(path.join(reportDir, "audit-runs", report.audit.runId, "run.json"));
  const groundTruthPath = path.isAbsolute(report.groundTruth.path)
    ? report.groundTruth.path
    : path.resolve(reportDir, report.groundTruth.path);
  const groundTruth = readJson(groundTruthPath);
  const rawFindings = new Map((groundTruth.findings ?? []).map((finding) => [finding.id, finding]));
  const labels = groundTruthLabelsFromValue(groundTruth, "REALVULN");
  const findings = scannerFindingsFromRun(run);
  const available = labels
    .map((label, index) => ({ label, index }))
    .sort((left, right) => Number(right.label.vulnerable) - Number(left.label.vulnerable) || left.index - right.index);
  const matched = new Set();
  const framework = report.repository.framework ?? report.repository.language ?? "unknown";

  totalFindings += findings.length;
  totalLabels += labels.length;
  for (const finding of findings) {
    const match = available
      .filter((candidate) => !matched.has(candidate.index) && matches(finding, candidate.label))
      .sort((left, right) => specificity(finding, right.label) - specificity(finding, left.label)
        || locationDistance(finding, left.label) - locationDistance(finding, right.label)
        || Number(right.label.vulnerable) - Number(left.label.vulnerable)
        || left.index - right.index)[0];
    if (!match) {
      falsePositive += 1;
      increment(falsePositiveRule, finding.ruleId);
      increment(falsePositiveFramework, framework);
      falsePositiveExamples[finding.ruleId] ??= [];
      if (falsePositiveExamples[finding.ruleId].length < 8) falsePositiveExamples[finding.ruleId].push({ repository: entry.id, framework, locations: finding.locations, title: finding.title });
      continue;
    }
    matched.add(match.index);
    if (match.label.vulnerable) {
      truePositive += 1;
      increment(truePositiveRule, finding.ruleId);
      truePositiveExamples[finding.ruleId] ??= [];
      if (truePositiveExamples[finding.ruleId].length < 100) truePositiveExamples[finding.ruleId].push({ repository: entry.id, framework, locations: finding.locations, title: finding.title });
    } else {
      falsePositive += 1;
      increment(falsePositiveRule, finding.ruleId);
      increment(falsePositiveFramework, framework);
      falsePositiveExamples[finding.ruleId] ??= [];
      if (falsePositiveExamples[finding.ruleId].length < 8) falsePositiveExamples[finding.ruleId].push({ repository: entry.id, framework, locations: finding.locations, title: finding.title });
    }
  }
  for (const candidate of available) {
    if (matched.has(candidate.index) || !candidate.label.vulnerable) continue;
    falseNegative += 1;
    const raw = rawFindings.get(candidate.label.id) ?? {};
    increment(falseNegativeCwe, raw.primary_cwe ?? candidate.label.ruleIds?.[0] ?? "unknown");
    increment(falseNegativeClass, raw.vulnerability_class ?? raw.expected_category ?? "unknown");
    increment(falseNegativeFramework, framework);
    const cwe = raw.primary_cwe ?? candidate.label.ruleIds?.[0] ?? "unknown";
    falseNegativeExamples[cwe] ??= [];
    if (falseNegativeExamples[cwe].length < 5) falseNegativeExamples[cwe].push({ framework, file: candidate.label.file, line: candidate.label.startLine, id: candidate.label.id, vulnerabilityClass: raw.vulnerability_class });
  }
}

const result = {
  repositories: aggregate.completed,
  totalFindings,
  totalLabels,
  truePositive,
  falsePositive,
  falseNegative,
  falseNegativeCwe: top(falseNegativeCwe),
  falseNegativeClass: top(falseNegativeClass),
  falseNegativeFramework: top(falseNegativeFramework),
  falsePositiveRule: top(falsePositiveRule),
  falsePositiveFramework: top(falsePositiveFramework),
  truePositiveRule: top(truePositiveRule),
  falsePositiveExamples,
  falseNegativeExamples,
};

if (focusRule) {
  if (focusRule.startsWith("CWE-")) {
    console.log(JSON.stringify({ cwe: focusRule, falseNegativeExamples: falseNegativeExamples[focusRule] ?? [] }, null, 2));
  } else {
    console.log(JSON.stringify({
      rule: focusRule,
      truePositiveCount: truePositiveRule[focusRule] ?? 0,
      truePositiveExamples: truePositiveExamples[focusRule] ?? [],
      falsePositiveCount: falsePositiveRule[focusRule] ?? 0,
      falsePositiveExamples: falsePositiveExamples[focusRule] ?? [],
    }, null, 2));
  }
} else {
  console.log(JSON.stringify(result, null, 2));
}
