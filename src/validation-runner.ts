import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import path from "node:path";
import type { AuditRun, EvidenceItem, ValidationCommandResult, ValidationRequest, ValidationResult } from "./types.js";

interface SandboxExecution {
  command: string;
  exitCode: number | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function bounded(value: string, max = 600): string {
  return value.length <= max ? value : `${value.slice(0, max)}...[truncated]`;
}

function commandResult(result: SandboxExecution): ValidationCommandResult {
  return {
    command: result.command,
    exitCode: result.exitCode,
    timedOut: result.timedOut,
    passed: result.exitCode === 0 && !result.timedOut,
    stdoutDigest: digest(result.stdout),
    stderrDigest: digest(result.stderr),
  };
}

function spawnCommand(command: string, args: string[], timeoutMs: number): Promise<SandboxExecution> {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"], windowsHide: true, shell: false });
    const append = (target: "stdout" | "stderr", chunk: Buffer): void => {
      const value = chunk.toString("utf8");
      if (target === "stdout") stdout = bounded(`${stdout}${value}`, 64 * 1024);
      else stderr = bounded(`${stderr}${value}`, 64 * 1024);
    };
    child.stdout?.on("data", (chunk: Buffer) => append("stdout", chunk));
    child.stderr?.on("data", (chunk: Buffer) => append("stderr", chunk));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, Math.max(100, timeoutMs));
    child.on("error", (error) => {
      clearTimeout(timer);
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      resolve({ command: `${command} ${args.map((arg) => JSON.stringify(arg)).join(" ")}`, exitCode: code, timedOut, stdout, stderr });
    });
  });
}

async function findContainerRuntime(): Promise<string | null> {
  for (const candidate of process.platform === "win32" ? ["docker.exe", "podman.exe"] : ["docker", "podman"]) {
    try {
      const probe = await spawnCommand(candidate, ["version", "--format", "{{.Server.Version}}"], 5_000);
      if (probe.exitCode === 0 && !probe.timedOut) return candidate;
    } catch {
      // Try the next isolated runtime. A missing daemon is handled as blocked.
    }
  }
  return null;
}

async function executeInContainer(run: AuditRun, command: string, request: ValidationRequest): Promise<SandboxExecution> {
  const runtime = await findContainerRuntime();
  if (!runtime) throw new Error("No Docker or Podman runtime is available for isolated validation.");
  const root = path.resolve(run.root);
  const image = request.image ?? "node:22-alpine";
  const args = [
    "run", "--rm",
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--user", "1000:1000",
    "--pids-limit", "128",
    "--memory", "512m",
    "--cpus", "1",
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
    "-v", `${root}:/workspace:ro`,
    "-w", "/workspace",
    image,
    "sh", "-lc", command,
  ];
  return spawnCommand(runtime, args, request.timeoutMs);
}

function evidenceFor(name: string, result: ValidationCommandResult): EvidenceItem {
  return {
    type: "TOOL_RESULT",
    title: name,
    detail: `exit=${result.exitCode ?? "none"} passed=${result.passed} timedOut=${result.timedOut} stdoutDigest=${result.stdoutDigest} stderrDigest=${result.stderrDigest}`,
    reproducible: result.passed,
  };
}

function blockedCommand(command: string, reason: string): ValidationCommandResult {
  const stderr = reason;
  return { command, exitCode: null, timedOut: false, passed: false, stdoutDigest: digest(""), stderrDigest: digest(stderr) };
}

export async function runValidationRequest(run: AuditRun, request: ValidationRequest, validator: string): Promise<ValidationResult> {
  const base = {
    schemaVersion: 1 as const,
    validator,
    requestId: request.requestId,
    runId: request.runId,
    findingId: request.findingId,
    baseTreeDigest: run.snapshot.treeDigest,
    sourceFiles: run.files,
    sandbox: { profile: request.sandboxProfile, readOnlySource: true, network: "DENY" as const },
  };
  if (request.sandboxProfile !== "READ_ONLY_NO_NETWORK" && request.sandboxProfile !== "READ_ONLY_ALLOWLIST") {
    const reason = "Unsupported sandbox profile.";
    return { ...base, outcome: "HARNESS_FAILED", reproducer: blockedCommand(request.reproducerCommand, reason), negativeControl: blockedCommand(request.negativeControlCommand, reason), notes: [reason] };
  }
  try {
    const positive = await executeInContainer(run, request.reproducerCommand, request);
    const negative = await executeInContainer(run, request.negativeControlCommand, request);
    const reproducer = commandResult(positive);
    const negativeControl = commandResult(negative);
    const outcome = positive.timedOut || negative.timedOut ? "BLOCKED" : reproducer.passed && negativeControl.passed ? "VERIFIED" : "REJECTED";
    return {
      ...base,
      outcome,
      reproducer,
      negativeControl,
      evidence: [evidenceFor("Sandbox positive control", reproducer), evidenceFor("Sandbox negative control", negativeControl)],
      notes: [
        `Validation ran in ${request.image ?? "node:22-alpine"} with a read-only source mount and network disabled.`,
        `Positive stdout/stderr previews: ${bounded(positive.stdout)} / ${bounded(positive.stderr)}`,
        `Negative stdout/stderr previews: ${bounded(negative.stdout)} / ${bounded(negative.stderr)}`,
      ],
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      ...base,
      outcome: "BLOCKED",
      reproducer: blockedCommand(request.reproducerCommand, reason),
      negativeControl: blockedCommand(request.negativeControlCommand, reason),
      evidence: [{ type: "LIMITATION", title: "Sandbox unavailable", detail: reason, reproducible: false }],
      notes: ["Validation did not fall back to host execution.", reason],
    };
  }
}
