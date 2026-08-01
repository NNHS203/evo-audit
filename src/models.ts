import { createHash, randomBytes, randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { URL } from "node:url";
import type {
  AuditModelConfig,
  AutoModelPolicy,
  ModelAuthConfig,
  ModelDefinition,
  ModelCapability,
  OAuthModelConfig,
  TokenAccounting,
} from "./types.js";

export interface ModelTaskRequest {
  phase: "HUNT" | "INVESTIGATE" | "VALIDATE";
  priority: number;
  estimatedInputTokens: number;
  budgetTokens: number;
  requiredCapabilities?: ModelCapability[];
  model?: string;
}

export interface ModelMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface ModelCompletionRequest extends ModelTaskRequest {
  messages: ModelMessage[];
  maxOutputTokens?: number;
  temperature?: number;
  signal?: AbortSignal;
}

export interface ModelCompletionResponse {
  requestId: string;
  modelId: string;
  providerModel: string;
  text: string;
  usage: TokenAccounting;
  finishReason?: string;
  cacheHit?: boolean;
}

export interface ModelStatus {
  id: string;
  model: string;
  transport: ModelDefinition["transport"];
  enabled: boolean;
  authMethod: ModelAuthConfig["method"];
  credentialAvailable: boolean;
  capabilities: ModelCapability[];
  qualityTier: number;
  reason?: string;
}

const DEFAULT_CONFIG_NAME = "audit.models.json";

function positive(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : fallback;
}

function normalizeConfig(value: unknown): AuditModelConfig {
  if (!value || typeof value !== "object") throw new Error("Model config must be a JSON object.");
  const candidate = value as Partial<AuditModelConfig>;
  if (candidate.schemaVersion !== 1) throw new Error("Unsupported model config schemaVersion; expected 1.");
  if (!Array.isArray(candidate.models)) throw new Error("Model config must contain a models array.");
  const models = candidate.models.map((model) => {
    if (!model || typeof model !== "object") throw new Error("Each model definition must be an object.");
    const item = model as ModelDefinition;
    if (!item.id || !item.model || !item.baseUrl || !item.transport || !item.auth) throw new Error("Each model needs id, model, baseUrl, transport, and auth.");
    if ("apiKey" in (item.auth as unknown as Record<string, unknown>) || "accessToken" in (item.auth as unknown as Record<string, unknown>)) {
      throw new Error(`Model ${item.id} contains a raw credential. Use an environment variable or tokenFile reference.`);
    }
    return {
      ...item,
      baseUrl: item.baseUrl.replace(/\/$/, ""),
      qualityTier: Math.max(0, Math.min(5, Math.floor(positive(item.qualityTier, 3)))),
      capabilities: [...new Set(item.capabilities ?? ["HUNT", "INVESTIGATE", "JSON"])],
      enabled: item.enabled !== false,
    };
  });
  const ids = new Set<string>();
  for (const model of models) {
    if (ids.has(model.id)) throw new Error(`Duplicate model id: ${model.id}`);
    ids.add(model.id);
  }
  const auto: AutoModelPolicy = {
    enabled: candidate.auto?.enabled !== false,
    preferred: candidate.auto?.preferred ?? [],
    minimumQualityTier: candidate.auto?.minimumQualityTier,
    maxCostPerRunUsd: candidate.auto?.maxCostPerRunUsd,
  };
  return { schemaVersion: 1, models, auto };
}

export function defaultModelConfig(): AuditModelConfig {
  return { schemaVersion: 1, models: [], auto: { enabled: true, preferred: [], minimumQualityTier: 1 } };
}

function environmentModelConfig(): AuditModelConfig {
  const modelName = process.env.EVO_AUDIT_MODEL?.trim();
  if (!modelName) return defaultModelConfig();
  const apiKeyEnv = process.env.EVO_AUDIT_API_KEY ? "EVO_AUDIT_API_KEY" : process.env.OPENAI_API_KEY ? "OPENAI_API_KEY" : undefined;
  const oauthEnv = process.env.EVO_AUDIT_OAUTH_TOKEN ? "EVO_AUDIT_OAUTH_TOKEN" : undefined;
  return {
    schemaVersion: 1,
    auto: { enabled: true, preferred: ["env-default"], minimumQualityTier: 1 },
    models: [{
      id: "env-default",
      transport: "OPENAI_COMPATIBLE",
      model: modelName,
      baseUrl: (process.env.EVO_AUDIT_BASE_URL ?? "https://api.openai.com/v1").replace(/\/$/, ""),
      auth: apiKeyEnv ? { method: "API_KEY", apiKeyEnv } : oauthEnv ? { method: "OAUTH", accessTokenEnv: oauthEnv } : { method: "NONE" },
      qualityTier: 3,
      capabilities: ["HUNT", "INVESTIGATE", "VALIDATE", "JSON"],
    }],
  };
}

export async function loadModelConfig(root: string, configPath?: string): Promise<AuditModelConfig> {
  const file = configPath ? path.resolve(root, configPath) : path.join(root, DEFAULT_CONFIG_NAME);
  try {
    return normalizeConfig(JSON.parse(await fs.readFile(file, "utf8")));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return environmentModelConfig();
    throw error;
  }
}

function defaultTokenFile(modelId: string): string {
  return path.join(os.homedir(), ".evo-audit", "oauth", `${modelId}.json`);
}

async function readTokenFile(file: string): Promise<string | null> {
  try {
    const parsed = JSON.parse(await fs.readFile(file, "utf8")) as { access_token?: unknown };
    return typeof parsed.access_token === "string" && parsed.access_token.trim() ? parsed.access_token.trim() : null;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error(`Unable to read OAuth token file ${file}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function credentialFor(model: ModelDefinition): Promise<string | null> {
  const auth = model.auth;
  if (auth.method === "NONE") return null;
  if (auth.method === "API_KEY") return auth.apiKeyEnv ? process.env[auth.apiKeyEnv]?.trim() || null : null;
  const envName = auth.accessTokenEnv ?? auth.oauth?.accessTokenEnv;
  if (envName && process.env[envName]?.trim()) return process.env[envName]!.trim();
  const file = auth.tokenFile ?? auth.oauth?.tokenFile ?? defaultTokenFile(model.id);
  return readTokenFile(file);
}

export async function modelStatuses(config: AuditModelConfig): Promise<ModelStatus[]> {
  return Promise.all(config.models.map(async (model) => {
    const credentialAvailable = model.auth.method === "NONE" || Boolean(await credentialFor(model));
    return {
      id: model.id,
      model: model.model,
      transport: model.transport,
      enabled: model.enabled !== false,
      authMethod: model.auth.method,
      credentialAvailable,
      capabilities: model.capabilities,
      qualityTier: model.qualityTier,
      reason: model.enabled === false ? "disabled" : credentialAvailable ? undefined : "credential unavailable",
    };
  }));
}

function capabilityMatch(model: ModelDefinition, request: ModelTaskRequest): boolean {
  const required = request.requiredCapabilities ?? [request.phase, "JSON"];
  return required.every((capability) => model.capabilities.includes(capability));
}

function modelScore(model: ModelDefinition, request: ModelTaskRequest, policy: AutoModelPolicy): number {
  const preferred = policy.preferred?.indexOf(model.id) ?? -1;
  const preference = preferred >= 0 ? 500 - preferred * 10 : 0;
  const budgetPressure = request.budgetTokens <= 2_000 ? -positive(model.pricing?.inputPerMillionUsd) - positive(model.pricing?.outputPerMillionUsd) : positive(model.qualityTier) * 4;
  const quality = request.priority >= 90 ? model.qualityTier * 30 : model.qualityTier * 12;
  return preference + quality + budgetPressure;
}

function withinAutoCost(model: ModelDefinition, request: ModelTaskRequest, policy: AutoModelPolicy): boolean {
  if (policy.maxCostPerRunUsd === undefined) return true;
  const outputTokens = Math.max(128, request.budgetTokens - request.estimatedInputTokens);
  const estimate = request.estimatedInputTokens / 1_000_000 * positive(model.pricing?.inputPerMillionUsd)
    + outputTokens / 1_000_000 * positive(model.pricing?.outputPerMillionUsd);
  return estimate <= policy.maxCostPerRunUsd;
}

function chooseModel(config: AuditModelConfig, request: ModelTaskRequest): ModelDefinition {
  if (request.model && request.model !== "auto") {
    const exact = config.models.find((candidate) => candidate.id === request.model && candidate.enabled !== false);
    if (!exact) throw new Error(`Model not found or disabled: ${request.model}`);
    if (!capabilityMatch(exact, request)) throw new Error(`Model ${request.model} does not support the required task capabilities.`);
    return exact;
  }
  if (!config.auto.enabled) throw new Error("Auto model routing is disabled and no explicit model was selected.");
  const minimum = positive(config.auto.minimumQualityTier, 0);
  const candidates = config.models.filter((model) => model.enabled !== false && model.qualityTier >= minimum && capabilityMatch(model, request) && withinAutoCost(model, request, config.auto));
  if (candidates.length === 0) throw new Error("No enabled model satisfies the task capabilities and auto-model policy.");
  return [...candidates].sort((left, right) => modelScore(right, request, config.auto) - modelScore(left, request, config.auto) || left.id.localeCompare(right.id))[0];
}

function responseText(value: unknown): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((part) => typeof part === "string" ? part : (part && typeof part === "object" && "text" in part ? String((part as { text: unknown }).text) : "")).join("");
  return "";
}

function usageFrom(value: unknown, model: ModelDefinition): TokenAccounting {
  const usage = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const prompt = positive(usage.prompt_tokens ?? usage.input_tokens);
  const completion = positive(usage.completion_tokens ?? usage.output_tokens);
  const cachedDetails = usage.prompt_tokens_details && typeof usage.prompt_tokens_details === "object" ? usage.prompt_tokens_details as Record<string, unknown> : {};
  const cached = positive(usage.cached_tokens ?? usage.cache_read_input_tokens ?? cachedDetails.cached_tokens);
  const estimatedCostUsd = prompt / 1_000_000 * positive(model.pricing?.inputPerMillionUsd) + completion / 1_000_000 * positive(model.pricing?.outputPerMillionUsd);
  return { inputTokens: prompt, outputTokens: completion, cachedTokens: cached, estimatedCostUsd, source: "WORKER_REPORTED" };
}

async function requestJson(url: string, init: RequestInit, signal?: AbortSignal): Promise<{ body: Record<string, unknown>; headers: Headers }> {
  const response = await fetch(url, { ...init, signal });
  const text = await response.text();
  let body: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed && typeof parsed === "object") body = parsed as Record<string, unknown>;
  } catch {
    // Preserve only a bounded server message; response bodies may contain secrets.
  }
  if (!response.ok) throw new Error(`Model request failed (${response.status}): ${String(body.error ?? body.message ?? text.slice(0, 300))}`);
  return { body, headers: response.headers };
}

async function completeOpenAI(model: ModelDefinition, credential: string | null, request: ModelCompletionRequest): Promise<ModelCompletionResponse> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (credential) headers.authorization = `Bearer ${credential}`;
  const result = await requestJson(`${model.baseUrl}/chat/completions`, {
    method: "POST",
    headers,
    body: JSON.stringify({ model: model.model, messages: request.messages, temperature: request.temperature ?? 0, max_tokens: request.maxOutputTokens ?? Math.max(256, request.budgetTokens - request.estimatedInputTokens), response_format: { type: "json_object" } }),
  }, request.signal);
  const choice = Array.isArray(result.body.choices) ? result.body.choices[0] as Record<string, unknown> | undefined : undefined;
  const message = choice?.message && typeof choice.message === "object" ? choice.message as Record<string, unknown> : {};
  return {
    requestId: String(result.body.id ?? result.headers.get("x-request-id") ?? randomUUID()),
    modelId: model.id,
    providerModel: model.model,
    text: responseText(message.content),
    usage: usageFrom(result.body.usage, model),
    finishReason: typeof choice?.finish_reason === "string" ? choice.finish_reason : undefined,
  };
}

async function completeAnthropic(model: ModelDefinition, credential: string | null, request: ModelCompletionRequest): Promise<ModelCompletionResponse> {
  const system = request.messages.filter((message) => message.role === "system").map((message) => message.content).join("\n\n");
  const messages = request.messages.filter((message) => message.role !== "system");
  const headers: Record<string, string> = { "content-type": "application/json", "anthropic-version": "2023-06-01" };
  if (credential) {
    if (model.auth.method === "API_KEY") headers["x-api-key"] = credential;
    else headers.authorization = `Bearer ${credential}`;
  }
  const result = await requestJson(`${model.baseUrl}/v1/messages`, {
    method: "POST",
    headers,
    body: JSON.stringify({ model: model.model, system: system || undefined, messages, max_tokens: request.maxOutputTokens ?? Math.max(256, request.budgetTokens - request.estimatedInputTokens), temperature: request.temperature ?? 0 }),
  }, request.signal);
  return {
    requestId: String(result.body.id ?? result.headers.get("request-id") ?? randomUUID()),
    modelId: model.id,
    providerModel: model.model,
    text: responseText(result.body.content),
    usage: usageFrom(result.body.usage, model),
    finishReason: typeof result.body.stop_reason === "string" ? result.body.stop_reason : undefined,
  };
}

export class ModelRegistry {
  constructor(private readonly config: AuditModelConfig) {}

  async statuses(): Promise<ModelStatus[]> {
    return modelStatuses(this.config);
  }

  select(request: ModelTaskRequest): ModelDefinition {
    return chooseModel(this.config, request);
  }

  async assertReady(model?: string): Promise<void> {
    const statuses = await this.statuses();
    const relevant = model && model !== "auto" ? statuses.filter((candidate) => candidate.id === model) : statuses.filter((candidate) => candidate.enabled);
    if (relevant.length === 0) throw new Error(model && model !== "auto" ? `Model not found or disabled: ${model}.` : "No enabled models are configured for model-backed work.");
    if (!relevant.some((candidate) => candidate.credentialAvailable)) {
      const reasons = relevant.map((candidate) => `${candidate.id}: ${candidate.reason ?? "credential unavailable"}`).join("; ");
      throw new Error(`No usable credential is available for model-backed work (${reasons}). Configure an API-key environment variable or run evo-audit auth for OAuth.`);
    }
  }

  async complete(request: ModelCompletionRequest): Promise<ModelCompletionResponse> {
    const model = chooseModel(this.config, request);
    const credential = await credentialFor(model);
    if (model.auth.method !== "NONE" && !credential) {
      const reference = model.auth.method === "OAUTH" ? `Run evo-audit auth . ${model.id}` : `set ${model.auth.apiKeyEnv ?? "the configured API-key environment variable"}`;
      throw new Error(`No credential is available for model ${model.id}. ${reference}.`);
    }
    const startedAt = Date.now();
    const response = model.transport === "ANTHROPIC"
      ? await completeAnthropic(model, credential, request)
      : await completeOpenAI(model, credential, request);
    response.usage = { ...response.usage, durationMs: Math.max(0, Date.now() - startedAt) };
    return response;
  }
}

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier, "utf8").digest("base64url");
}

function openBrowser(url: string): void {
  if (process.platform !== "win32") return;
  const child = spawn("cmd", ["/c", "start", "", url], { stdio: "ignore", detached: true, windowsHide: true });
  child.unref();
}

async function listenForOAuthCode(redirect: URL, state: string, timeoutMs: number): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const server = createServer((request, response) => {
      try {
        const current = new URL(request.url ?? "/", `${redirect.protocol}//${redirect.host}`);
        if (current.pathname !== redirect.pathname || current.searchParams.get("state") !== state) {
          response.statusCode = 400;
          response.end("OAuth state mismatch");
          return;
        }
        const code = current.searchParams.get("code");
        response.statusCode = code ? 200 : 400;
        response.end(code ? "Evo Audit authorization complete. You can close this window." : "OAuth authorization failed.");
        server.close();
        if (code) resolve(code);
        else reject(new Error("OAuth provider did not return an authorization code."));
      } catch (error) {
        server.close();
        reject(error);
      }
    });
    const timeout = setTimeout(() => {
      server.close();
      reject(new Error("OAuth authorization timed out."));
    }, timeoutMs);
    server.on("close", () => clearTimeout(timeout));
    const port = redirect.port ? Number(redirect.port) : 0;
    server.listen(port, redirect.hostname || "127.0.0.1");
  });
}

export async function authorizeModel(model: ModelDefinition, options: { timeoutMs?: number; openBrowser?: boolean } = {}): Promise<string> {
  if (model.auth.method !== "OAUTH" || !model.auth.oauth) throw new Error(`Model ${model.id} does not define OAuth settings.`);
  const oauth: OAuthModelConfig = model.auth.oauth;
  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(24).toString("base64url");
  const redirect = new URL(oauth.redirectUri ?? "http://127.0.0.1:8765/oauth/callback");
  const authorization = new URL(oauth.authorizationUrl);
  authorization.searchParams.set("response_type", "code");
  authorization.searchParams.set("client_id", oauth.clientId);
  authorization.searchParams.set("redirect_uri", redirect.toString());
  authorization.searchParams.set("code_challenge", pkceChallenge(verifier));
  authorization.searchParams.set("code_challenge_method", "S256");
  authorization.searchParams.set("state", state);
  if (oauth.scopes.length > 0) authorization.searchParams.set("scope", oauth.scopes.join(" "));
  for (const [key, value] of Object.entries(oauth.extraAuthorizationParams ?? {})) authorization.searchParams.set(key, value);
  if (options.openBrowser !== false) openBrowser(authorization.toString());
  process.stderr.write(`Open this URL to authorize ${model.id}: ${authorization.toString()}\n`);
  const code = await listenForOAuthCode(redirect, state, options.timeoutMs ?? 120_000);
  const form = new URLSearchParams({ grant_type: "authorization_code", code, client_id: oauth.clientId, redirect_uri: redirect.toString(), code_verifier: verifier });
  if (oauth.clientSecretEnv && process.env[oauth.clientSecretEnv]) form.set("client_secret", process.env[oauth.clientSecretEnv]!);
  const tokenResponse = await fetch(oauth.tokenUrl, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form });
  const tokenText = await tokenResponse.text();
  if (!tokenResponse.ok) throw new Error(`OAuth token exchange failed (${tokenResponse.status}): ${tokenText.slice(0, 300)}`);
  const token = JSON.parse(tokenText) as { access_token?: unknown; refresh_token?: unknown; expires_in?: unknown; token_type?: unknown };
  if (typeof token.access_token !== "string" || !token.access_token) throw new Error("OAuth token response did not contain access_token.");
  const tokenFile = path.resolve(model.auth.tokenFile ?? oauth.tokenFile ?? defaultTokenFile(model.id));
  await fs.mkdir(path.dirname(tokenFile), { recursive: true });
  await fs.writeFile(tokenFile, `${JSON.stringify({ access_token: token.access_token, refresh_token: token.refresh_token, expires_in: token.expires_in, token_type: token.token_type, savedAt: new Date().toISOString() }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  return tokenFile;
}
