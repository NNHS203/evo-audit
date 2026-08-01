# Model providers

Evo Audit keeps model choice outside the evidence contract. A model can open a
candidate or explain a path, but it cannot promote a finding to `VERIFIED`.
The deterministic graph and the independent validator remain the authority.

## API-key model

Create `audit.models.json` in the audited repository (or pass `--config`):

```json
{
  "schemaVersion": 1,
  "auto": { "enabled": true, "preferred": ["primary"], "minimumQualityTier": 3 },
  "models": [
    {
      "id": "primary",
      "transport": "OPENAI_COMPATIBLE",
      "model": "your-model-id",
      "baseUrl": "https://api.example.com/v1",
      "auth": { "method": "API_KEY", "apiKeyEnv": "YOUR_PROVIDER_API_KEY" },
      "qualityTier": 5,
      "capabilities": ["HUNT", "INVESTIGATE", "VALIDATE", "JSON"]
    }
  ]
}
```

The key is read only from the named environment variable. Raw keys and access
tokens in `audit.models.json` are rejected.

For a quick OpenAI-compatible setup without a config file, set
`EVO_AUDIT_MODEL` and either `EVO_AUDIT_API_KEY` or `OPENAI_API_KEY` (optionally
`EVO_AUDIT_BASE_URL`). The loader creates an `env-default` model in memory; the
secret is never written to the repository.

List providers without making a network request:

```bash
evo-audit models .
evo-audit models . --json
```

## OAuth model

Use the same model definition with `auth.method` set to `OAUTH` and supply
PKCE settings:

```json
{
  "id": "oauth-model",
  "transport": "OPENAI_COMPATIBLE",
  "model": "your-model-id",
  "baseUrl": "https://api.example.com/v1",
  "auth": {
    "method": "OAUTH",
    "tokenFile": "C:/Users/you/.evo-audit/oauth/oauth-model.json",
    "oauth": {
      "authorizationUrl": "https://example.com/oauth/authorize",
      "tokenUrl": "https://example.com/oauth/token",
      "clientId": "public-client-id",
      "scopes": ["model:use"]
    }
  },
  "qualityTier": 5,
  "capabilities": ["HUNT", "INVESTIGATE", "VALIDATE", "JSON"]
}
```

Run:

```bash
evo-audit auth . oauth-model
```

The flow uses a loopback callback and PKCE. The token file is outside the
repository by default; use `--no-open` when the authorization URL must be
opened manually. Provider-specific OAuth scopes, redirect registrations, and
terms still apply.

## Auto model

`auto` selects only enabled models whose declared task capabilities match the
task. It prefers configured models, increases quality preference for higher
priority findings, and considers cost pressure for small budgets. It does not
pretend to know a model's true security performance: benchmark results should
be used to tune `qualityTier`, preferred order, and playbook policy.

Provider responses are normalized to the same completion and token-usage
contract. Model calls are not validation evidence; they are worker input to the
existing candidate and validator workflow.

Model-backed commands perform a credential preflight before opening the worker
queue. A missing API key or OAuth token fails clearly with the required
environment variable or `evo-audit auth` action; it is not reported as a
successful static-only model run.

API/OAuth providers receive the bounded source and graph context selected for a
task. Do not configure an external provider for repositories whose policy does
not permit source sharing; use a local OpenAI-compatible endpoint or omit model
execution. Credentials are never placed in prompts, run manifests, or model
cache keys.
