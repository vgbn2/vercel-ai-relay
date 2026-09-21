# vercel-ai-relay

Edge proxy relay deployed on Vercel Edge Runtime.
Provides zero-trust credential isolation, SSE streaming acceleration, header sanitization for payload/token efficiency, and dual-mode routing (SDK path-based and gateway header-based).

## Architecture & Optimizations

- **Zero-Trust Credential Isolation (Pattern 7)**: Local agents or gateways connect with dummy session keys. The relay strips client auth and injects real provider secrets securely from Vercel environment variables.
- **Global Edge Routing**: Runs across Vercel global edge regions, terminating TLS near the client and routing over optimized backbones.
- **CORS Fast-Path**: Handles `OPTIONS` preflight immediately at the edge with `204 No Content` and `86400s` caching to eliminate preflight round-trips.
- **SSE Streaming Acceleration**: Injects `x-accel-buffering: no` and `cache-control: no-cache, no-transform` on `text/event-stream` responses to prevent intermediate proxy buffering.
- **Payload & Header Sanitization (Token Efficiency)**: Strips redundant client telemetry, browser metadata (`sec-ch-ua*`, `x-vercel-*`), and session cookies before calling upstream providers to minimize packet size.
- **Latency Telemetry**: Attaches `Server-Timing: upstream;dur=<ms>` and `X-Relay-Latency-Ms: <ms>` to every response for monitoring.

---

## Routing Modes

### 1. Path-Based Routing (Standard AI SDK BaseURL)
Simply point your SDK's `baseURL` to the relay:
- Anthropic: `https://<relay-domain>/anthropic` (e.g. `/anthropic/v1/messages`)
- OpenAI: `https://<relay-domain>/openai` or `https://<relay-domain>/v1`
- Gemini: `https://<relay-domain>/gemini`
- DeepSeek: `https://<relay-domain>/deepseek`
- OpenRouter: `https://<relay-domain>/openrouter`
- Groq: `https://<relay-domain>/groq`
- Mistral: `https://<relay-domain>/mistral`
- xAI Grok: `https://<relay-domain>/xai`
- Cohere: `https://<relay-domain>/cohere`
- Together AI: `https://<relay-domain>/together`
- Perplexity: `https://<relay-domain>/perplexity`
- Voyage AI: `https://<relay-domain>/voyage`
- GitHub / Copilot: `https://<relay-domain>/github` (e.g. `/github/user`)
- Google Cloud Companion / Antigravity: `https://<relay-domain>/google-companion`
- Google Vertex AI: `https://<relay-domain>/vertex`
- Generic Proxy: `https://<relay-domain>/proxy/<domain>/<path>`

### 2. Header-Based Routing (Gateway Proxy)
Pass explicit target headers:
- `x-relay-target`: `https://api.anthropic.com`
- `x-relay-path`: `/v1/messages`

---

## Configuration & Environment Variables

### 1. Relay Access Gate
- `RELAY_SECRET_KEY`: Optional shared secret. Clients pass `Authorization: Bearer <RELAY_SECRET_KEY>` or `x-relay-key: <RELAY_SECRET_KEY>`.

### 2. Server-Side Provider Credentials
Configure in Vercel Project Environment Variables:
- `ANTHROPIC_API_KEY` (`x-api-key`, `anthropic-version: 2023-06-01`, `anthropic-beta` passthrough)
- `OPENAI_API_KEY` (`Authorization: Bearer <key>`)
- `GEMINI_API_KEY` (`x-goog-api-key`)
- `DEEPSEEK_API_KEY` (`Authorization: Bearer <key>`)
- `OPENROUTER_API_KEY` (`Authorization: Bearer <key>`)
- `GROQ_API_KEY` (`Authorization: Bearer <key>`)
- `MISTRAL_API_KEY` (`Authorization: Bearer <key>`)
- `XAI_API_KEY` (`Authorization: Bearer <key>`)
- `COHERE_API_KEY` (`Authorization: Bearer <key>`)
- `TOGETHER_API_KEY` (`Authorization: Bearer <key>`)
- `PERPLEXITY_API_KEY` (`Authorization: Bearer <key>`)
- `VOYAGE_API_KEY` (`Authorization: Bearer <key>`)

### 3. Target Allowlist
Default allowed AI and Quota Tracking hosts:
- `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`
- `api.deepseek.com`, `openrouter.ai`, `api.groq.com`, `api.mistral.ai`
- `api.x.ai`, `api.cohere.com`, `api.together.xyz`, `api.perplexity.ai`, `api.voyageai.com`
- `api.github.com`, `github.com` (GitHub Copilot usage & token management)
- `cloudaicompanion.googleapis.com`, `cloudcode-pa.googleapis.com` (Antigravity & Cloud AI quota)
- `aiplatform.googleapis.com`, `oauth2.googleapis.com` (Vertex AI & Google Auth)
- `httpbin.org` (9Router gateway diagnostic probe)

Set `ALLOWED_DOMAINS` to add comma-separated HTTPS hostnames.

---

## Viewing Vercel Edge Logs

To monitor live Edge function logs and latency:
1. **Interactive CLI**: Run `npx vercel login`, link the project with `npx vercel link`, and tail logs:
   ```bash
   npx vercel logs --follow
   ```
2. **Headless / CI**: Provide `VERCEL_TOKEN`, `VERCEL_ORG_ID`, and `VERCEL_PROJECT_ID`:
   ```bash
   npx vercel logs --token "$VERCEL_TOKEN"
   ```
3. **Vercel Dashboard**: Navigate to **Project -> Logs -> Edge Middleware / Functions** for real-time trace inspection and status distribution.

---

## Testing

Run the test suite:
```bash
npm test
```
