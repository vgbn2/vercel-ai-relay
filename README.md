# vercel-ai-relay

Edge proxy relay deployed on Vercel Edge Runtime pinned to US West (`sfo1` - San Francisco).
Designed for 9Router AI gateway request dispatching with `x-relay-target` and `x-relay-path` headers, implementing **Pattern 7: Zero-Knowledge Credential Proxy**.

## Features

- **Zero-Trust Credential Injection**: Client/agent processes connect with a dummy token or session ID; the relay strips incoming auth headers and injects real provider API keys server-side before outbound egress.
- **SSRF Protection**: Target hosts are restricted to verified AI providers.
- **Authentication Gate**: Enforces `RELAY_SECRET_KEY` so only authorized agents/relays can invoke the edge function.
- **Edge Pinned Region**: Pinned to `sfo1` for minimal latency to US-based AI provider datacenters.

## Configuration & Environment Variables

### 1. Relay Access Control
- `RELAY_SECRET_KEY`: Shared secret key. Clients must pass `Authorization: Bearer <RELAY_SECRET_KEY>` or `x-relay-key: <RELAY_SECRET_KEY>`.

### 2. Server-Side Provider Credentials (Zero-Trust Injection)
Configure any of the following secrets in Vercel Project Settings:
- `ANTHROPIC_API_KEY`: Injected into `x-api-key` (with `anthropic-version: 2023-06-01`).
- `OPENAI_API_KEY`: Injected into `Authorization: Bearer <key>`.
- `GEMINI_API_KEY`: Injected into `x-goog-api-key`.
- `DEEPSEEK_API_KEY`: Injected into `Authorization: Bearer <key>`.
- `OPENROUTER_API_KEY`: Injected into `Authorization: Bearer <key>`.
- `GROQ_API_KEY`: Injected into `Authorization: Bearer <key>`.
- `MISTRAL_API_KEY`: Injected into `Authorization: Bearer <key>`.

### 3. SSRF Allowlist
Default allowed target hosts:
- `api.anthropic.com`
- `api.openai.com`
- `generativelanguage.googleapis.com`
- `api.deepseek.com`
- `openrouter.ai`
- `api.groq.com`
- `api.mistral.ai`

To permit additional endpoints, set `ALLOWED_DOMAINS` to a comma-separated list of hostnames.

## Testing

Run the assertion test suite:
```bash
npm test
```
