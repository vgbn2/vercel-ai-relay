# vercel-ai-relay

Edge proxy relay deployed on Vercel Edge Runtime pinned to US West (`sfo1` - San Francisco).
Designed for 9Router AI gateway request dispatching with `x-relay-target` and `x-relay-path` headers.

## Security & Configuration

- **Authentication**: Set environment variable `RELAY_SECRET_KEY`. When configured, requests must supply either `Authorization: Bearer <RELAY_SECRET_KEY>` or `x-relay-key: <RELAY_SECRET_KEY>`.
- **SSRF Allowlist**: Outbound requests are restricted to HTTPS AI providers:
  - `api.anthropic.com`
  - `api.openai.com`
  - `generativelanguage.googleapis.com`
  - `api.deepseek.com`
  - `openrouter.ai`
  - `api.groq.com`
  - `api.mistral.ai`
- **Additional Domains**: Configure comma-separated hosts in the `ALLOWED_DOMAINS` environment variable.
