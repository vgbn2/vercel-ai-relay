export const config = {
  runtime: 'edge',
  regions: ['sfo1'],
};

// Default allowed AI provider hostnames
const DEFAULT_ALLOWED_DOMAINS = new Set([
  "api.anthropic.com",
  "api.openai.com",
  "generativelanguage.googleapis.com",
  "api.deepseek.com",
  "openrouter.ai",
  "api.groq.com",
  "api.mistral.ai",
]);

// Map of provider hostnames to server-side environment variables and injection rules
const PROVIDER_AUTH_MAP = {
  "api.anthropic.com": {
    envVar: "ANTHROPIC_API_KEY",
    inject: (headers, key) => {
      headers.set("x-api-key", key);
      if (!headers.has("anthropic-version")) {
        headers.set("anthropic-version", "2023-06-01");
      }
    },
  },
  "api.openai.com": {
    envVar: "OPENAI_API_KEY",
    inject: (headers, key) => {
      headers.set("authorization", `Bearer ${key}`);
    },
  },
  "generativelanguage.googleapis.com": {
    envVar: "GEMINI_API_KEY",
    inject: (headers, key) => {
      headers.set("x-goog-api-key", key);
    },
  },
  "api.deepseek.com": {
    envVar: "DEEPSEEK_API_KEY",
    inject: (headers, key) => {
      headers.set("authorization", `Bearer ${key}`);
    },
  },
  "openrouter.ai": {
    envVar: "OPENROUTER_API_KEY",
    inject: (headers, key) => {
      headers.set("authorization", `Bearer ${key}`);
    },
  },
  "api.groq.com": {
    envVar: "GROQ_API_KEY",
    inject: (headers, key) => {
      headers.set("authorization", `Bearer ${key}`);
    },
  },
  "api.mistral.ai": {
    envVar: "MISTRAL_API_KEY",
    inject: (headers, key) => {
      headers.set("authorization", `Bearer ${key}`);
    },
  },
};

function isDomainAllowed(targetUrl) {
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== "https:") {
      return false;
    }
    const host = parsed.hostname.toLowerCase();
    if (DEFAULT_ALLOWED_DOMAINS.has(host)) {
      return true;
    }
    const extraDomains = process.env.ALLOWED_DOMAINS
      ? process.env.ALLOWED_DOMAINS.split(",").map(d => d.trim().toLowerCase())
      : [];
    return extraDomains.includes(host);
  } catch {
    return false;
  }
}

export default async function handler(request) {
  const target = request.headers.get("x-relay-target");
  const relayPath = request.headers.get("x-relay-path") || "/";

  if (!target) {
    // Health check / ping fallback
    return new Response(JSON.stringify({
      status: "ok",
      service: "vercel-ai-relay",
      mode: "zero-trust-credential-proxy",
      region: "sfo1"
    }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }

  // Authentication gate: enforce RELAY_SECRET_KEY when configured
  const expectedKey = process.env.RELAY_SECRET_KEY;
  if (expectedKey) {
    const authHeader = request.headers.get("authorization") || "";
    const bearerToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;
    const customKey = request.headers.get("x-relay-key");

    if (bearerToken !== expectedKey && customKey !== expectedKey) {
      return new Response(JSON.stringify({ error: "Unauthorized: invalid or missing relay key" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });
    }
  }

  const targetUrl = target.replace(/\/$/, "") + relayPath;

  // SSRF Protection: target domain allowlist check
  if (!isDomainAllowed(targetUrl)) {
    return new Response(JSON.stringify({ error: "Forbidden: target domain is not in the allowlist" }), {
      status: 403,
      headers: { "content-type": "application/json" },
    });
  }

  const parsedTarget = new URL(targetUrl);
  const targetHost = parsedTarget.hostname.toLowerCase();

  const newHeaders = new Headers(request.headers);
  newHeaders.delete("x-relay-target");
  newHeaders.delete("x-relay-path");
  newHeaders.delete("x-relay-key");
  newHeaders.delete("host");

  // Zero-Trust Credential Injection:
  // If server-side provider key is configured, strip incoming client auth and inject the server secret.
  const providerConfig = PROVIDER_AUTH_MAP[targetHost];
  if (providerConfig && process.env[providerConfig.envVar]) {
    const serverKey = process.env[providerConfig.envVar];
    // Remove client-supplied auth to prevent leaking or conflicting headers
    newHeaders.delete("authorization");
    newHeaders.delete("x-api-key");
    newHeaders.delete("x-goog-api-key");
    providerConfig.inject(newHeaders, serverKey);
  }

  try {
    const response = await fetch(targetUrl, {
      method: request.method,
      headers: newHeaders,
      body: request.method !== "GET" && request.method !== "HEAD" ? request.body : undefined,
      duplex: "half",
    });

    return new Response(response.body, {
      status: response.status,
      headers: response.headers,
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 502,
      headers: { "content-type": "application/json" },
    });
  }
}
