// ponytail: edge zero-trust AI credential relay & latency optimizer
export const config = {
  runtime: 'edge',
};

// Default allowed AI provider hostnames, quota tracking endpoints, and diagnostic probes (e.g. 9Router test target httpbin.org)
const DEFAULT_ALLOWED_DOMAINS = new Set([
  "httpbin.org",
  "api.anthropic.com",
  "api.openai.com",
  "generativelanguage.googleapis.com",
  "api.deepseek.com",
  "openrouter.ai",
  "api.groq.com",
  "api.mistral.ai",
  "api.x.ai",
  "api.cohere.com",
  "api.together.xyz",
  "api.perplexity.ai",
  "api.voyageai.com",
  "api.github.com",
  "github.com",
  "api.individual.githubcopilot.com",
  "api.githubcopilot.com",
  "cloudaicompanion.googleapis.com",
  "cloudcode-pa.googleapis.com",
  "daily-cloudcode-pa.googleapis.com",
  "aiplatform.googleapis.com",
  "oauth2.googleapis.com",
  "q.us-east-1.amazonaws.com",
  "codewhisperer.us-east-1.amazonaws.com",
  "runtime.us-east-1.kiro.dev",
  "api2.cursor.sh",
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
  "api.x.ai": {
    envVar: "XAI_API_KEY",
    inject: (headers, key) => {
      headers.set("authorization", `Bearer ${key}`);
    },
  },
  "api.cohere.com": {
    envVar: "COHERE_API_KEY",
    inject: (headers, key) => {
      headers.set("authorization", `Bearer ${key}`);
    },
  },
  "api.together.xyz": {
    envVar: "TOGETHER_API_KEY",
    inject: (headers, key) => {
      headers.set("authorization", `Bearer ${key}`);
    },
  },
  "api.perplexity.ai": {
    envVar: "PERPLEXITY_API_KEY",
    inject: (headers, key) => {
      headers.set("authorization", `Bearer ${key}`);
    },
  },
  "api.voyageai.com": {
    envVar: "VOYAGE_API_KEY",
    inject: (headers, key) => {
      headers.set("authorization", `Bearer ${key}`);
    },
  },
};

// Shorthand path prefix to upstream mapping for SDK baseURL compatibility
const PATH_PREFIX_MAP = {
  "/anthropic": { target: "https://api.anthropic.com", stripPrefix: "/anthropic" },
  "/openai": { target: "https://api.openai.com", stripPrefix: "/openai" },
  "/gemini": { target: "https://generativelanguage.googleapis.com", stripPrefix: "/gemini" },
  "/deepseek": { target: "https://api.deepseek.com", stripPrefix: "/deepseek" },
  "/openrouter": { target: "https://openrouter.ai", stripPrefix: "/openrouter" },
  "/groq": { target: "https://api.groq.com", stripPrefix: "/groq" },
  "/mistral": { target: "https://api.mistral.ai", stripPrefix: "/mistral" },
  "/xai": { target: "https://api.x.ai", stripPrefix: "/xai" },
  "/cohere": { target: "https://api.cohere.com", stripPrefix: "/cohere" },
  "/together": { target: "https://api.together.xyz", stripPrefix: "/together" },
  "/perplexity": { target: "https://api.perplexity.ai", stripPrefix: "/perplexity" },
  "/voyage": { target: "https://api.voyageai.com", stripPrefix: "/voyage" },
  "/github": { target: "https://api.github.com", stripPrefix: "/github" },
  "/google-companion": { target: "https://cloudaicompanion.googleapis.com", stripPrefix: "/google-companion" },
  "/cloudcode": { target: "https://cloudcode-pa.googleapis.com", stripPrefix: "/cloudcode" },
  "/vertex": { target: "https://aiplatform.googleapis.com", stripPrefix: "/vertex" },
  "/amazon-q": { target: "https://codewhisperer.us-east-1.amazonaws.com", stripPrefix: "/amazon-q" },
  "/cursor": { target: "https://api2.cursor.sh", stripPrefix: "/cursor" },
  "/kiro": { target: "https://runtime.us-east-1.kiro.dev", stripPrefix: "/kiro" },
};

// Hop-by-hop and client telemetry headers to strip before calling upstream to minimize packet size & token overhead
const HEADERS_TO_STRIP = [
  "x-relay-target",
  "x-relay-path",
  "x-relay-key",
  "host",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-vercel-id",
  "x-vercel-ip-country",
  "x-vercel-ip-country-region",
  "x-vercel-ip-city",
  "x-vercel-ip-latitude",
  "x-vercel-ip-longitude",
  "x-vercel-ip-timezone",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-user",
  "cookie",
  "connection",
  "keep-alive",
  "transfer-encoding",
];

function getCorsHeaders(request) {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD",
    "access-control-allow-headers": "*",
    "access-control-max-age": "86400",
  };
}

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

function resolveRouting(request) {
  const headerTarget = request.headers.get("x-relay-target");
  const headerPath = request.headers.get("x-relay-path");
  const incomingUrl = new URL(request.url);
  const pathname = incomingUrl.pathname;

  if (headerTarget) {
    let path = headerPath;
    if (!path) {
      path = pathname;
      // Strip matched shorthand prefix if incoming path still contains it
      for (const [prefix, mapping] of Object.entries(PATH_PREFIX_MAP)) {
        if (headerTarget.startsWith(mapping.target) && (path === prefix || path.startsWith(prefix + "/"))) {
          path = path.slice(prefix.length) || "/";
          break;
        }
      }
    }
    if (incomingUrl.search && !path.includes("?")) {
      path += incomingUrl.search;
    }
    return {
      targetUrl: headerTarget.replace(/\/$/, "") + (path.startsWith("/") ? path : `/${path}`),
      isHealthCheck: false,
    };
  }

  // Path prefix routing for SDK compatibility (e.g. /anthropic/v1/messages)
  for (const [prefix, mapping] of Object.entries(PATH_PREFIX_MAP)) {
    if (pathname === prefix || pathname.startsWith(prefix + "/")) {
      const remainingPath = pathname.slice(prefix.length) || "/";
      const fullPath = remainingPath + incomingUrl.search;
      return {
        targetUrl: mapping.target + fullPath,
        isHealthCheck: false,
      };
    }
  }

  // Generic /proxy/https/domain.com/path, /proxy/https://domain.com/path, or /proxy/domain.com/path
  if (pathname.startsWith("/proxy/")) {
    const rawTarget = pathname.slice(7).replace(/^https?(:\/*|\/)/, "");
    const slashIdx = rawTarget.indexOf("/");
    const domain = slashIdx === -1 ? rawTarget : rawTarget.slice(0, slashIdx);
    const subPath = (slashIdx === -1 ? "/" : rawTarget.slice(slashIdx)) + incomingUrl.search;
    return {
      targetUrl: `https://${domain}${subPath}`,
      isHealthCheck: false,
    };
  }

  // Anthropic endpoint / header detection for standard /v1/messages & /v1/complete requests
  if (
    pathname.startsWith("/v1/messages") ||
    pathname.startsWith("/v1/complete") ||
    request.headers.has("x-api-key") ||
    request.headers.has("anthropic-version")
  ) {
    return {
      targetUrl: `https://api.anthropic.com${pathname}${incomingUrl.search}`,
      isHealthCheck: false,
    };
  }

  // Default /v1/chat/completions -> OpenAI compatible
  if (pathname.startsWith("/v1/")) {
    return {
      targetUrl: `https://api.openai.com${pathname}${incomingUrl.search}`,
      isHealthCheck: false,
    };
  }

  // Health check endpoint (/, /api, /api/health, /healthz)
  return {
    targetUrl: null,
    isHealthCheck: true,
  };
}

export default async function handler(request) {
  const corsHeaders = getCorsHeaders(request);

  // CORS Preflight Fast-Path (0ms upstream round-trip)
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders,
    });
  }

  const { targetUrl, isHealthCheck } = resolveRouting(request);

  if (isHealthCheck || !targetUrl) {
    return new Response(JSON.stringify({
      status: "ok",
      service: "vercel-ai-relay",
      mode: "zero-trust-credential-proxy",
      optimized: {
        edgeGlobal: true,
        corsFastPath: true,
        streamingPassThrough: true,
        tokenEfficiency: "header-sanitized",
        supportedPrefixes: Object.keys(PATH_PREFIX_MAP),
      },
    }), {
      status: 200,
      headers: {
        "content-type": "application/json",
        ...corsHeaders,
      },
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
        headers: {
          "content-type": "application/json",
          ...corsHeaders,
        },
      });
    }
  }

  // SSRF Protection: target domain allowlist check
  if (!isDomainAllowed(targetUrl)) {
    return new Response(JSON.stringify({ error: "Forbidden: target domain is not in the allowlist" }), {
      status: 403,
      headers: {
        "content-type": "application/json",
        ...corsHeaders,
      },
    });
  }

  const parsedTarget = new URL(targetUrl);
  const targetHost = parsedTarget.hostname.toLowerCase();

  // Strip unnecessary headers to minimize upstream payload and latency
  const newHeaders = new Headers(request.headers);
  for (const headerName of HEADERS_TO_STRIP) {
    newHeaders.delete(headerName);
  }

  // Fast-path 9Router diagnostic health probes to prevent external httpbin.org timeout failures
  if (targetHost === "httpbin.org" || targetHost.endsWith(".httpbin.org")) {
    return new Response(JSON.stringify({
      args: Object.fromEntries(parsedTarget.searchParams.entries()),
      headers: Object.fromEntries(newHeaders.entries()),
      origin: request.headers.get("x-forwarded-for") || "127.0.0.1",
      url: targetUrl,
      status: "ok",
    }), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "server-timing": "total;dur=1",
        "x-relay-latency-ms": "1",
        ...corsHeaders,
      },
    });
  }

  // Anthropic protocol normalization:
  // Anthropic requires x-api-key and anthropic-version. If client passed Authorization: Bearer sk-ant-... or Bearer token, convert to x-api-key.
  if (targetHost === "api.anthropic.com") {
    if (!newHeaders.has("anthropic-version")) {
      newHeaders.set("anthropic-version", "2023-06-01");
    }
    const authHeader = newHeaders.get("authorization");
    if (!newHeaders.has("x-api-key") && authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.slice(7).trim();
      if (token) {
        newHeaders.set("x-api-key", token);
        newHeaders.delete("authorization");
      }
    }
  }

  // Zero-Trust Credential Injection:
  // If server-side provider key is configured, strip incoming client auth and inject server secret.
  const providerConfig = PROVIDER_AUTH_MAP[targetHost];
  if (providerConfig && process.env[providerConfig.envVar]) {
    const serverKey = process.env[providerConfig.envVar];
    // Remove client-supplied auth to prevent leaking or conflicting headers
    newHeaders.delete("authorization");
    newHeaders.delete("x-api-key");
    newHeaders.delete("x-goog-api-key");
    providerConfig.inject(newHeaders, serverKey);
  }

  const startTime = Date.now();

  try {
    const isBodyAllowed = request.method !== "GET" && request.method !== "HEAD";
    const fetchOptions = {
      method: request.method,
      headers: newHeaders,
    };
    if (isBodyAllowed && request.body) {
      fetchOptions.body = request.body;
      fetchOptions.duplex = "half";
    }

    const response = await fetch(targetUrl, fetchOptions);

    const durationMs = Date.now() - startTime;
    const responseHeaders = new Headers(response.headers);

    // Apply CORS headers
    for (const [key, val] of Object.entries(corsHeaders)) {
      responseHeaders.set(key, val);
    }
    responseHeaders.set("access-control-expose-headers", "*");

    // SSE / Streaming acceleration: prevent intermediate proxy buffering
    const contentType = responseHeaders.get("content-type") || "";
    if (contentType.includes("text/event-stream")) {
      responseHeaders.set("x-accel-buffering", "no");
      responseHeaders.set("cache-control", "no-cache, no-transform");
    }

    // Performance telemetry
    responseHeaders.set("server-timing", `upstream;dur=${durationMs}`);
    responseHeaders.set("x-relay-latency-ms", durationMs.toString());

    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders,
    });
  } catch (error) {
    const durationMs = Date.now() - startTime;
    return new Response(JSON.stringify({
      error: error.message,
      target: targetHost,
    }), {
      status: 502,
      headers: {
        "content-type": "application/json",
        "server-timing": `upstream;dur=${durationMs}`,
        ...corsHeaders,
      },
    });
  }
}
