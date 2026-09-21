import assert from 'node:assert';
import handler from '../api/index.js';

async function runTests() {
  console.log('Running Expanded Zero-Trust Relay & Latency Optimizer tests...');

  // Test 1: Health check when no x-relay-target header is passed
  {
    const req = new Request('http://localhost/', {
      method: 'GET',
    });
    const res = await handler(req);
    assert.strictEqual(res.status, 200, 'Health check should return 200');
    const data = await res.json();
    assert.strictEqual(data.status, 'ok');
    assert.strictEqual(data.mode, 'zero-trust-credential-proxy');
    assert.strictEqual(data.optimized.edgeGlobal, true);
    assert.strictEqual(data.optimized.corsFastPath, true);
    console.log('✓ Health check with optimization metadata passed');
  }

  // Test 2: CORS Preflight Fast-Path
  {
    const req = new Request('http://localhost/anthropic/v1/messages', {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://agent-ui.local',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type, Authorization',
      },
    });
    const res = await handler(req);
    assert.strictEqual(res.status, 204, 'CORS preflight should return 204 No Content');
    assert.strictEqual(res.headers.get('access-control-allow-origin'), '*');
    assert.strictEqual(res.headers.get('access-control-max-age'), '86400');
    console.log('✓ CORS OPTIONS preflight fast-path passed');
  }

  // Test 3: SSRF block on non-allowed domains
  {
    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: {
        'x-relay-target': 'https://malicious-internal-service.local',
        'x-relay-path': '/secret',
      },
    });
    const res = await handler(req);
    assert.strictEqual(res.status, 403, 'Disallowed target domain should be rejected with 403');
    const data = await res.json();
    assert.ok(data.error.includes('Forbidden'));
    console.log('✓ SSRF block passed');
  }

  // Test 4: Path Prefix Routing with Query String Preservation
  {
    const originalFetch = globalThis.fetch;
    let interceptedUrl = null;
    let interceptedHeaders = null;

    globalThis.fetch = async (url, options) => {
      interceptedUrl = url;
      interceptedHeaders = options.headers;
      return new Response(JSON.stringify({ id: 'msg_123', content: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };

    process.env.ANTHROPIC_API_KEY = 'sk-ant-server-injected-secret-999';

    // Request to /anthropic/v1/messages?beta=true with browser headers to verify stripping
    const req = new Request('http://localhost/anthropic/v1/messages?beta=true', {
      method: 'POST',
      headers: {
        'authorization': 'Bearer client-dummy-token',
        'sec-ch-ua': '"Not.A/Brand";v="8"',
        'x-vercel-id': 'iad1::abc1234',
        'cookie': 'session=abc',
        'anthropic-beta': 'prompt-caching-2024-07-31',
      },
      body: JSON.stringify({ model: 'claude-3-5-sonnet-20241022' }),
    });

    const res = await handler(req);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(interceptedUrl, 'https://api.anthropic.com/v1/messages?beta=true');
    assert.strictEqual(interceptedHeaders.get('x-api-key'), 'sk-ant-server-injected-secret-999');
    assert.strictEqual(interceptedHeaders.get('anthropic-beta'), 'prompt-caching-2024-07-31', 'Prompt caching header preserved');
    assert.strictEqual(interceptedHeaders.get('authorization'), null, 'Client authorization header stripped');
    assert.strictEqual(interceptedHeaders.get('sec-ch-ua'), null, 'Client browser telemetry stripped');
    assert.strictEqual(interceptedHeaders.get('x-vercel-id'), null, 'Vercel internal header stripped');
    assert.strictEqual(interceptedHeaders.get('cookie'), null, 'Cookie header stripped');

    // Verify response telemetry & CORS
    assert.strictEqual(res.headers.get('access-control-allow-origin'), '*');
    assert.ok(res.headers.has('server-timing'));
    assert.ok(res.headers.has('x-relay-latency-ms'));

    globalThis.fetch = originalFetch;
    delete process.env.ANTHROPIC_API_KEY;
    console.log('✓ Path prefix routing, query preservation & header sanitization passed');
  }

  // Test 5: SSE Streaming Headers & Buffer Bypass
  {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      return new Response('event: message\ndata: {"token": "hello"}\n\n', {
        status: 200,
        headers: {
          'content-type': 'text/event-stream; charset=utf-8',
        },
      });
    };

    const req = new Request('http://localhost/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'authorization': 'Bearer dummy-token' },
      body: JSON.stringify({ stream: true }),
    });

    const res = await handler(req);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('x-accel-buffering'), 'no');
    assert.strictEqual(res.headers.get('cache-control'), 'no-cache, no-transform');

    globalThis.fetch = originalFetch;
    console.log('✓ SSE streaming header acceleration passed');
  }

  // Test 6: Expanded Provider Injections (xAI Grok, DeepSeek, Groq)
  {
    const originalFetch = globalThis.fetch;
    const providerTests = [
      {
        path: '/xai/v1/chat/completions',
        envVar: 'XAI_API_KEY',
        envVal: 'xai-test-key-789',
        expectedUrl: 'https://api.x.ai/v1/chat/completions',
        expectedHeader: 'authorization',
        expectedVal: 'Bearer xai-test-key-789',
      },
      {
        path: '/deepseek/v1/chat/completions',
        envVar: 'DEEPSEEK_API_KEY',
        envVal: 'sk-deepseek-test-key',
        expectedUrl: 'https://api.deepseek.com/v1/chat/completions',
        expectedHeader: 'authorization',
        expectedVal: 'Bearer sk-deepseek-test-key',
      },
      {
        path: '/groq/openai/v1/chat/completions',
        envVar: 'GROQ_API_KEY',
        envVal: 'gsk_test_groq_key',
        expectedUrl: 'https://api.groq.com/openai/v1/chat/completions',
        expectedHeader: 'authorization',
        expectedVal: 'Bearer gsk_test_groq_key',
      },
    ];

    for (const pt of providerTests) {
      let interceptedUrl = null;
      let interceptedHeaders = null;

      globalThis.fetch = async (url, options) => {
        interceptedUrl = url;
        interceptedHeaders = options.headers;
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      };

      process.env[pt.envVar] = pt.envVal;

      const req = new Request(`http://localhost${pt.path}`, {
        method: 'POST',
        headers: { 'authorization': 'Bearer dummy-client' },
        body: JSON.stringify({ prompt: 'hi' }),
      });

      const res = await handler(req);
      assert.strictEqual(res.status, 200);
      assert.strictEqual(interceptedUrl, pt.expectedUrl);
      assert.strictEqual(interceptedHeaders.get(pt.expectedHeader), pt.expectedVal);

      delete process.env[pt.envVar];
    }

    globalThis.fetch = originalFetch;
    console.log('✓ Expanded provider matrix (xAI, DeepSeek, Groq) credential injection passed');
  }

  // Test 7: Authentication Gate with RELAY_SECRET_KEY
  {
    process.env.RELAY_SECRET_KEY = 'secret-relay-pass-123';

    // Unauthorized request
    const unauthReq = new Request('http://localhost/anthropic/v1/messages', {
      method: 'POST',
    });
    const unauthRes = await handler(unauthReq);
    assert.strictEqual(unauthRes.status, 401, 'Request without relay secret should return 401');

    // Authorized request
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } });

    const authReq = new Request('http://localhost/anthropic/v1/messages', {
      method: 'POST',
      headers: { 'authorization': 'Bearer secret-relay-pass-123' },
    });
    const authRes = await handler(authReq);
    assert.strictEqual(authRes.status, 200);

    globalThis.fetch = originalFetch;
    delete process.env.RELAY_SECRET_KEY;
    console.log('✓ Auth gate with RELAY_SECRET_KEY passed');
  }

  // Test 8: 9Router Proxy Pool Healthcheck Probe (httpbin.org/get)
  {
    const originalFetch = globalThis.fetch;
    let interceptedUrl = null;

    globalThis.fetch = async (url) => {
      interceptedUrl = url;
      return new Response(JSON.stringify({ origin: '1.2.3.4' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };

    const req = new Request('http://localhost/', {
      method: 'GET',
      headers: {
        'x-relay-target': 'https://httpbin.org',
        'x-relay-path': '/get',
      },
    });

    const res = await handler(req);
    assert.strictEqual(res.status, 200, '9Router healthcheck probe to httpbin.org should return 200');
    assert.strictEqual(interceptedUrl, 'https://httpbin.org/get');

    globalThis.fetch = originalFetch;
    console.log('✓ 9Router healthcheck probe to httpbin.org passed');
  }

  console.log('\nAll 8 Expanded Zero-Trust Relay & Latency Optimizer tests passed successfully!');
}

runTests().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
