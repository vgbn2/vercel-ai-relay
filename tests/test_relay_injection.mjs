import assert from 'node:assert';
import handler from '../api/index.js';

async function runTests() {
  console.log('Running Zero-Trust Relay tests...');

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
    console.log('✓ Health check passed');
  }

  // Test 2: SSRF block on non-allowed domains
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

  // Test 3: Authentication Gate with RELAY_SECRET_KEY
  {
    process.env.RELAY_SECRET_KEY = 'secret-relay-pass-123';

    // Unauthorized request
    const unauthReq = new Request('http://localhost/', {
      method: 'POST',
      headers: {
        'x-relay-target': 'https://api.anthropic.com',
        'x-relay-path': '/v1/messages',
      },
    });
    const unauthRes = await handler(unauthReq);
    assert.strictEqual(unauthRes.status, 401, 'Request without relay secret should return 401');

    // Authorized request with Bearer token
    // (We test auth pass by intercepting global fetch)
    const originalFetch = globalThis.fetch;
    let interceptedHeaders = null;
    let interceptedUrl = null;

    globalThis.fetch = async (url, options) => {
      interceptedUrl = url;
      interceptedHeaders = options.headers;
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };

    const authReq = new Request('http://localhost/', {
      method: 'POST',
      headers: {
        'x-relay-target': 'https://api.anthropic.com',
        'x-relay-path': '/v1/messages',
        'authorization': 'Bearer secret-relay-pass-123',
        'x-api-key': 'dummy-client-token',
      },
      body: JSON.stringify({ model: 'claude-3-haiku-20240307' }),
    });

    // Configure server-side injection key
    process.env.ANTHROPIC_API_KEY = 'sk-ant-server-injected-secret-999';
    const authRes = await handler(authReq);
    assert.strictEqual(authRes.status, 200);

    // Verify injected credentials
    assert.strictEqual(interceptedUrl, 'https://api.anthropic.com/v1/messages');
    assert.strictEqual(interceptedHeaders.get('x-api-key'), 'sk-ant-server-injected-secret-999');
    assert.strictEqual(interceptedHeaders.get('anthropic-version'), '2023-06-01');
    assert.strictEqual(interceptedHeaders.get('authorization'), null, 'Client authorization header should be stripped');
    assert.strictEqual(interceptedHeaders.get('x-relay-target'), null, 'Relay routing headers should be stripped');

    // Cleanup mock
    globalThis.fetch = originalFetch;
    delete process.env.RELAY_SECRET_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    console.log('✓ Auth gate & Anthropic server-side credential injection passed');
  }

  // Test 4: OpenAI Credential Injection
  {
    const originalFetch = globalThis.fetch;
    let interceptedHeaders = null;

    globalThis.fetch = async (url, options) => {
      interceptedHeaders = options.headers;
      return new Response(JSON.stringify({ id: 'chatcmpl-test' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };

    process.env.OPENAI_API_KEY = 'sk-proj-server-injected-openai-key';
    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: {
        'x-relay-target': 'https://api.openai.com',
        'x-relay-path': '/v1/chat/completions',
        'authorization': 'Bearer dummy-client-token',
      },
      body: JSON.stringify({ model: 'gpt-4o' }),
    });

    const res = await handler(req);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(interceptedHeaders.get('authorization'), 'Bearer sk-proj-server-injected-openai-key');

    globalThis.fetch = originalFetch;
    delete process.env.OPENAI_API_KEY;
    console.log('✓ OpenAI server-side credential injection passed');
  }

  // Test 5: Gemini Credential Injection
  {
    const originalFetch = globalThis.fetch;
    let interceptedHeaders = null;

    globalThis.fetch = async (url, options) => {
      interceptedHeaders = options.headers;
      return new Response(JSON.stringify({ candidates: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };

    process.env.GEMINI_API_KEY = 'AIzaSy-server-injected-gemini-key';
    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: {
        'x-relay-target': 'https://generativelanguage.googleapis.com',
        'x-relay-path': '/v1beta/models/gemini-pro:generateContent',
        'x-goog-api-key': 'dummy-client-key',
      },
      body: JSON.stringify({ contents: [] }),
    });

    const res = await handler(req);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(interceptedHeaders.get('x-goog-api-key'), 'AIzaSy-server-injected-gemini-key');

    globalThis.fetch = originalFetch;
    delete process.env.GEMINI_API_KEY;
    console.log('✓ Gemini server-side credential injection passed');
  }

  console.log('\nAll 5 Zero-Trust Relay tests passed successfully!');
}

runTests().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
