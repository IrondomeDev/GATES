import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createIronDomeClient, IronDomeClientError } from '../src/core/irondome.js';

const allowed = { provider: 'gmail', valid: true, disposable: false, reason: 'not_listed' };
const json = (body: unknown, status = 200, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
const fake = (fn: (input: RequestInfo | URL, init?: RequestInit) => Response | Promise<Response>): typeof fetch =>
  (async (input: RequestInfo | URL, init?: RequestInit) => fn(input, init)) as typeof fetch;
const code = (expected: string, retryable?: boolean) => (error: unknown): boolean => {
  assert.ok(error instanceof IronDomeClientError);
  assert.equal(error.code, expected);
  if (retryable !== undefined) assert.equal(error.retryable, retryable);
  return true;
};

// All requests here use an injected synthetic Fetch. No network or real secret.
test('matches verified API and sends exact submitted address, not canonical form', async () => {
  let requests = 0;
  const client = createIronDomeClient({ apiKey: 'synthetic-key', fetch: fake((url, init) => {
    requests++;
    assert.equal(url, 'https://api.irondome.dev/v1/check');
    assert.equal(init?.method, 'POST');
    assert.equal(init?.redirect, 'manual');
    assert.equal(init?.credentials, 'omit');
    assert.equal(init?.cache, 'no-store');
    assert.equal(init?.referrerPolicy, 'no-referrer');
    const headers = new Headers(init?.headers);
    assert.equal(headers.get('authorization'), 'Bearer synthetic-key');
    assert.equal(headers.get('accept-encoding'), 'identity');
    const bytes = init?.body as Uint8Array;
    assert.deepEqual(JSON.parse(new TextDecoder().decode(bytes)), { email: 'Some.Name+Tag@Gmail.com' });
    return json(allowed);
  }) });
  assert.deepEqual(await client.screen('Some.Name+Tag@Gmail.com'), { allowed: true, reason: 'not_listed' });
  assert.equal(requests, 1);
});

test('maps each contract reason consistently', async () => {
  for (const reason of ['blocked_email', 'blocked_domain', 'allowed_domain', 'not_listed']) {
    const disposable = reason.startsWith('blocked_');
    const client = createIronDomeClient({ apiKey: 'synthetic-key', fetch: fake(() => json({ ...allowed, reason, disposable })) });
    const result = await client.screen('test@example.com');
    assert.deepEqual(result, { allowed: !disposable, reason });
    assert.equal(Object.isFrozen(result), true);
  }
});

test('accepts verified provider enum and does not leak extra response fields', async () => {
  for (const provider of ['gmail', 'microsoft', 'icloud', 'proton', 'yahoo', 'custom']) {
    const client = createIronDomeClient({ apiKey: 'synthetic-key', fetch: fake(() => json({ ...allowed, provider, secret: 'ignored' })) });
    assert.deepEqual(await client.screen('test@example.com'), { allowed: true, reason: 'not_listed' });
  }
});

test('Fastmail mail canonicalization keeps the established screening API provider contract', async () => {
  let submitted = '';
  const client = createIronDomeClient({ apiKey: 'synthetic-key', fetch: fake((_url, init) => {
    submitted = JSON.parse(new TextDecoder().decode(init?.body as Uint8Array)).email;
    return json({ ...allowed, provider: 'custom' });
  }) });
  assert.deepEqual(await client.screen('User+tag@fastmail.com'), { allowed: true, reason: 'not_listed' });
  assert.equal(submitted, 'User+tag@fastmail.com');
});

test('invalid client configuration is rejected without I/O', () => {
  for (const apiKey of ['', 'with space', 'key\nInjected:yes', '\u0000']) {
    assert.throws(() => createIronDomeClient({ apiKey }), code('configuration'));
  }
  for (const timeoutMs of [0, -1, NaN, Infinity, 1.1, 2_147_483_648]) {
    assert.throws(() => createIronDomeClient({ apiKey: 'key', timeoutMs }), code('configuration'));
  }
  for (const maxInFlight of [0, -1, 1.1, 65537]) {
    assert.throws(() => createIronDomeClient({ apiKey: 'key', maxInFlight }), code('configuration'));
  }
});

test('obviously malformed direct inputs cannot trigger a billable call', async () => {
  let requests = 0;
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => { requests++; return json(allowed); }) });
  for (const email of ['', 'not-email', '@domain.test', 'local@', 'a@@b', 'a\r\n@b', 'a b@c', '"quoted"@example.com', "o'hara@example.com", 'Name <test@example.com>',
    'mailto:test@example.com', 'test@localhost', 'test@-invalid.example', 'test@invalid-.example',
    'test..name@example.com', '.test@example.com', 'test.@example.com', 'tést@example.com',
    `${'a'.repeat(65)}@example.com`, 'test@xn--.example', '\ud800@b' , 'a@\udfff', `${'é'.repeat(600)}@example.com`]) {
    await assert.rejects(client.screen(email), code('invalid_email', false));
  }
  assert.equal(requests, 0);
});

test('malformed or contradictory success payloads fail closed', async () => {
  const bodies = [null, [], {}, { ...allowed, provider: 'surprise' }, { ...allowed, reason: 'allowed' },
    { ...allowed, valid: false }, { ...allowed, valid: 'true' }, { ...allowed, disposable: 'false' },
    { ...allowed, disposable: true }, { ...allowed, reason: 'blocked_email' },
    { provider: 'gmail', valid: true, disposable: false }];
  for (const body of bodies) {
    const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => json(body)) });
    await assert.rejects(client.screen('test@example.com'), code('protocol', false));
  }
});

test('rejects malformed JSON, non-JSON, unexpected compression and non-UTF8', async () => {
  const responses = [
    () => new Response('{', { headers: { 'content-type': 'application/json' } }),
    () => new Response(JSON.stringify(allowed), { headers: { 'content-type': 'text/plain' } }),
    () => json(allowed, 200, { 'content-encoding': 'gzip' }),
    () => new Response(new Uint8Array([0xff]), { headers: { 'content-type': 'application/json' } }),
  ];
  for (const response of responses) {
    await assert.rejects(createIronDomeClient({ apiKey: 'key', fetch: fake(response) }).screen('test@example.com'), code('protocol'));
  }
});

test('rejects declared oversized response before reading and cancels stream', async () => {
  let cancelled = false;
  const response = new Response(new ReadableStream({ cancel() { cancelled = true; } }), {
    headers: { 'content-type': 'application/json', 'content-length': '16385' },
  });
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => response) });
  await assert.rejects(client.screen('test@example.com'), code('protocol'));
  assert.equal(cancelled, true);
});

test('rejects oversized chunked body without trusting content length', async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new Uint8Array(16385)); }, cancel() { cancelled = true; } });
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => new Response(stream, { headers: { 'content-type': 'application/json' } })) });
  await assert.rejects(client.screen('test@example.com'), code('protocol'));
  assert.equal(cancelled, true);
});

test('rejects a body with a pathological count of empty chunks', async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) { for (let i = 0; i < 257; i++) controller.enqueue(new Uint8Array()); },
    cancel() { cancelled = true; },
  });
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => new Response(stream, { headers: { 'content-type': 'application/json' } })) });
  await assert.rejects(client.screen('test@example.com'), code('protocol'));
  assert.equal(cancelled, true);
});

test('accepts exact maximum body size', async () => {
  const content = JSON.stringify(allowed);
  const body = content + ' '.repeat(16384 - content.length);
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => new Response(body, { headers: { 'content-type': 'application/json' } })) });
  assert.equal((await client.screen('test@example.com')).allowed, true);
});

test('never follows redirects or forwards the key to a new origin', async () => {
  let calls = 0;
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake((_url, init) => {
    calls++;
    assert.equal(init?.redirect, 'manual');
    return new Response(null, { status: 302, headers: { location: 'https://attacker.invalid/' } });
  }) });
  await assert.rejects(client.screen('test@example.com'), code('protocol'));
  assert.equal(calls, 1);
});

test('API error status is sanitized and retryability explicit; no automatic retry', async () => {
  for (const status of [400, 401, 403, 404, 429, 500, 503]) {
    let calls = 0;
    const client = createIronDomeClient({ apiKey: 'synthetic-secret', fetch: fake(() => { calls++; return json({ error: { code: 'PII test@example.com synthetic-secret' } }, status); }) });
    await assert.rejects(client.screen('test@example.com'), (error: unknown) => {
      code('api', status >= 500)(error);
      assert.equal((error as IronDomeClientError).status, status);
      assert.doesNotMatch(JSON.stringify(error), /synthetic-secret|test@example/);
      return true;
    });
    assert.equal(calls, 1);
  }
});

test('non-422 API errors cancel stalled bodies and return from status alone', async () => {
  let cancelled = false;
  const response = new Response(new ReadableStream({ cancel() { cancelled = true; } }), {
    status: 429, headers: { 'content-type': 'application/json' },
  });
  const client = createIronDomeClient({ apiKey: 'key', timeoutMs: 1000, fetch: fake(() => response) });
  await assert.rejects(client.screen('test@example.com'), (error: unknown) => {
    code('api', false)(error);
    assert.equal((error as IronDomeClientError).status, 429);
    return true;
  });
  assert.equal(cancelled, true);
});

test('verified invalid_email API error becomes non-retryable input error', async () => {
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => json({ error: { code: 'invalid_email' } }, 422)) });
  await assert.rejects(client.screen('test@example.com'), code('invalid_email', false));
});

test('transport exceptions are scrubbed and never retained as cause', async () => {
  const client = createIronDomeClient({ apiKey: 'synthetic-secret', fetch: fake(() => { throw new Error('synthetic-secret test@example.com'); }) });
  await assert.rejects(client.screen('test@example.com'), (error: unknown) => {
    code('transport', true)(error);
    assert.doesNotMatch(String(error), /synthetic-secret|test@example/);
    assert.equal((error as Error).cause, undefined);
    return true;
  });
});

test('pre-aborted requests do no I/O', async () => {
  let calls = 0;
  const controller = new AbortController(); controller.abort(new Error('sensitive'));
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => { calls++; return json(allowed); }) });
  await assert.rejects(client.screen('test@example.com', controller.signal), code('cancelled', false));
  assert.equal(calls, 0);
});

test('deadline aborts fetch and bounded slot becomes reusable', async () => {
  let calls = 0;
  let signal: AbortSignal | null | undefined;
  const client = createIronDomeClient({ apiKey: 'key', timeoutMs: 20, maxInFlight: 1, fetch: fake((_input, init) => {
    if (++calls === 1) { signal = init?.signal; return new Promise<Response>(() => undefined); }
    return json(allowed);
  }) });
  await assert.rejects(client.screen('test@example.com'), code('timeout', true));
  assert.equal(signal?.aborted, true);
  assert.equal((await client.screen('test@example.com')).allowed, true);
});

test('deadline covers a stalled body and cancels the stream', async () => {
  let cancelled = false;
  const response = new Response(new ReadableStream({ cancel() { cancelled = true; } }), { headers: { 'content-type': 'application/json' } });
  const client = createIronDomeClient({ apiKey: 'key', timeoutMs: 20, fetch: fake(() => response) });
  await assert.rejects(client.screen('test@example.com'), code('timeout', true));
  assert.equal(cancelled, true);
});

test('caller cancellation wins promptly even if adapter ignores abort', async () => {
  const controller = new AbortController();
  const client = createIronDomeClient({ apiKey: 'key', timeoutMs: 1000, fetch: fake(() => new Promise<Response>(() => undefined)) });
  const pending = client.screen('test@example.com', controller.signal);
  controller.abort('sensitive reason');
  await assert.rejects(pending, code('cancelled', false));
});

test('concurrent calls have a bound and no growing wait queue', async () => {
  let release: (response: Response) => void = () => undefined;
  let calls = 0;
  const client = createIronDomeClient({ apiKey: 'key', maxInFlight: 1, fetch: fake(() => { calls++; return new Promise<Response>((resolve) => { release = resolve; }); }) });
  const first = client.screen('first@example.com');
  await assert.rejects(client.screen('second@example.com'), code('busy', true));
  release(json(allowed));
  assert.equal((await first).allowed, true);
  assert.equal(calls, 1);
});

test('there is no shared raw-address cache and retries are caller-owned', async () => {
  let calls = 0;
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => { calls++; return json(allowed); }) });
  await client.screen('test@example.com');
  await client.screen('test@example.com');
  assert.equal(calls, 2);
});

test('late response after deadline is cancelled instead of retained', async () => {
  let release: (response: Response) => void = () => undefined;
  let cancelled = false;
  const client = createIronDomeClient({ apiKey: 'key', timeoutMs: 10, fetch: fake(() => new Promise<Response>((resolve) => { release = resolve; })) });
  await assert.rejects(client.screen('test@example.com'), code('timeout'));
  release(new Response(new ReadableStream({ cancel() { cancelled = true; } }), { headers: { 'content-type': 'application/json' } }));
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(cancelled, true);
});

test('caller abort listeners are removed on success and failure', async () => {
  for (const fail of [false, true]) {
    const controller = new AbortController();
    let added = 0; let removed = 0;
    const add = controller.signal.addEventListener.bind(controller.signal);
    const remove = controller.signal.removeEventListener.bind(controller.signal);
    controller.signal.addEventListener = ((...args: Parameters<AbortSignal['addEventListener']>) => { added++; add(...args); }) as AbortSignal['addEventListener'];
    controller.signal.removeEventListener = ((...args: Parameters<AbortSignal['removeEventListener']>) => { removed++; remove(...args); }) as AbortSignal['removeEventListener'];
    const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => { if (fail) throw new Error('sensitive'); return json(allowed); }) });
    if (fail) await assert.rejects(client.screen('test@example.com', controller.signal), code('transport'));
    else await client.screen('test@example.com', controller.signal);
    assert.equal(added, 1);
    assert.equal(removed, 1);
  }
});

test('direct client applies shared 254-byte address limit before a billable call', async () => {
  let calls = 0;
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => { calls++; return json(allowed); }) });
  const domainPrefix = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63)].join('.');
  const atLimit = `x@${domainPrefix}.${'d'.repeat(60)}`;
  const tooLong = `x@${domainPrefix}.${'d'.repeat(61)}`;
  assert.equal(Buffer.byteLength(atLimit), 254);
  assert.equal(Buffer.byteLength(tooLong), 255);
  await assert.rejects(client.screen(tooLong), code('invalid_email', false));
  assert.equal(calls, 0);
  assert.equal((await client.screen(atLimit)).allowed, true);
  assert.equal(calls, 1);
});

test('very large direct inputs reject before fetch', async () => {
  let calls = 0;
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => { calls++; return json(allowed); }) });
  await assert.rejects(client.screen('x'.repeat(10_000_000)), code('invalid_email', false));
  assert.equal(calls, 0);
});

test('response fragmentation into single-byte chunks does not change JSON semantics', async () => {
  const bytes = new TextEncoder().encode(JSON.stringify(allowed) + ' '.repeat(512));
  let offset = 0;
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => new Response(new ReadableStream({
    pull(controller) {
      if (offset < bytes.length) controller.enqueue(bytes.slice(offset, ++offset));
      else controller.close();
    },
  }), { headers: { 'content-type': 'application/json' } })) });
  assert.equal((await client.screen('test@example.com')).allowed, true);
});

test('response chunks are copied before a transport reuses their backing buffer', async () => {
  const bytes = new TextEncoder().encode(JSON.stringify({ ...allowed, extra: '€\u{10400}' }));
  const scratch = new Uint8Array(7);
  let offset = 0;
  const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => new Response(new ReadableStream({
    pull(controller) {
      if (offset === bytes.length) { controller.close(); return; }
      const count = Math.min(scratch.length, bytes.length - offset);
      scratch.set(bytes.subarray(offset, offset + count));
      offset += count;
      controller.enqueue(scratch.subarray(0, count));
    },
  }, { highWaterMark: 0 }), { headers: { 'content-type': 'application/json' } })) });
  assert.deepEqual(await client.screen('test@example.com'), { allowed: true, reason: 'not_listed' });
});

test('fragmented UTF-8 bodies obey the byte cap despite an underreported content length', async () => {
  for (const length of [16384, 16385]) {
    const content = JSON.stringify({ ...allowed, extra: '€\u{10400}' });
    const prefix = new TextEncoder().encode(content);
    const bytes = new Uint8Array(length).fill(32);
    bytes.set(prefix);
    let offset = 0;
    let cancelled = false;
    const client = createIronDomeClient({ apiKey: 'key', fetch: fake(() => new Response(new ReadableStream({
      pull(controller) {
        if (offset === bytes.length) { controller.close(); return; }
        // Single-byte prefix splits multibyte UTF-8; later chunks force growth.
        const next = Math.min(bytes.length, offset + (offset < prefix.length ? 1 : 137));
        controller.enqueue(bytes.subarray(offset, next)); offset = next;
      },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 }), { headers: { 'content-type': 'application/json', 'content-length': '1' } })) });
    if (length === 16384) assert.equal((await client.screen('test@example.com')).allowed, true);
    else { await assert.rejects(client.screen('test@example.com'), code('protocol')); assert.equal(cancelled, true); }
  }
});
