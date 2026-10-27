import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { spawn, spawnSync } from 'node:child_process';
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http';
import { createServer as createTcpServer, type Server as TcpServer } from 'node:net';
import { resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { SignJWT } from 'jose';
import { createLifecycleGate } from '../src/core/lifecycle.js';
import { createOnlinePostgresGate } from '../src/storage/postgres/online.js';
import { createPostgresIdentityRegistry } from '../src/storage/postgres/identity.js';
import { createProviderLifecycle } from '../src/core/provider-lifecycle.js';
import { createPostgresProviderOperationStore } from '../src/storage/postgres/provider-lifecycle.js';
import { createSupabaseGate, type SupabaseProviderUser } from '../src/connectors/supabase/index.js';
import type { PgPool } from '../src/storage/postgres/identity.js';
import { createEmailPolicy, prepareEmail } from '../src/core/policy.js';

const gotrueBinary = process.env.GATE_TEST_GOTRUE_BIN;
const postgresUrl = process.env.GATE_TEST_POSTGRES_URL;
const supported = !!gotrueBinary && !!postgresUrl;
const TEST_TIMEOUT_MS = 180_000;
const STARTUP_TIMEOUT_MS = 60_000;

interface CapturedMail { recipient: string; text: string }
function listen(server: HttpServer | TcpServer): Promise<number> {
  return new Promise((resolvePort, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      const address = server.address();
      if (!address || typeof address === 'string') return reject(new Error('Invalid listener address'));
      resolvePort(address.port);
    });
  });
}
function close(server: HttpServer | TcpServer): Promise<void> {
  return new Promise(resolveClose => server.close(() => resolveClose()));
}
async function freePort(): Promise<number> {
  const server = createHttpServer();
  const port = await listen(server);
  await close(server);
  return port;
}
function safeDatabaseUrl(raw: string, database: string): string {
  const url = new URL(raw);
  if (!['postgres:', 'postgresql:'].includes(url.protocol) || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) || url.search !== '') {
    throw new Error('Integration requires explicit loopback PostgreSQL URL');
  }
  url.pathname = `/${database}`;
  return url.toString();
}
async function waitFor<T>(get: () => T | undefined, timeout = 10_000): Promise<T> {
  const stop = Date.now() + timeout;
  while (Date.now() < stop) {
    const value = get();
    if (value !== undefined) return value;
    await delay(25);
  }
  throw new Error('Timed out waiting for local fixture data');
}
async function nextMail(messages: CapturedMail[], recipient: string, fromIndex: number): Promise<{ mail: CapturedMail; index: number }> {
  const until = Date.now() + 15_000;
  while (Date.now() < until) {
    const index = messages.findIndex((mail, i) => i >= fromIndex && mail.recipient.toLowerCase() === recipient.toLowerCase());
    if (index >= 0) return { mail: messages[index]!, index };
    await delay(25);
  }
  throw new Error('Timed out waiting for captured local confirmation mail');
}
function confirmationUrl(message: string): string {
  const decoded = message.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (_whole, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
  const match = /https?:\/\/[^\s<>"']+/.exec(decoded);
  if (!match) throw new Error('GoTrue confirmation link missing from local SMTP message');
  const url = new URL(match[0].replace(/&amp;/g, '&').replace(/&quot;/g, ''));
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) || url.pathname !== '/verify') throw new Error('Unexpected confirmation link origin');
  return url.href;
}
function codeVerifier(): string { return randomBytes(32).toString('base64url'); }
function codeChallenge(verifier: string): string { return createHash('sha256').update(verifier).digest('base64url'); }
function scrubRuntimeText(raw: string, secrets: string[]): string {
  let text = raw;
  for (const secret of secrets) if (secret) text = text.split(secret).join('[redacted]');
  return text.replace(/postgres(?:ql)?:\/\/[^\s"']+/gi, '[database-url]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[email]')
    .replace(/\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, '[jwt]')
    .split('\n').slice(-8).join('\n').slice(-800);
}
async function assertHttpOk(response: Response, where: string, diagnostic = '', secrets: string[] = []): Promise<void> {
  if (response.ok) return;
  const value = await response.clone().json().catch(() => ({})) as Record<string, unknown>;
  const code = typeof value.error_code === 'string' ? value.error_code : typeof value.code === 'string' ? value.code : 'unknown';
  const rawMessage = typeof value.msg === 'string' ? value.msg : typeof value.message === 'string' ? value.message : '';
  const message = rawMessage.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[email]')
    .replace(/\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, '[jwt]').slice(0, 240);
  const details = diagnostic ? scrubRuntimeText(diagnostic, secrets) : '';
  throw new Error(`${where}: HTTP ${response.status}, provider code ${code}${message ? `, ${message}` : ''}${details ? `; sanitized local logs: ${details}` : ''}`);
}
function smtpServer(messages: CapturedMail[]): TcpServer {
  return createTcpServer(socket => {
    socket.setEncoding('utf8');
    socket.write('220 localhost ESMTP ready\r\n');
    let carry = '';
    let inData = false;
    let data = '';
    let recipient = '';
    socket.on('data', chunk => {
      carry += chunk;
      if (inData) {
        const end = carry.indexOf('\r\n.\r\n');
        if (end < 0) { data += carry; carry = ''; return; }
        data += carry.slice(0, end);
        carry = carry.slice(end + 5);
        inData = false;
        messages.push({ recipient, text: data });
        data = '';
        socket.write('250 2.0.0 queued\r\n');
      }
      const lines = carry.split('\r\n');
      carry = lines.pop() ?? '';
      for (const line of lines) {
        if (/^(EHLO|HELO) /i.test(line)) socket.write('250-localhost\r\n250 OK\r\n');
        else if (/^MAIL FROM:/i.test(line)) socket.write('250 OK\r\n');
        else if (/^RCPT TO:/i.test(line)) { recipient = line.slice(line.indexOf(':') + 1).trim().replace(/^<|>$/g, ''); socket.write('250 OK\r\n'); }
        else if (/^DATA$/i.test(line)) { inData = true; socket.write('354 End data with <CR><LF>.<CR><LF>\r\n'); }
        else if (/^RSET$/i.test(line)) { recipient = ''; socket.write('250 OK\r\n'); }
        else if (/^NOOP$/i.test(line)) socket.write('250 OK\r\n');
        else if (/^QUIT$/i.test(line)) { socket.write('221 Bye\r\n'); socket.end(); }
        else socket.write('250 OK\r\n');
      }
    });
  });
}
function readBody(req: import('node:http').IncomingMessage, maxBytes = 64 * 1024): Promise<Buffer> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) { reject(new Error('hook body too large')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => resolveBody(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

for (const storage of ['fixed', 'online'] as const) test(`self-hosted GoTrue v2.197.0 (${storage} storage): signup, PKCE proof, token hooks, aliases, lifecycle, refresh and deletion`, {
  skip: supported ? false : 'requires explicit GATE_TEST_GOTRUE_BIN and loopback GATE_TEST_POSTGRES_URL',
  timeout: TEST_TIMEOUT_MS,
}, async t => {
  const binary = resolve(gotrueBinary!);
  const databaseName = `gate_auth_it_${process.pid}_${randomBytes(4).toString('hex')}`;
  const adminUrl = new URL(safeDatabaseUrl(postgresUrl!, 'postgres'));
  type LocalPool = PgPool & { end(): Promise<void> };
  const driverModuleName = 'pg';
  const driverModule = await import(driverModuleName) as unknown as { Pool: new (options: Record<string, unknown>) => LocalPool };
  const driver = new driverModule.Pool({
    connectionString: adminUrl.toString(), connectionTimeoutMillis: 2000, statement_timeout: 5000,
  });
  let databaseCreated = false;
  let postgresRoleCreated = false;
  let dbPool: LocalPool | undefined;
  let hookServer: HttpServer | undefined;
  let smtp: TcpServer | undefined;
  let gotrue: ReturnType<typeof spawn> | undefined;
  let shutdown: Promise<void> | undefined;
  const logs: string[] = [];
  const mails: CapturedMail[] = [];
  const hookOutcomes: string[] = [];
  const screeningOutcomes: string[] = [];
  const hookEventShapes: string[] = [];
  const jwtSecret = randomBytes(48).toString('base64url');
  const hookKey = `whsec_${randomBytes(32).toString('base64')}`;
  const hookSecret = `v1,${hookKey}`;
  const namespace = `integration-${process.pid}-${Date.now()}`;
  let apiBase = '';
  let serviceKey = '';
  let anonKey = '';
  let adapter: ReturnType<typeof createSupabaseGate> | undefined;
  let gate: ReturnType<typeof createLifecycleGate> | ReturnType<typeof createOnlinePostgresGate> | undefined;
  let onlineGate: ReturnType<typeof createOnlinePostgresGate> | undefined;
  let providerLifecycle: ReturnType<typeof createProviderLifecycle> | undefined;

  t.after(async () => {
    if (gotrue && gotrue.exitCode === null) {
      gotrue.kill('SIGTERM');
      await Promise.race([shutdown ?? new Promise<void>(resolveShutdown => gotrue!.once('exit', () => resolveShutdown())), delay(3000)]);
      if (gotrue.exitCode === null) gotrue.kill('SIGKILL');
    }
    if (hookServer) await close(hookServer);
    if (smtp) await close(smtp);
    await dbPool?.end();
    try {
      if (databaseCreated) {
        // Pool.end can resolve while TCP close is still reaching PostgreSQL.
        // Wait for the server to observe the closes before dropping the database;
        // FORCE can otherwise terminate a Node client during its close handshake.
        const deadline = Date.now() + 5000;
        for (;;) {
          const sessions = await driver.query('SELECT count(*)::int AS count FROM pg_catalog.pg_stat_activity WHERE datname=$1', [databaseName]);
          if (sessions.rows[0]?.count === 0) break;
          if (Date.now() >= deadline) throw new Error('Local auth database connections did not close');
          await delay(25);
        }
        await driver.query(`DROP DATABASE "${databaseName}"`);
      }
    } finally {
      try { if (postgresRoleCreated) await driver.query('DROP ROLE postgres'); }
      finally { await driver.end(); }
    }
  });

  const binaryVersion = spawnSync(binary, ['version'], { encoding: 'utf8', timeout: 5000, env: process.env });
  assert.equal(binaryVersion.status, 0);
  assert.match(binaryVersion.stdout + binaryVersion.stderr, /v2\.197\.0/i);
  await driver.query(`CREATE DATABASE "${databaseName}"`);
  databaseCreated = true;
  const postgresRole = await driver.query("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='postgres'");
  if (postgresRole.rows.length === 0) {
    await driver.query('CREATE ROLE postgres NOLOGIN');
    postgresRoleCreated = true;
  }
  const testDatabaseUrl = safeDatabaseUrl(postgresUrl!, databaseName);
  const gotrueDatabaseUrl = new URL(testDatabaseUrl);
  gotrueDatabaseUrl.searchParams.set('search_path', 'auth,public');
  dbPool = new driverModule.Pool({ connectionString: testDatabaseUrl, max: 12, connectionTimeoutMillis: 2000,
    statement_timeout: 5000, query_timeout: 6000, lock_timeout: 3000 });
  await dbPool.query('CREATE SCHEMA auth');
  await dbPool.query(await readFile(resolve('migrations/001_identity.sql'), 'utf8'));
  await dbPool.query(await readFile(resolve('migrations/002_lifecycle.sql'), 'utf8'));
  await dbPool.query(await readFile(resolve('migrations/004_provider_operations.sql'), 'utf8'));
  await dbPool.query(await readFile(resolve('migrations/005_tenant_policy.sql'), 'utf8'));
  if (storage === 'online') await dbPool.query(await readFile(resolve('migrations/006_online_policy.sql'), 'utf8'));

  const registry = createPostgresIdentityRegistry(dbPool as unknown as PgPool);
  const screening = { async screen(email: string) {
    const allowed = !email.toLowerCase().startsWith('blocked-');
    screeningOutcomes.push(allowed ? 'allowed' : 'denied');
    return { allowed, reason: 'local-integration' };
  } };
  if (storage === 'online') {
    onlineGate = createOnlinePostgresGate(dbPool, { screening });
    gate = onlineGate;
  } else gate = createLifecycleGate({ registry, screening });
  const operationStore = createPostgresProviderOperationStore(dbPool as unknown as PgPool);
  const emailUsers = new Map<string, string>();
  let savedRefreshToken = '';
  let apiPort = 0;
  // The reader is filled after GoTrue starts. All hook reads go through GoTrue's real admin API.
  const providerReader = async (userId: string, signal?: AbortSignal) => {
    const response = await fetch(`${apiBase}/admin/users/${encodeURIComponent(userId)}`, {
      headers: { authorization: `Bearer ${serviceKey}`, apikey: serviceKey }, ...(signal ? { signal } : {}),
    });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error('local GoTrue admin lookup failed');
    const value = await response.json() as Record<string, unknown>;
    if (typeof value.id !== 'string' || typeof value.email !== 'string') return null;
    return value;
  };
  const lifecycleReader = async (userId: string, signal?: AbortSignal) => {
    const value = await providerReader(userId, signal);
    if (!value) return null;
    return { id: String(value.id), email: String(value.email), emailVerified: typeof value.email_confirmed_at === 'string',
      generation: String(value.created_at) };
  };
  const providerPlaceholder = { getUserById: lifecycleReader,
    async deleteUser(userId: string, generation: string, signal?: AbortSignal) {
      const current = await lifecycleReader(userId, signal);
      if (!current) return;
      if (current.generation !== generation) throw new Error('provider generation changed');
      const response = await fetch(`${apiBase}/admin/users/${encodeURIComponent(userId)}`, {
        method: 'DELETE', headers: { authorization: `Bearer ${serviceKey}`, apikey: serviceKey }, ...(signal ? { signal } : {}),
      });
      if (!response.ok && response.status !== 404) throw new Error('local GoTrue delete failed');
    } };

  smtp = smtpServer(mails);
  const smtpPort = await listen(smtp);
  const stubScreenGate = createSupabaseGate({ tenantId: 'gotrue-integration', gate, webhookSecret: hookSecret,
    async getUserById(userId, signal) {
      const value = await providerReader(userId, signal);
      if (!value) return null;
      return value as unknown as SupabaseProviderUser;
    }, async getUserForAccessToken(token, signal) {
      const response = await fetch(`${apiBase}/user`, { headers: { authorization: `Bearer ${token}`, apikey: anonKey }, ...(signal ? { signal } : {}) });
      if (!response.ok) return null;
      return await response.json() as SupabaseProviderUser;
    } });
  adapter = stubScreenGate;
  const hookServerPortPromise = new Promise<number>((resolvePort, reject) => {
    hookServer = createHttpServer(async (req, res) => {
      try {
        const raw = await readBody(req);
        try {
          const payload = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
          const user = payload.user as Record<string, unknown> | undefined;
          const claims = payload.claims as Record<string, unknown> | undefined;
          const claimInfo = claims && typeof claims === 'object'
            ? `claims=${Object.keys(claims).join('|')}:sub-match=${payload.user_id === claims.sub}:email-type=${typeof claims.email}` : '';
          hookEventShapes.push(`${req.url?.split('?')[0]}:root=${Object.keys(payload).join('|')}:user=${user && typeof user === 'object' ? Object.keys(user).join('|') : typeof user}:email=${typeof user?.email}:uid=${typeof payload.user_id}:${claimInfo}`);
        } catch { hookEventShapes.push(`${req.url?.split('?')[0]}:invalid-json`); }
        const headers = new Headers();
        for (const [key, value] of Object.entries(req.headers)) {
          if (typeof value === 'string') headers.set(key, value);
          else if (Array.isArray(value)) headers.set(key, value.join(', '));
        }
        const request = new Request(`http://127.0.0.1:${(hookServer!.address() as { port: number }).port}${req.url ?? '/'}`, {
          method: req.method ?? 'POST', headers, body: Uint8Array.from(raw),
        });
        const response = req.url?.includes('before-user-created') ? await adapter!.beforeUserCreated(request) : await adapter!.customAccessToken(request);
        res.statusCode = response.status;
        response.headers.forEach((value, key) => res.setHeader(key, value));
        const responseBody = await response.text();
        try {
          const value = JSON.parse(responseBody) as { error?: { http_code?: unknown } };
          if (value.error) hookOutcomes.push(`${req.url?.split('?')[0]}:${String(value.error.http_code ?? 'unknown')}`);
        } catch { hookOutcomes.push(`${req.url?.split('?')[0]}:invalid-response`); }
        res.end(responseBody);
      } catch {
        res.statusCode = 503;
        res.setHeader('content-type', 'application/json');
        res.end('{"error":{"message":"Unable to complete this request.","http_code":503}}');
      }
    });
    hookServer.once('error', reject);
    hookServer.listen(0, '127.0.0.1', () => {
      hookServer!.removeListener('error', reject);
      const address = hookServer!.address();
      if (!address || typeof address === 'string') return reject(new Error('Invalid hook address'));
      resolvePort(address.port);
    });
  });
  const hookPort = await hookServerPortPromise;
  const smtpConfiguredBase = `http://127.0.0.1:${hookPort}`;
  apiPort = await freePort();
  apiBase = `http://127.0.0.1:${apiPort}`;
  const payload = { role: 'service_role', iss: 'supabase', aud: 'authenticated' };
  serviceKey = await new SignJWT(payload).setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('1h').sign(new TextEncoder().encode(jwtSecret));
  anonKey = await new SignJWT({ role: 'anon', iss: 'supabase', aud: 'authenticated' }).setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('1h').sign(new TextEncoder().encode(jwtSecret));
  providerLifecycle = createProviderLifecycle({ tenantId: 'gotrue-integration', namespace, engine: gate,
    operations: operationStore, ...providerPlaceholder });
  // Replace the adapter with the lifecycle-aware instance before any GoTrue request.
  adapter = createSupabaseGate({ tenantId: 'gotrue-integration', gate, webhookSecret: hookSecret,
    lifecycle: providerLifecycle,
    async getUserById(userId, signal) {
      const value = await providerReader(userId, signal);
      if (!value) return null;
      return value as unknown as SupabaseProviderUser;
    }, async getUserForAccessToken(token, signal) {
      const response = await fetch(`${apiBase}/user`, { headers: { authorization: `Bearer ${token}`, apikey: anonKey }, ...(signal ? { signal } : {}) });
      if (!response.ok) return null;
      return await response.json() as SupabaseProviderUser;
    } });

  const baseEnvironment: NodeJS.ProcessEnv = { ...process.env,
    GOTRUE_API_HOST: '127.0.0.1', GOTRUE_API_PORT: String(apiPort), PORT: String(apiPort),
    GOTRUE_API_EXTERNAL_URL: apiBase, API_EXTERNAL_URL: apiBase,
    GOTRUE_DB_DRIVER: 'postgres', GOTRUE_DB_DATABASE_URL: gotrueDatabaseUrl.toString(), GOTRUE_DB_NAMESPACE: 'auth',
    GOTRUE_JWT_SECRET: jwtSecret, GOTRUE_JWT_EXP: '3600', GOTRUE_SITE_URL: 'http://127.0.0.1:4000',
    GOTRUE_URI_ALLOW_LIST: 'http://127.0.0.1:4000', GOTRUE_DISABLE_SIGNUP: 'false',
    GOTRUE_EXTERNAL_EMAIL_ENABLED: 'true', GOTRUE_EXTERNAL_PHONE_ENABLED: 'false',
    GOTRUE_MAILER_AUTOCONFIRM: 'false', GOTRUE_MAILER_ALLOW_UNVERIFIED_EMAIL_SIGN_INS: 'false',
    GOTRUE_MAILER_SECURE_EMAIL_CHANGE_ENABLED: 'true', GOTRUE_SMTP_HOST: '127.0.0.1', GOTRUE_SMTP_PORT: String(smtpPort),
    GOTRUE_SMTP_ADMIN_EMAIL: 'admin@localhost', GOTRUE_SMTP_SENDER_NAME: 'Local GoTrue Test',
    GOTRUE_HOOK_BEFORE_USER_CREATED_ENABLED: 'true', GOTRUE_HOOK_BEFORE_USER_CREATED_URI: `${smtpConfiguredBase}/before-user-created`,
    GOTRUE_HOOK_BEFORE_USER_CREATED_SECRETS: hookSecret,
    GOTRUE_HOOK_CUSTOM_ACCESS_TOKEN_ENABLED: 'true', GOTRUE_HOOK_CUSTOM_ACCESS_TOKEN_URI: `${smtpConfiguredBase}/custom-access-token`,
    GOTRUE_HOOK_CUSTOM_ACCESS_TOKEN_SECRETS: hookSecret, GOTRUE_LOG_LEVEL: 'error',
  };
  const migration = spawnSync(binary, ['migrate'], { cwd: process.cwd(), env: baseEnvironment,
    encoding: 'utf8', timeout: STARTUP_TIMEOUT_MS, windowsHide: true });
  if (migration.status !== 0) throw new Error(`local GoTrue migration failed (exit ${migration.status ?? 'timeout'}): ${scrubRuntimeText(`${migration.stdout ?? ''}\n${migration.stderr ?? ''}`, [gotrueDatabaseUrl.toString(), jwtSecret, hookSecret, serviceKey, anonKey])}`);
  gotrue = spawn(binary, ['serve'], { cwd: process.cwd(), env: baseEnvironment,
    stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  const onLog = (chunk: Buffer) => { if (logs.length < 50) logs.push(chunk.toString('utf8').slice(0, 2048)); };
  gotrue.stdout?.on('data', onLog); gotrue.stderr?.on('data', onLog);
  shutdown = new Promise<void>(resolveShutdown => gotrue!.once('exit', () => resolveShutdown()));
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  let ready = false;
  while (Date.now() < deadline && gotrue.exitCode === null) {
    try { const response = await fetch(`${apiBase}/health`, { signal: AbortSignal.timeout(500) }); if (response.ok) { ready = true; break; } }
    catch { /* local child is still starting */ }
    await delay(250);
  }
  assert.ok(ready, `GoTrue v2.197.0 failed to start; exit=${gotrue.exitCode}; captured ${logs.length} bounded local log chunks`);

  const headers = { apikey: anonKey, 'content-type': 'application/json' };
  async function request(path: string, init: RequestInit = {}) {
    return await fetch(`${apiBase}${path}`, { ...init, headers: { ...headers, ...(init.headers as Record<string, string> | undefined) } });
  }
  async function signup(email: string, verifier: string) {
    return await request('/signup', { method: 'POST', body: JSON.stringify({ email, password: 'LocalOnly-Password-4862!',
      code_challenge: codeChallenge(verifier), code_challenge_method: 's256' }) });
  }
  async function confirm(email: string, verifier: string, fromIndex: number, type = 'signup') {
    const delivered = await nextMail(mails, email, fromIndex);
    const parsedUrl = new URL(confirmationUrl(delivered.mail.text));
    // Supabase clients append the verification type when opening a token link.
    if (!parsedUrl.searchParams.has('type')) parsedUrl.searchParams.set('type', type);
    const url = parsedUrl.href;
    const emailedToken = parsedUrl.searchParams.get('token') ?? '';
    const rowToken = (await dbPool!.query('SELECT confirmation_token FROM auth.users WHERE email=$1', [email])).rows[0]?.confirmation_token;
    const response = await fetch(url, { redirect: 'manual' });
    if (response.status !== 303) {
      const body = await response.clone().json().catch(() => ({})) as Record<string, unknown>;
      const code = typeof body.error_code === 'string' ? body.error_code : typeof body.code === 'string' ? body.code : 'unknown';
      const message = typeof body.msg === 'string' ? body.msg.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[email]').slice(0, 200) : '';
      throw new Error(`GoTrue confirmation HTTP ${response.status}, provider code ${code}${message ? `, ${message}` : ''}; token-match=${typeof rowToken === 'string' && rowToken === emailedToken}, row-prefix=${typeof rowToken === 'string' ? rowToken.slice(0, 5) : 'none'}, link-prefix=${emailedToken.slice(0, 5)}, row-len=${typeof rowToken === 'string' ? rowToken.length : 0}, link-len=${emailedToken.length}`);
    }
    const location = response.headers.get('location');
    assert.ok(location);
    const locationUrl = new URL(location);
    const code = locationUrl.searchParams.get('code');
    const fragment = new URLSearchParams(locationUrl.hash.slice(1));
    const fragmentCode = fragment.get('error_code') ?? fragment.get('error') ?? 'none';
    assert.ok(code, `PKCE callback has no code (query=${[...locationUrl.searchParams.keys()].join(',')}, fragment=${[...fragment.keys()].join(',')}, provider code=${fragmentCode}, token-match=${typeof rowToken === 'string' && rowToken === emailedToken}, row-prefix=${typeof rowToken === 'string' ? rowToken.slice(0, 5) : 'none'}, link-prefix=${emailedToken.slice(0, 5)}, row-len=${typeof rowToken === 'string' ? rowToken.length : 0}, link-len=${emailedToken.length})`);
    const exchange = await request('/token?grant_type=pkce', { method: 'POST', body: JSON.stringify({ auth_code: code, code_verifier: verifier }) });
    return { response: exchange, json: await exchange.json() as Record<string, unknown>, mailIndex: delivered.index };
  }

  await t.test('Before User Created rejects blocked email before GoTrue inserts a row', async () => {
    const verifier = codeVerifier();
    const email = `blocked-${randomBytes(5).toString('hex')}@example.test`;
    const response = await signup(email, verifier);
    assert.ok(!response.ok);
    const result = await dbPool!.query('SELECT count(*)::int AS count FROM auth.users WHERE email=$1', [email]);
    assert.equal(result.rows[0]?.count, 0);
  });

  await t.test('PKCE email confirmation commits before token hook, then live password/session works', async () => {
    const verifier = codeVerifier();
    const email = `gate.${randomBytes(5).toString('hex')}+one@gmail.com`;
    const beforeMail = mails.length;
    const start = await signup(email, verifier);
    await assertHttpOk(start, 'signup', `${logs.join('\n')}\nHook outcomes: ${hookOutcomes.join(',')}\nScreening: ${screeningOutcomes.join(',')}\nHook event shapes: ${hookEventShapes.join(';')}`,
      [testDatabaseUrl, gotrueDatabaseUrl.toString(), jwtSecret, hookSecret, serviceKey, anonKey]);
    const signupJson = await start.json() as Record<string, unknown>;
    assert.equal(signupJson.access_token, undefined);
    const issued = await confirm(email, verifier, beforeMail);
    const exchangeCode = typeof issued.json.error_code === 'string' ? issued.json.error_code : 'unknown';
    assert.ok(issued.response.ok, `PKCE token exchange failed with provider code ${exchangeCode}; hook outcomes=${hookOutcomes.join(',')}; event shapes=${hookEventShapes.join(';')}; screening=${screeningOutcomes.join(',')}`);
    assert.equal(typeof issued.json.access_token, 'string');
    assert.equal(typeof issued.json.refresh_token, 'string');
    assert.ok(issued.json.user && typeof issued.json.user === 'object');
    const user = issued.json.user as Record<string, unknown>;
    assert.equal(user.email, email);
    const userId = String(user.id);
    emailUsers.set(email, userId);
    assert.equal((await dbPool!.query('SELECT email_confirmed_at IS NOT NULL AS confirmed FROM auth.users WHERE id=$1', [userId])).rows[0]?.confirmed, true);

    const login = await request('/token?grant_type=password', { method: 'POST', body: JSON.stringify({ email, password: 'LocalOnly-Password-4862!' }) });
    await assertHttpOk(login, 'password login');
    const loginJson = await login.json() as Record<string, unknown>;
    assert.equal(typeof loginJson.access_token, 'string');
    savedRefreshToken = String(issued.json.refresh_token);
    const active = await adapter!.assertActive(String(loginJson.access_token));
    assert.equal(active.id, userId);
  });

  await t.test('a canonical alias conflict cannot receive a token, and revocation rejects refresh', async () => {
    const email = [...emailUsers.keys()][0]!;
    const userId = emailUsers.get(email)!;
    const original = await request('/token?grant_type=password', { method: 'POST', body: JSON.stringify({ email, password: 'LocalOnly-Password-4862!' }) });
    await assertHttpOk(original, 'password login before alias check');
    const originalJson = await original.json() as Record<string, unknown>;

    const alias = email.replace('+one@', '+two@');
    const verifier = codeVerifier();
    const startIndex = mails.length;
    await assertHttpOk(await signup(alias, verifier), 'alias signup');
    const aliasResult = await confirm(alias, verifier, startIndex);
    assert.ok(!aliasResult.response.ok, 'canonical conflict blocks token issuance after independent provider confirmation');
    assert.equal(aliasResult.json.access_token, undefined);
    assert.equal((await dbPool!.query('SELECT email_confirmed_at IS NOT NULL AS confirmed FROM auth.users WHERE email=$1', [alias])).rows[0]?.confirmed, true);

    assert.ok(originalJson.refresh_token);
  });

  await t.test('pending email change preserves old confirmed access; staged proof commits before canonical replacement, then revocation rejects refresh', async () => {
    const oldEmail = [...emailUsers.keys()][0]!;
    const userId = emailUsers.get(oldEmail)!;
    const login = await request('/token?grant_type=password', { method: 'POST', body: JSON.stringify({ email: oldEmail, password: 'LocalOnly-Password-4862!' }) });
    await assertHttpOk(login, 'password login before email change');
    const loginJson = await login.json() as Record<string, unknown>;
    const accessToken = String(loginJson.access_token);
    const newEmail = oldEmail.replace('+one@gmail.com', '+changed@example.test');
    await providerLifecycle!.beginEmailChange({ userId, email: newEmail });
    const verifier = codeVerifier();
    const beforeChangeMails = mails.length;
    const change = await request('/user', { method: 'PUT', headers: { authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ email: newEmail, code_challenge: codeChallenge(verifier), code_challenge_method: 's256' }) });
    await assertHttpOk(change, 'email change request');
    const during = await adapter!.assertActive(accessToken);
    assert.equal(during.email, oldEmail, 'old current confirmed address stays active while the provider change is pending');
    const oldProof = await nextMail(mails, oldEmail, beforeChangeMails);
    const newProof = await nextMail(mails, newEmail, beforeChangeMails);
    if (storage === 'online') {
      const beforeCutover = await gate!.getOwnership({ tenantId: 'gotrue-integration', userId });
      assert.equal(beforeCutover.status, 'active');
      if (beforeCutover.status !== 'active') return;
      const targetPolicy = createEmailPolicy({ 'example.test': { lowercase: true, stripPlusTag: true, stripDots: true } });
      const begun = await onlineGate!.migration.begin({ tenantId: 'gotrue-integration', targetPolicy });
      assert.ok(begun.pendingEpoch);
      let migrationStatus = begun;
      for (let i = 0; i < 20 && migrationStatus.phase === 'building'; i++) {
        migrationStatus = await onlineGate!.migration.backfill({ tenantId: 'gotrue-integration', epoch: begun.pendingEpoch!, batchSize: 10 });
      }
      assert.equal(migrationStatus.phase, 'ready');
      const activated = await onlineGate!.migration.activate({ tenantId: 'gotrue-integration', epoch: begun.pendingEpoch! });
      assert.equal(activated.activePolicyVersion, targetPolicy.version);
      const afterCutover = await gate!.getOwnership({ tenantId: 'gotrue-integration', userId });
      assert.deepEqual(afterCutover.status === 'active' ? { policyVersion: afterCutover.policyVersion, revision: afterCutover.revision } : afterCutover,
        { policyVersion: targetPolicy.version, revision: beforeCutover.revision });
      assert.equal((await adapter!.assertActive(accessToken)).email, oldEmail,
        'the old confirmed GoTrue token stays active after the representation-only policy flip');
    }
    const oldConfirmation = await fetch(confirmationUrl(oldProof.mail.text), { redirect: 'manual' });
    assert.equal(oldConfirmation.status, 303);
    const finalUrl = confirmationUrl(newProof.mail.text);
    const finalConfirmation = await fetch(finalUrl, { redirect: 'manual' });
    assert.equal(finalConfirmation.status, 303);
    const location = finalConfirmation.headers.get('location');
    assert.ok(location);
    const code = new URL(location).searchParams.get('code');
    assert.ok(code);
    const completed = await request('/token?grant_type=pkce', { method: 'POST', body: JSON.stringify({ auth_code: code, code_verifier: verifier }) });
    assert.ok(completed.ok, 'trusted staged provider operation moves the gate only after fresh confirmed provider state');
    const state = await gate!.getOwnership({ tenantId: 'gotrue-integration', userId });
    assert.equal(state.status, 'active');
    if (state.status === 'active') {
      const canonical = storage === 'online'
        ? (await onlineGate!.prepareEmail({ tenantId: 'gotrue-integration', email: newEmail, policyVersion: state.policyVersion })).canonical
        : prepareEmail(newEmail).canonical;
      assert.equal(state.canonical, canonical);
      if (storage === 'online') {
        assert.equal(state.policyVersion, (await onlineGate!.migration.status({ tenantId: 'gotrue-integration' })).activePolicyVersion,
          'the GoTrue proof was committed under the active post-cutover epoch');
      }
    }
    await gate!.revokeUser({ tenantId: 'gotrue-integration', userId });
    const refresh = await request('/token?grant_type=refresh_token', { method: 'POST', body: JSON.stringify({ refresh_token: savedRefreshToken }) });
    assert.ok(!refresh.ok, 'revoked identity cannot mint a token from its live refresh token');
  });

  await t.test('native provider deletion invalidates an already issued access token at protected lookup', async () => {
    const user = await request('/admin/users', { method: 'POST', headers: { authorization: `Bearer ${serviceKey}` },
      body: JSON.stringify({ email: `delete-${randomBytes(5).toString('hex')}@example.test`, password: 'LocalOnly-Password-4862!', email_confirm: true }) });
    await assertHttpOk(user, 'admin create user');
    const created = await user.json() as Record<string, unknown>;
    const email = String(created.email);
    const signIn = await request('/token?grant_type=password', { method: 'POST', body: JSON.stringify({ email, password: 'LocalOnly-Password-4862!' }) });
    await assertHttpOk(signIn, 'password login before delete');
    const signInJson = await signIn.json() as Record<string, unknown>;
    const token = String(signInJson.access_token);
    const userId = String((signInJson.user as Record<string, unknown>).id);
    const deletion = await request(`/admin/users/${encodeURIComponent(userId)}`, { method: 'DELETE', headers: { authorization: `Bearer ${serviceKey}` } });
    assert.ok(deletion.ok);
    await assert.rejects(adapter!.assertActive(token));
  });
});
