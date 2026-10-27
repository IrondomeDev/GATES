import { createServer } from 'node:http';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import { betterAuth } from 'better-auth';
import { getMigrations } from 'better-auth/db/migration';
import { fromNodeHeaders, toNodeHandler } from 'better-auth/node';
import { createIronDomeClient } from '@irondome-dev/gate';
import { createBetterAuthGate } from '@irondome-dev/gate/better-auth';
import { createPostgresBetterAuthChangeStore } from '@irondome-dev/gate/better-auth/postgres';
import { createOnlinePostgresGate } from '@irondome-dev/gate/online/postgres';

const command = process.argv[2];
if (command === '--help') {
  console.log('Usage: node --env-file=examples/docs/.env examples/docs/better-auth-server.mjs <migrate|start>');
  console.log('migrate: apply Better Auth tables after the required GATES migrations');
  console.log('start: localhost development server with private temporary mail capture');
  process.exit(0);
}

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing ${name}.`);
  return value;
}

let pool;
try {
  if (!['migrate', 'start'].includes(command)) throw new Error('Choose migrate or start; use --help for usage.');
  if (command === 'start' && process.env.NODE_ENV === 'production') {
    throw new Error('This development mail-capture server must not run in production.');
  }
  const connectionString = required(command === 'migrate' ? 'MIGRATION_DATABASE_URL' : 'DATABASE_URL');
  const secret = required('BETTER_AUTH_SECRET');
  if (secret.length < 32) throw new Error('BETTER_AUTH_SECRET must contain at least 32 characters.');
  const tenantId = required('GATES_TENANT_ID');
  const apiKey = required('IRONDOME_API_KEY');
  const baseURL = required('BETTER_AUTH_URL');
  const url = new URL(baseURL);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.pathname !== '/api/auth' || url.search || url.hash || url.username || url.password) {
    throw new Error('BETTER_AUTH_URL must be http://127.0.0.1:<port>/api/auth for this local starter.');
  }
  const port = Number(url.port || '80');
  if (port < 1024) throw new Error('Choose an unprivileged port (1024 or above).');
  pool = new Pool({
    connectionString,
    options: '-c search_path=trusted_auth,pg_catalog',
    connectionTimeoutMillis: 2_000,
    statement_timeout: 5_000,
    query_timeout: 6_000,
    lock_timeout: 2_000,
    max: 5,
  });
  const engine = createOnlinePostgresGate(pool, {
    schema: 'trusted_auth',
    screening: createIronDomeClient({ apiKey }),
  });
  const changes = createPostgresBetterAuthChangeStore(pool, { schema: 'trusted_auth' });
  let mailDirectory;
  const integration = createBetterAuthGate({
    tenantId,
    engine,
    changes,
    async sendVerificationEmail({ user, url }) {
      if (!mailDirectory) throw new Error('Mail capture is not initialized.');
      await writeFile(join(mailDirectory, `${randomUUID()}.json`), JSON.stringify({
        to: user.email,
        subject: 'Verify your email address',
        verificationURL: url,
      }, null, 2), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    },
  });
  const options = { database: pool, secret, baseURL, ...integration.authOptions };
  if (command === 'migrate') {
    const migration = await getMigrations(options);
    if (migration.unsafeChanges.length) throw new Error('Review unsafe Better Auth schema changes before applying them.');
    await migration.runMigrations();
    console.log('Better Auth schema migration complete. Apply runtime grants next.');
    await pool.end();
  } else {
    await engine.getEmailPolicy(tenantId);
    mailDirectory = await mkdtemp(join(tmpdir(), 'gates-mail-'));
    const bound = integration.bind(betterAuth(options));
    const authHandler = toNodeHandler(bound.handler);
    const server = createServer((request, response) => {
      void (async () => {
        const path = new URL(request.url ?? '/', baseURL).pathname;
        if (path.startsWith('/api/auth/')) return authHandler(request, response);
        if (path === '/api/protected' && request.method === 'GET') {
          const session = await bound.getActiveSession(fromNodeHeaders(request.headers));
          response.writeHead(session ? 200 : 401, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
          response.end(JSON.stringify({ allowed: Boolean(session) }));
          return;
        }
        response.writeHead(404);
        response.end();
      })().catch(() => {
        if (!response.headersSent) response.writeHead(503, { 'Cache-Control': 'no-store' });
        response.end();
      });
    });
    let closing = false;
    const close = () => {
      if (closing) return;
      closing = true;
      server.close(() => { void pool.end(); });
      server.closeIdleConnections();
    };
    process.once('SIGINT', close);
    process.once('SIGTERM', close);
    server.once('error', () => {
      console.error('Server could not start. Check the configured port.');
      void pool.end();
      process.exitCode = 1;
    });
    server.listen(port, '127.0.0.1', () => {
      console.log(`Development auth server: ${baseURL}`);
      console.log(`Private development mail directory: ${mailDirectory}`);
      console.log('Verification URLs are stored only in private files. Delete this directory after testing.');
    });
  }
} catch (error) {
  // never print database errors or credential-bearing connection strings
  const safe = error instanceof Error && /^(Missing |Choose |BETTER_AUTH_|This development|Review unsafe)/.test(error.message);
  console.error(safe ? error.message : 'Setup failed. Check configuration, database connectivity, schema and permissions.');
  if (pool) await pool.end();
  process.exitCode = 1;
}
