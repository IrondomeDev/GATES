import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    throw new Error(`${command} exited with status ${result.status}`);
  }
  return result.stdout ?? '';
}
function parseJsonOutput(output) {
  const start = output.search(/[\[{]/);
  assert.notEqual(start, -1, 'npm pack --json returned no manifest');
  const opening = output[start];
  const closing = opening === '{' ? '}' : ']';
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (let index = start; index < output.length; index++) {
    const character = output[index];
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') quoted = false;
      continue;
    }
    if (character === '"') quoted = true;
    else if (character === opening) depth++;
    else if (character === closing && --depth === 0) return JSON.parse(output.slice(start, index + 1));
  }
  throw new Error('npm pack --json returned an incomplete manifest');
}

const root = process.cwd();
const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const docsManifestPath = 'docs/public/gates/manifest.json';
const docsManifest = JSON.parse(await readFile(join(root, docsManifestPath), 'utf8'));
assert.equal(docsManifest.packageName, manifest.name, 'docs package name differs');
assert.equal(docsManifest.packageVersion, manifest.version, 'docs package version differs');
const publicFiles = new Set([docsManifestPath, 'docs/public/README.md', ...docsManifest.pages.map(page => page.path), ...docsManifest.examples]);
assert.equal(publicFiles.size, 2 + docsManifest.pages.length + docsManifest.examples.length, 'duplicate public file');
for (const path of publicFiles) {
  assert.ok(typeof path === 'string' && !path.startsWith('/') && !path.includes('\\') &&
    !path.split('/').includes('..') && (path === 'docs/public/README.md' || /^(docs\/public\/gates\/|examples\/docs\/)/.test(path)), `unsafe public file: ${path}`);
  assert.ok(manifest.files.includes(path), `public file missing from package allowlist: ${path}`);
}
const logoPath = 'assets/brand/gates-dark.svg';
assert.ok(manifest.files.includes(logoPath), 'README logo missing from package allowlist');
const temp = await mkdtemp(join(tmpdir(), 'irondome-gate-package-'));
try {
  const packedOutput = run('npm', ['pack', '--json', '--pack-destination', temp], { cwd: root });
  const parsed = parseJsonOutput(packedOutput);
  const packed = Array.isArray(parsed) ? parsed[0] : Object.values(parsed)[0];
  assert.ok(packed && typeof packed === 'object');
  const files = packed.files.map(file => file.path);
  const bundledPackages = ['mail-canon', 'tr46', 'punycode'];
  const allow = path => path === 'package.json' || path === 'README.md' || path === 'LICENSE' || path === logoPath ||
    path.startsWith('dist/') || path.startsWith('migrations/') || publicFiles.has(path) ||
    bundledPackages.some(name => path.startsWith(`node_modules/${name}/`));
  assert.ok(files.length > 0);
  assert.ok(files.includes(logoPath), 'README logo missing from tarball');
  const licensed = typeof manifest.license === 'string' && manifest.license !== 'UNLICENSED';
  if (licensed) {
    assert.ok(files.includes('LICENSE'), 'licensed release must include LICENSE');
    assert.ok((await readFile(join(root, 'LICENSE'), 'utf8')).trim().length > 0, 'LICENSE must not be empty');
  }
  assert.ok(files.every(allow), `unexpected tarball files: ${files.filter(path => !allow(path)).join(', ')}`);
  for (const expected of publicFiles) assert.ok(files.includes(expected), `missing public file: ${expected}`);
  for (const forbidden of ['test/', 'src/', 'evidence/', 'vendor/', 'docs/verification', 'artifacts/', 'reports/']) {
    assert.ok(files.every(path => !path.startsWith(forbidden)), `tarball contains ${forbidden}`);
  }
  for (const name of bundledPackages) {
    assert.ok(files.some(path => path.startsWith(`node_modules/${name}/`)), `missing bundled ${name}`);
  }
  for (const expected of ['dist/index.js', 'dist/index.d.ts', 'dist/storage/postgres/identity.js', 'dist/storage/postgres/identity.d.ts',
    'dist/connectors/better-auth/index.js', 'dist/connectors/better-auth/index.d.ts', 'dist/storage/postgres/better-auth.js', 'dist/storage/postgres/better-auth.d.ts',
    'migrations/001_identity.sql', 'migrations/002_lifecycle.sql', 'migrations/003_better_auth.sql',
    'docs/public/gates/manifest.json',
    'dist/connectors/auth0/index.js', 'dist/connectors/auth0/index.d.ts', 'dist/connectors/supabase/index.js', 'dist/connectors/supabase/index.d.ts',
    'dist/core/provider-lifecycle.js', 'dist/core/provider-lifecycle.d.ts',
    'dist/storage/postgres/provider-lifecycle.js', 'dist/storage/postgres/provider-lifecycle.d.ts',
    'migrations/004_provider_operations.sql', 'migrations/005_tenant_policy.sql',
    'dist/storage/postgres/policy-migration.js', 'dist/storage/postgres/policy-migration.d.ts',
    'dist/storage/postgres/online.js', 'dist/storage/postgres/online.d.ts', 'migrations/006_online_policy.sql']) {
    assert.ok(files.includes(expected), `missing ${expected}`);
  }
  for (const path of files.filter(path => path.startsWith('dist/') && path.endsWith('.d.ts'))) {
    const declaration = await readFile(join(root, path), 'utf8');
    assert.ok(!declaration.includes('zod/v4/core'), `${path} leaks zod/v4/core in its public declarations`);
  }

  const tarball = join(temp, packed.filename);
  const consumer = join(temp, 'consumer');
  await mkdir(consumer);
  await writeFile(join(consumer, 'package.json'), JSON.stringify({ name: 'consumer-smoke', private: true, type: 'module' }));
  run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--no-save', '--package-lock=false',
    tarball, 'typescript@7.0.2'], { cwd: consumer });

  const runtime = `import assert from 'node:assert/strict';
import * as root from '${manifest.name}';
import * as postgres from '${manifest.name}/postgres';
import * as authPostgres from '${manifest.name}/better-auth/postgres';
import { createOnlinePostgresGate } from '${manifest.name}/online/postgres';
import { createAuth0Gate } from '${manifest.name}/auth0';
import { createSupabaseGate } from '${manifest.name}/supabase';
import { createProviderLifecycle } from '${manifest.name}/provider-lifecycle';
import { createPostgresProviderOperationStore } from '${manifest.name}/provider-lifecycle/postgres';
import { createPostgresPolicyMigrator } from '${manifest.name}/policy-migration/postgres';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
const require = createRequire(import.meta.url);
const packageRequire = createRequire(require.resolve('${manifest.name}'));
const packageRoot = join(dirname(require.resolve('${manifest.name}')), '..');
const installedManifest = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'));
assert.equal(installedManifest.name, ${JSON.stringify(manifest.name)});
assert.equal(installedManifest.license, ${JSON.stringify(manifest.license)});
${licensed ? `assert.equal(readFileSync(join(packageRoot, 'LICENSE'), 'utf8'), ${JSON.stringify(await readFile(join(root, 'LICENSE'), 'utf8'))});` : ''}
assert.equal(typeof createAuth0Gate, 'function');
assert.equal(typeof createSupabaseGate, 'function');
assert.equal(typeof createProviderLifecycle, 'function');
assert.equal(typeof createPostgresProviderOperationStore, 'function');
assert.equal(typeof createPostgresPolicyMigrator, 'function');
assert.equal(typeof createOnlinePostgresGate, 'function');
assert.equal(typeof root.createGate, 'function');
assert.equal(typeof root.createLifecycleGate, 'function');
assert.equal(typeof root.applyBackfill, 'function');
const customPolicy = root.createEmailPolicy({ 'company.test': { lowercase: true, stripPlusTag: true } });
assert.equal(customPolicy.prepareEmail('Name+tag@company.test').canonical, 'name@company.test');
assert.equal(customPolicy.prepareEmail('Name+tag@other.test').canonical, 'Name+tag@other.test');
assert.notEqual(customPolicy.version, root.POLICY_VERSION);
assert.equal(root.DEFAULT_EMAIL_POLICY.prepareEmail('Name+tag@company.test').canonical, 'Name+tag@company.test');
assert.equal(typeof postgres.createPostgresIdentityRegistry, 'function');
assert.equal(typeof authPostgres.createPostgresBetterAuthChangeStore, 'function');
assert.ok(require.resolve('${manifest.name}/migrations/001_identity.sql'));
assert.ok(require.resolve('${manifest.name}/migrations/002_lifecycle.sql'));
assert.ok(require.resolve('${manifest.name}/migrations/003_better_auth.sql'));
assert.ok(require.resolve('${manifest.name}/migrations/004_provider_operations.sql'));
assert.ok(require.resolve('${manifest.name}/migrations/005_tenant_policy.sql'));
assert.ok(require.resolve('${manifest.name}/migrations/006_online_policy.sql'));
assert.throws(() => require.resolve('better-auth'), { code: 'MODULE_NOT_FOUND' });
for (const [entry, expected] of [['mail-canon', '0.2.0'], ['tr46', '5.1.1'], ['punycode/', '2.3.1']]) {
  const resolved = packageRequire.resolve(entry);
  const manifestPath = join(dirname(resolved), 'package.json');
  assert.equal(JSON.parse(readFileSync(manifestPath, 'utf8')).version, expected, entry);
}
`;
  await writeFile(join(consumer, 'smoke.mjs'), runtime);
  run(process.execPath, ['smoke.mjs'], { cwd: consumer });

  const declarations = `import { createGate, createLifecycleGate, applyBackfill, dryRunBackfill, type BackfillRow } from '${manifest.name}';
import { createPostgresIdentityRegistry } from '${manifest.name}/postgres';
import { createPostgresBetterAuthChangeStore, type BetterAuthChangeStore } from '${manifest.name}/better-auth/postgres';
import { createAuth0Gate } from '${manifest.name}/auth0';
import { createSupabaseGate } from '${manifest.name}/supabase';
import { createProviderLifecycle } from '${manifest.name}/provider-lifecycle';
import { createPostgresProviderOperationStore } from '${manifest.name}/provider-lifecycle/postgres';
import { createPostgresPolicyMigrator } from '${manifest.name}/policy-migration/postgres';
import { createOnlinePostgresGate } from '${manifest.name}/online/postgres';
declare const row: BackfillRow;
declare const pool: Parameters<typeof createPostgresIdentityRegistry>[0];
const registry = createPostgresIdentityRegistry(pool, { schema: 'trusted_auth' });
const store: BetterAuthChangeStore = createPostgresBetterAuthChangeStore(pool, { schema: 'trusted_auth' });
createGate({ registry, screening: { async screen() { return { allowed: true, reason: 'not_listed' as const }; } } });
const engine = createLifecycleGate({ registry, canonicalRules: { 'company.test': { lowercase: true, stripPlusTag: true, stripDots: true } },
  screening: { async screen() { return { allowed: true, reason: 'not_listed' as const }; } } });
void dryRunBackfill([row], engine);
const operations = createPostgresProviderOperationStore(pool, { schema: 'trusted_auth' });
const lifecycle = createProviderLifecycle({ tenantId: 'smoke', namespace: 'fixed-project', engine, operations,
  async getUserById() { return null; }, async deleteUser(_id, _generation, _signal) {},
});
const auth0 = createAuth0Gate({ tenantId: 'smoke', engine, trustedConnections: ['con_smoke'], lifecycle,
  async getUserById() { return null; },
});
void auth0.onExecutePreUserRegistration({ user: { email: 'person@example.com' } }, { access: { deny() {} } });
void auth0.onExecutePostLogin({ user: { user_id: 'auth0|subject', email: 'person@example.com', email_verified: true },
  connection: { id: 'con_smoke' } }, { access: { deny() {} } });
void auth0.assertActive({ sub: 'auth0|subject' });
const supabase = createSupabaseGate({ tenantId: 'smoke', gate: engine, lifecycle,
  webhookSecret: 'whsec_c21va2U=', async getUserById() { return null; }, async getUserForAccessToken() { return null; },
});
void supabase.beforeUserCreated(new Request('https://hooks.example.test/before'));
void supabase.customAccessToken(new Request('https://hooks.example.test/token'));
void supabase.assertActive('verified-by-provider');
void lifecycle.beginEmailChange({ userId: 'subject', email: 'next@example.com' });
void lifecycle.completeEmailChange({ userId: 'subject', operationId: 'captured-operation-id' });
void lifecycle.deleteAccount({ userId: 'subject' });
void lifecycle.resumeDeletion({ userId: 'subject' });
void operations.deleteExpiredChanges();
const migrator = createPostgresPolicyMigrator(pool, { schema: 'trusted_auth', maxRows: 1000, emailPolicy: engine.emailPolicy });
void migrator.auditTenant({ tenantId: 'smoke' });
void migrator.migrateTenant({ tenantId: 'smoke', expectedDigest: '0'.repeat(64) });
const onlineEngine = createOnlinePostgresGate(pool, { schema: 'trusted_auth', screening: {
  async screen() { return { allowed: true, reason: 'not_listed' as const }; },
} });
const onlineOperations = createPostgresProviderOperationStore(pool, { schema: 'trusted_auth' });
const onlineLifecycle = createProviderLifecycle({ tenantId: 'smoke', namespace: 'fixed-project', engine: onlineEngine,
  operations: onlineOperations, async getUserById() { return null; }, async deleteUser(_id, _generation, _signal) {},
});
const onlineAuth0 = createAuth0Gate({ tenantId: 'smoke', engine: onlineEngine, trustedConnections: ['con_online'],
  lifecycle: onlineLifecycle, async getUserById() { return null; },
});
const onlineSupabase = createSupabaseGate({ tenantId: 'smoke', gate: onlineEngine, lifecycle: onlineLifecycle,
  webhookSecret: 'whsec_c21va2U=', async getUserById() { return null; }, async getUserForAccessToken() { return null; },
});
void onlineAuth0;
void onlineSupabase;
void applyBackfill;
void row;
void store;
`;
  await writeFile(join(consumer, 'smoke.ts'), declarations);
  run(process.execPath, ['node_modules/typescript/bin/tsc', '--noEmit', '--strict', '--skipLibCheck',
    '--target', 'ES2022', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', 'smoke.ts'], { cwd: consumer });

  run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--no-save', '--package-lock=false',
    tarball, 'better-auth@1.7.7', 'typescript@7.0.2'], { cwd: consumer });
  await writeFile(join(consumer, 'auth-smoke.mjs'), `import assert from 'node:assert/strict';
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { createBetterAuthGate } from '${manifest.name}/better-auth';
assert.equal(typeof createBetterAuthGate, 'function');
const gate = createBetterAuthGate({ tenantId: 'smoke', engine: {
  async screenSignup() {}, async claimVerified() {}, async assertActive() {},
}, async sendVerificationEmail() {} });
const auth = betterAuth({ baseURL: 'https://auth.example.test', secret: 'local-smoke-secret-12345678901234567890',
  database: memoryAdapter({ user: [], account: [], session: [], verification: [] }), ...gate.authOptions });
const bound = gate.bind(auth);
assert.equal(typeof bound.handler, 'function');
assert.equal(typeof bound.getActiveSession, 'function');
`);
  run(process.execPath, ['auth-smoke.mjs'], { cwd: consumer });
  await writeFile(join(consumer, 'auth-smoke.ts'), `import { betterAuth, type BetterAuthOptions } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { createBetterAuthGate } from '${manifest.name}/better-auth';
import { createGate } from '${manifest.name}';
import { createPostgresIdentityRegistry, type PgPool } from '${manifest.name}/postgres';
import { createOnlinePostgresGate } from '${manifest.name}/online/postgres';
import { createPostgresProviderOperationStore } from '${manifest.name}/provider-lifecycle/postgres';
import { createProviderLifecycle } from '${manifest.name}/provider-lifecycle';
import { createAuth0Gate } from '${manifest.name}/auth0';
import { createSupabaseGate } from '${manifest.name}/supabase';

const registry = createPostgresIdentityRegistry({} as PgPool);
const core = createGate({ registry, screening: { async screen() { return { allowed: true, reason: 'not_listed' as const }; } } });
const integration = createBetterAuthGate({ tenantId: 'smoke', engine: core, async sendVerificationEmail() {} });
const options: BetterAuthOptions = {
  baseURL: 'https://auth.example.test',
  secret: 'local-smoke-secret-12345678901234567890',
  database: memoryAdapter({ user: [], account: [], session: [], verification: [] }),
  ...integration.authOptions,
};
const auth = betterAuth(options);
const bound = integration.bind(auth);
void bound.handler;
void bound.getActiveSession;
void auth.api.signUpEmail({ body: { email: 'person@example.com', password: 'local-password-123456', name: 'Smoke' } });
void auth.api.changeEmail({ body: { newEmail: 'next@example.com' } });
void auth.api.verifyEmail({ query: { token: 'signed-provider-token' } });
const onlineEngine = createOnlinePostgresGate({} as PgPool, { schema: 'trusted_auth', screening: {
  async screen() { return { allowed: true, reason: 'not_listed' as const }; },
} });
const operations = createPostgresProviderOperationStore({} as PgPool, { schema: 'trusted_auth' });
const lifecycle = createProviderLifecycle({ tenantId: 'smoke', namespace: 'fixed-project', engine: onlineEngine, operations,
  async getUserById() { return null; }, async deleteUser(_id, _generation, _signal) {},
});
createAuth0Gate({ tenantId: 'smoke', engine: onlineEngine, trustedConnections: ['con_online'], lifecycle,
  async getUserById() { return null; },
});
createSupabaseGate({ tenantId: 'smoke', gate: onlineEngine, lifecycle, webhookSecret: 'whsec_c21va2U=',
  async getUserById() { return null; }, async getUserForAccessToken() { return null; },
});
const onlineAuth = createBetterAuthGate({ tenantId: 'smoke', engine: onlineEngine, async sendVerificationEmail() {} });
void onlineAuth;
`);
  run(process.execPath, ['node_modules/typescript/bin/tsc', '--noEmit', '--strict', '--skipLibCheck',
    '--target', 'ES2022', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', 'auth-smoke.ts'], { cwd: consumer });

  const hash = createHash('sha256').update(await readFile(tarball)).digest('hex');
  process.stdout.write(`Package smoke passed: ${manifest.name}@${manifest.version}, ${files.length} packed files; SHA-256 ${hash}; core-only provider imports and Better Auth runtime, pinned consumer closure, typed auth APIs, and all migrations resolved.\n`);
} finally {
  await rm(temp, { recursive: true, force: true });
}

