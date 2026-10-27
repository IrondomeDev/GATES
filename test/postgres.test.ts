import assert from "node:assert/strict";
import test from "node:test";
import { createPostgresIdentityRegistry, type PgClient, type PgPool, type PgQueryResult } from "../src/storage/postgres/identity.js";

const empty = (): PgQueryResult => ({ rows: [], rowCount: 0 });
const row = (value: Record<string, unknown>): PgQueryResult => ({ rows: [value], rowCount: 1 });
type Step = { sql: RegExp; result?: PgQueryResult; error?: unknown };
function harness(steps: Step[]) {
  const calls: { sql: string; values: unknown[] | undefined }[] = [];
  const released: (Error | boolean | undefined)[] = [];
  const client: PgClient = {
    async query(sql, values) {
      // Optional schema-capability discovery is independent of the scripted
      // identity operation; real PostgreSQL coverage verifies its fencing path.
      if (sql.includes('pg_catalog.to_regclass(')) return row({ enabled: false });
      calls.push({ sql, values });
      const step = steps.shift();
      assert.ok(step, `Unexpected query: ${sql}`);
      assert.match(sql, step.sql);
      if (step.error !== undefined) throw step.error;
      return step.result ?? empty();
    },
    release(error) { released.push(error); },
  };
  const pool: PgPool = { connect: async () => client, query: client.query };
  return { registry: createPostgresIdentityRegistry(pool), pool, calls, released, remaining: () => steps.length };
}
const start: Step[] = [{ sql: /^BEGIN ISOLATION LEVEL READ COMMITTED$/ }, { sql: /pg_advisory_xact_lock/ }];
const claim = { tenantId: "tenant-a", userId: "user-a", canonical: "person@example.com", policyVersion: "policy-v1" };

test("postgres: claim uses a bound unique insert inside a released transaction", async () => {
  const h = harness([...start, { sql: /^SELECT canonical_email/ }, { sql: /^INSERT/, result: row({ user_id: claim.userId }) }, { sql: /^COMMIT$/ }]);
  assert.equal(await h.registry.claim(claim), "claimed");
  assert.deepEqual(h.calls[3]?.values, [claim.tenantId, claim.userId, claim.canonical, claim.policyVersion]);
  assert.match(h.calls[3]!.sql, /ON CONFLICT \(tenant_id, canonical_email\) DO NOTHING/);
  assert.deepEqual(h.released, [undefined]);
  assert.equal(h.remaining(), 0);
});

test("postgres: same-user retry does not reinsert or change original policy metadata", async () => {
  const h = harness([...start, { sql: /^SELECT canonical_email/, result: row({ canonical_email: claim.canonical }) }, { sql: /^COMMIT$/ }]);
  assert.equal(await h.registry.claim({ ...claim, policyVersion: "v2" }), "already-owned");
  assert.equal(h.calls.length, 4);
  assert.deepEqual(h.released, [undefined]);
});

test("postgres: another user's canonical claim is a conflict, not an ownership transfer", async () => {
  const h = harness([...start, { sql: /^SELECT canonical_email/ }, { sql: /^INSERT/ }, { sql: /^COMMIT$/ }]);
  assert.equal(await h.registry.claim(claim), "conflict");
  assert.ok(h.calls.every(({ sql }) => !sql.startsWith("UPDATE") && !sql.startsWith("DELETE")));
});

test("postgres: different canonical for an existing user cannot replace ownership", async () => {
  const h = harness([...start, { sql: /^SELECT canonical_email/, result: row({ canonical_email: "old@example.com" }) }, { sql: /^COMMIT$/ }]);
  assert.equal(await h.registry.claim(claim), "conflict");
  assert.ok(h.calls.every(({ sql }) => !/^(UPDATE|DELETE|INSERT)/.test(sql)));
  assert.deepEqual(h.released, [undefined]);
});

test("postgres: stale verification callback cannot revert current ownership", async () => {
  const h = harness([...start, { sql: /^SELECT canonical_email/, result: row({ canonical_email: "current@example.com" }) }, { sql: /^COMMIT$/ }]);
  assert.equal(await h.registry.claim({ ...claim, canonical: "stale@example.com" }), "conflict");
  assert.equal(h.calls.length, 4);
  assert.deepEqual(h.released, [undefined]);
});

test("postgres: unrelated constraint errors are not reported as canonical conflicts", async () => {
  const error = Object.assign(new Error("database problem"), { code: "23505", constraint: "unexpected_constraint" });
  const h = harness([...start, { sql: /^SELECT canonical_email/ }, { sql: /^INSERT/, error }, { sql: /^ROLLBACK$/ }]);
  await assert.rejects(h.registry.claim(claim), (e) => e === error);
  assert.deepEqual(h.released, [undefined]);
});

test("postgres: timeout fails closed and rolls back", async () => {
  const error = Object.assign(new Error("statement timeout"), { code: "57014" });
  const h = harness([{ sql: /^BEGIN/ }, { sql: /pg_advisory_xact_lock/, error }, { sql: /^ROLLBACK$/ }]);
  await assert.rejects(h.registry.claim(claim), (e) => e === error);
  assert.deepEqual(h.released, [undefined]);
});

test("postgres: failed rollback destroys the pooled connection", async () => {
  const original = new Error("connection lost");
  const rollback = new Error("rollback impossible");
  const h = harness([...start, { sql: /^SELECT canonical_email/, error: original }, { sql: /^ROLLBACK$/, error: rollback }]);
  await assert.rejects(h.registry.claim(claim), (e) => e === original);
  assert.deepEqual(h.released, [rollback]);
});

test("postgres: uncertain COMMIT is an error, never an assumed allow", async () => {
  const error = new Error("commit connection lost");
  const h = harness([...start, { sql: /^SELECT canonical_email/ }, { sql: /^INSERT/, result: row({ user_id: claim.userId }) }, { sql: /^COMMIT$/, error }, { sql: /^ROLLBACK$/ }]);
  await assert.rejects(h.registry.claim(claim), (e) => e === error);
  assert.deepEqual(h.released, [undefined]);
});

test("postgres: SQL-like identifiers and addresses stay in parameters", async () => {
  const injected = { ...claim, tenantId: "x'; DROP TABLE users; --", userId: "u' OR 1=1 --", canonical: "'quote@example.com" };
  const h = harness([...start, { sql: /^SELECT canonical_email/ }, { sql: /^INSERT/, result: row({ user_id: injected.userId }) }, { sql: /^COMMIT$/ }]);
  assert.equal(await h.registry.claim(injected), "claimed");
  for (const call of h.calls) {
    assert.ok(!call.sql.includes(injected.tenantId));
    assert.ok(!call.sql.includes(injected.userId));
    assert.ok(!call.sql.includes(injected.canonical));
  }
  assert.deepEqual(h.calls[1]?.values, [JSON.stringify(["irondome-gate", injected.tenantId, injected.userId])]);
});

test("postgres: ownership lookup includes tenant, user, and canonical", async () => {
  const h = harness([{ sql: /WHERE owner.tenant_id = \$1 AND owner.user_id = \$2 AND owner.canonical_email = \$3/, result: row({ owned: 1 }) }]);
  assert.equal(await h.registry.owns(claim), true);
  assert.deepEqual(h.calls[0]?.values, [claim.tenantId, claim.userId, claim.canonical]);
  assert.equal(h.released.length, 0);
});

test("postgres: missing ownership fails closed", async () => {
  const h = harness([{ sql: /^SELECT 1/ }]);
  assert.equal(await h.registry.owns(claim), false);
});

test("postgres: release is tenant scoped and serialized with claims", async () => {
  const h = harness([...start, { sql: /^WITH marked AS/, result: row({ inserted: true }) }, { sql: /^COMMIT$/ }]);
  await h.registry.releaseUser(claim);
  assert.deepEqual(h.calls[2]?.values, [claim.tenantId, claim.userId]);
  assert.deepEqual(h.released, [undefined]);
});

test("postgres: malformed input rejects without acquiring a connection", async () => {
  const h = harness([]);
  for (const bad of [{ ...claim, tenantId: "" }, { ...claim, canonical: "bad\0address" }, { ...claim, policyVersion: "x".repeat(129) }, { ...claim, userId: "\uD800" }, { ...claim, tenantId: "é".repeat(257) }]) {
    await assert.rejects(h.registry.claim(bad), /Invalid identity registry input/);
  }
  assert.equal(h.calls.length, 0);
  assert.equal(h.released.length, 0);
});

test("postgres: caller mutation during connect cannot change validated lock/claim identity", async () => {
  const h = harness([...start, { sql: /^SELECT canonical_email/ }, { sql: /^INSERT/, result: row({ user_id: claim.userId }) }, { sql: /^COMMIT$/ }]);
  const originalConnect = h.pool.connect;
  let resume!: () => void;
  const pendingConnect = new Promise<void>((resolve) => { resume = resolve; });
  h.pool.connect = async () => { await pendingConnect; return originalConnect(); };
  const mutable = { ...claim };
  const result = h.registry.claim(mutable);
  mutable.tenantId = "changed-tenant";
  mutable.userId = "changed-user";
  mutable.canonical = "changed@example.com";
  mutable.policyVersion = "changed-policy";
  resume();
  assert.equal(await result, "claimed");
  assert.deepEqual(h.calls[1]?.values, [JSON.stringify(["irondome-gate", claim.tenantId, claim.userId])]);
  assert.deepEqual(h.calls[2]?.values, [claim.tenantId, claim.userId]);
  assert.deepEqual(h.calls[3]?.values, [claim.tenantId, claim.userId, claim.canonical, claim.policyVersion]);
});

test('postgres: rejects ambiguous schema identifiers and invalid revisions before I/O', async () => {
  const h = harness([]);
  for (const schema of ['', 'a.b', 'x"; DROP SCHEMA public; --', 'x'.repeat(64), '\ud800']) {
    assert.throws(() => createPostgresIdentityRegistry(h.pool, { schema }), /Invalid identity registry schema/);
  }
  for (const expectedRevision of ['0', '-1', '01', '1.0', '9007199254740993x', '9223372036854775807']) {
    await assert.rejects(h.registry.replaceVerified({ ...claim, expectedRevision }), /Invalid identity revision/);
  }
  assert.equal(h.calls.length, 0);
});
