import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";
import { createPostgresIdentityRegistry, type PgPool } from "../src/storage/postgres/identity.js";

const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;

/** Optional REAL PostgreSQL test; not a SQL emulator and not a hidden network call. */
test("real PostgreSQL: atomic ownership, races, rollback, tenant scope, cleanup", {
  skip: databaseUrl ? false : "GATE_TEST_POSTGRES_URL is unset; no real PostgreSQL verification performed",
  timeout: 30_000,
}, async (t) => {
  const url = new URL(databaseUrl!);
  assert.ok(["localhost", "127.0.0.1", "[::1]"].includes(url.hostname), "Only an explicitly supplied local disposable PostgreSQL is permitted");
  assert.ok(["postgres:", "postgresql:"].includes(url.protocol), "Expected PostgreSQL URL");
  // Dynamic by name: pg is the host application's dependency, not engine bloat.
  const driverName = "pg";
  const driver = await import(driverName) as { Pool: new (options: Record<string, unknown>) => PgPool & { end(): Promise<void> } };
  const schema = `gate_test_${process.pid}_${Date.now()}`;
  const options = {
    connectionString: databaseUrl,
    connectionTimeoutMillis: 2_000,
    statement_timeout: 5_000,
    query_timeout: 6_000,
    lock_timeout: 3_000,
    max: 16,
  };
  const admin = new driver.Pool(options);
  let pool: (PgPool & { end(): Promise<void> }) | undefined;
  let created = false;
  t.after(async () => {
    await pool?.end();
    try {
      if (created) await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    } finally {
      await admin.end();
    }
  });
  await admin.query(`CREATE SCHEMA ${schema}`);
  created = true;
  pool = new driver.Pool({ ...options, options: `-c search_path=${schema}` });
  await pool.query(await readFile(resolve("migrations/001_identity.sql"), "utf8"));
  await pool.query(await readFile(resolve("migrations/002_lifecycle.sql"), "utf8"));
  await pool.query(await readFile(resolve("migrations/005_tenant_policy.sql"), "utf8"));
  const registry = createPostgresIdentityRegistry(pool, { schema });
  const base = { tenantId: "tenant-a", userId: "user-a", canonical: "same@example.com", policyVersion: "v1" };

  await t.test("32 concurrent different users produce exactly one canonical owner", async () => {
    const outcomes = await Promise.all(Array.from({ length: 32 }, (_, index) => registry.claim({ ...base, userId: `race-${index}` })));
    assert.equal(outcomes.filter((value) => value === "claimed").length, 1);
    assert.equal(outcomes.filter((value) => value === "conflict").length, 31);
    const result = await pool!.query("SELECT count(*)::int AS total FROM irondome_gate_identity WHERE tenant_id = $1 AND canonical_email = $2", [base.tenantId, base.canonical]);
    assert.equal(result.rows[0]?.total, 1);
  });

  await t.test("32 concurrent same-user retries are idempotent", async () => {
    const input = { ...base, userId: "retry", canonical: "retry@example.com" };
    const outcomes = await Promise.all(Array.from({ length: 32 }, () => registry.claim(input)));
    assert.equal(outcomes.filter((value) => value === "claimed").length, 1);
    assert.equal(outcomes.filter((value) => value === "already-owned").length, 31);
  });

  await t.test("canonical uniqueness and tenant policy fences are independent", async () => {
    assert.equal(await registry.claim({ ...base, userId: "different-owner" }), "conflict");
    assert.equal(await registry.claim({ ...base, userId: "policy-bypass", policyVersion: "v2" }), "conflict");
    assert.equal(await registry.claim({ ...base, tenantId: "tenant-b" }), "claimed");
    assert.equal(await registry.owns({ ...base, tenantId: "tenant-b" }), true);
    assert.equal(await registry.owns(base), false);
  });

  await t.test("tenant policy fence rejects a second canonicalization policy", async () => {
    const first = { ...base, tenantId: "tenant-policy", canonical: "policy-one@example.com", policyVersion: "policy-v1" };
    assert.equal(await registry.claim(first), "claimed");
    assert.equal(await registry.claim({ ...first, userId: "other-policy", canonical: "policy-two@example.com", policyVersion: "policy-v2" }), "policy-mismatch");
  });

  await t.test("email changes and stale callbacks cannot replace the old claim", async () => {
    const old = { ...base, userId: "changing-user", canonical: "old@example.com" };
    assert.equal(await registry.claim(old), "claimed");
    assert.equal(await registry.claim({ ...old, canonical: base.canonical }), "conflict");
    assert.equal(await registry.owns(old), true);
    assert.equal(await registry.owns({ ...old, canonical: base.canonical }), false);
    assert.equal(await registry.claim({ ...old, canonical: "new@example.com" }), "conflict");
    assert.equal(await registry.owns(old), true);
    assert.equal(await registry.owns({ ...old, canonical: "new@example.com" }), false);
    assert.equal(await registry.claim({ ...old, canonical: "stale@example.com" }), "conflict");
    assert.equal(await registry.owns(old), true);
  });

  await t.test("concurrent initial different emails for one user cannot replace the winner", async () => {
    const outcomes = await Promise.all(["a", "b", "c", "d"].map((part) => registry.claim({ ...base, userId: "changing-race", canonical: `change-${part}@example.com` })));
    assert.equal(outcomes.filter((outcome) => outcome === "claimed").length, 1);
    assert.equal(outcomes.filter((outcome) => outcome === "conflict").length, 3);
    const result = await pool!.query("SELECT count(*)::int AS total FROM irondome_gate_identity WHERE tenant_id = $1 AND user_id = $2", [base.tenantId, "changing-race"]);
    assert.equal(result.rows[0]?.total, 1);
  });

  await t.test("quotes/injection strings are data; cleanup is scoped and repeatable", async () => {
    const input = { ...base, userId: "'; DROP TABLE irondome_gate_identity; --", canonical: "quote'person@example.com" };
    assert.equal(await registry.claim(input), "claimed");
    assert.equal(await registry.owns(input), true);
    await registry.releaseUser({ ...input, tenantId: "wrong-tenant" });
    assert.equal(await registry.owns(input), true);
    await registry.releaseUser(input);
    await registry.releaseUser(input);
    assert.equal(await registry.owns(input), false);
    assert.equal(await registry.claim({ ...input, userId: "new-owner" }), "claimed");
  });

  await t.test("real lock timeout rolls back, creates no owner, and permits a safe retry", async () => {
    const input = { ...base, userId: "timeout-user", canonical: "timeout@example.com" };
    const blocker = await pool!.connect();
    const timedPool = new driver.Pool({ ...options, lock_timeout: 75, statement_timeout: 500, options: `-c search_path=${schema}` });
    const timedRegistry = createPostgresIdentityRegistry(timedPool, { schema });
    let blocking = false;
    try {
      await blocker.query("BEGIN");
      blocking = true;
      await blocker.query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", [JSON.stringify(["irondome-gate", input.tenantId, input.userId])]);
      await assert.rejects(timedRegistry.claim(input), (error: unknown) => {
        return typeof error === "object" && error !== null && "code" in error && ["55P03", "57014"].includes(String(error.code));
      });
      assert.equal(await registry.owns(input), false);
      await blocker.query("ROLLBACK");
      blocking = false;
      assert.equal(await timedRegistry.claim(input), "claimed");
    } finally {
      try { if (blocking) await blocker.query("ROLLBACK"); }
      finally { blocker.release(); await timedPool.end(); }
    }
  });

  await t.test("a real SQL error after insert rolls back the row and releases the lock", async () => {
    const input = { ...base, userId: "rollback-user", canonical: "rollback@example.com" };
    const failingPool: PgPool = {
      query: (sql, values) => pool!.query(sql, values),
      async connect() {
        const client = await pool!.connect();
        return {
          async query(sql, values) {
            const result = await client.query(sql, values);
            if (sql.startsWith("INSERT INTO ")) await client.query("SELECT 1 / 0");
            return result;
          },
          release: (error) => client.release(error),
        };
      },
    };
    await assert.rejects(createPostgresIdentityRegistry(failingPool, { schema }).claim(input), (error: unknown) => {
      return typeof error === "object" && error !== null && "code" in error && error.code === "22012";
    });
    assert.equal(await registry.owns(input), false);
    assert.equal(await registry.claim(input), "claimed");
  });

  await t.test("lost COMMIT acknowledgment is fail-closed and reconciles idempotently", async () => {
    const input = { ...base, userId: "uncertain-commit", canonical: "uncertain@example.com" };
    const acknowledgmentLost = new Error("Injected lost commit acknowledgment");
    const failingPool: PgPool = {
      query: (sql, values) => pool!.query(sql, values),
      async connect() {
        const client = await pool!.connect();
        return {
          async query(sql, values) {
            const result = await client.query(sql, values);
            if (sql === "COMMIT") throw acknowledgmentLost;
            return result;
          },
          release: (error) => client.release(error),
        };
      },
    };
    await assert.rejects(createPostgresIdentityRegistry(failingPool, { schema }).claim(input), (error) => error === acknowledgmentLost);
    assert.equal(await registry.owns(input), true);
    assert.equal(await registry.claim(input), "already-owned");
  });
});
