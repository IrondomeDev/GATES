# Prepare PostgreSQL

GATES uses your PostgreSQL database through a `pg.Pool`-compatible pool. The recommended engine is `createOnlinePostgresGate`; it retains verified delivery addresses and supports later canonical-policy changes without a planned authentication pause.

Use a dedicated trusted schema. The examples use `trusted_auth`; Supabase deployments must keep this schema outside the Data API's exposed schemas and separate from Supabase's managed `auth` schema.

Create the schema as its trusted migration owner before running the files:

```sql
CREATE SCHEMA trusted_auth AUTHORIZATION gate_migrator;
```

`gate_migrator` is an existing deployment role chosen by your administrator, not a role created by GATES. Do not recreate a schema that already holds data.

## Apply the migrations once

Use a migration role that owns the schema and your application's tracked migration runner. Apply each numbered file once, in order, in a transaction. Do not run migrations from request handlers.

| Integration | Required GATES migrations |
| --- | --- |
| Better Auth | 001, 002, 003, 005, 006 |
| Auth0 or Supabase with lifecycle operations | 001, 002, 004, 005, 006 |

The package exports all six SQL files. Resolve them rather than depending on a package manager's directory layout:

```js
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const path = fileURLToPath(
  import.meta.resolve('@irondome-dev/gate/migrations/001_identity.sql'),
);
const sql = await readFile(path, 'utf8');
```

Supply the SQL to your migration runner. On the same checked-out connection, set the trusted schema for the transaction before executing a file:

```sql
BEGIN;
SET LOCAL search_path = trusted_auth, pg_catalog;
SET LOCAL lock_timeout = '50ms';
-- execute one migration file here
COMMIT;
```

The snippet describes the transaction boundary; it is not a substitute for migration tracking. On failure, roll back before returning the connection to its pool. Migration 006 installs triggers and can briefly conflict with writes. Retry its entire transaction after lock contention instead of leaving it queued indefinitely. Test upgrades on a representative copy first.

Better Auth's own tables are additional. Run Better Auth's migration helper with the final integration options so its private delivery-email field exists. Its pool and migration runner must use the intended schema. GATES qualifies its own table names explicitly; it does not configure Better Auth's table placement for you.

## Restrict access

Separate the migration owner from the application runtime role. Assuming `gate_server` already exists, the owner must grant runtime access **after all tables have been created**, including Better Auth's own migration step. `ON ALL TABLES` only covers tables that exist when the statement runs. Repeat these grants after later migrations create tables:

```sql
REVOKE ALL ON SCHEMA trusted_auth FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA trusted_auth FROM PUBLIC;
GRANT USAGE ON SCHEMA trusted_auth TO gate_server;
GRANT SELECT, INSERT, UPDATE, DELETE
  ON ALL TABLES IN SCHEMA trusted_auth TO gate_server;
```

On Supabase, also revoke schema and table privileges from `anon` and `authenticated`. Do not run those role names against a database where they do not exist. Review default privileges for the migration role so future migrations do not reintroduce browser access.

GATES migrations do not enable RLS. Isolation depends on private schemas and restricted grants. Application tables exposed to browsers still need their own authorization and RLS policies. A JWT-only policy does not automatically consult GATES revocation.

Verify effective privileges using the actual runtime and browser roles. A successful administrator query is not evidence that browser access is blocked. PostgreSQL's [schema documentation](https://www.postgresql.org/docs/current/ddl-schemas.html) explains why every role with `CREATE` in a search-path schema is trusted.

## Bound database work

Use finite connection, statement, query and lock deadlines. For example:

```ts
import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  options: '-c search_path=trusted_auth,pg_catalog',
  max: 10,
  connectionTimeoutMillis: 2_000,
  statement_timeout: 5_000,
  query_timeout: 6_000,
  lock_timeout: 2_000,
});
```

These are starting values, not service-level guarantees. Match them to your provider deadlines and measured workload. The online engine also sets transaction-local statement and lock timeouts; see [configuration](reference.md#online-postgresql-options). Pass a pool, not a client already participating in another transaction. Lifecycle operations can hold a checked-out connection while an engine operation acquires another. A single-connection pool is not sufficient; reserve headroom for concurrent operations and measure queueing under load.

Use the same schema and stable server-selected tenant ID for the engine and adapter stores. Initialize the engine at startup with `await engine.getEmailPolicy(tenantId)` to surface missing tables or policy mismatches before accepting traffic.

Continue with your [provider quickstart](index.md#start-with-your-provider). Existing users require the separate [migration procedure](migration.md).
