# Migrate existing users and email policies

There are two different migrations:

1. **Adopt GATES in an application that already has users.** Establish verified ownership without silently merging existing accounts.
2. **Change the canonical policy of an existing GATES tenant.** Build new keys while the active policy continues serving requests.

The online policy worker performs the second operation. It does not discover your provider's entire user population or turn a partially exported account list into a complete backfill.

## Adopt GATES in an existing application

Before enabling protected-route enforcement, decide which existing users are eligible and how to resolve collisions. Otherwise legitimate users without claims will be denied.

### Audit a complete, private export

Export current provider-verified users with a stable tenant ID, never-reused user ID and exact verified delivery address. Exclude pending/unverified users from claims. An old normalized login string cannot prove the original spelling.

Use the same policy you intend to deploy:

```ts
import { createEmailPolicy, dryRunBackfill } from 'irondome-gates';

const policy = createEmailPolicy();
const report = dryRunBackfill(providerRows, { emailPolicy: policy });
if (!report.ready) throw new Error('Resolve the migration blockers first');
```

`providerRows` is the restricted export described above, using the `BackfillRow` shape in the package's TypeScript declarations. The audit performs no network calls or writes. Its reports contain source-row indexes, not email addresses; keep the source export separately access-controlled.

Resolve duplicate user rows, invalid addresses and canonical collisions explicitly. Do not pick the oldest account automatically, delete another account or turn a canonical match into account linking. A clean audit proves only that the supplied snapshot has no detected blockers.

### Coordinate the initial cutover

The current supervised `applyBackfill` utility is a fixed-policy adoption path. Coordinate signup verification, email changes and deletion for the cutover, re-export under that boundary, and re-audit. It is not a zero-downtime first-installation importer.

Use `createLifecycleGate` with `createPostgresIdentityRegistry` and the same canonical rules for this initial controlled operation. Its required migrations are 001, 002 and 005, plus the provider's store migrations. The apply utility accepts at most 100,000 rows, validates the whole input before writes, and requires a `revalidate` callback that checks fresh provider state for every row.

```ts
import { applyBackfill } from 'irondome-gates';

const result = await applyBackfill(fixedPolicyEngine, providerRows, {
  concurrency: 4,
  async revalidate(row) {
    const current = await trustedProvider.readCurrentUser(row.tenantId, row.userId);
    return current !== null &&
      current.tenantId === row.tenantId &&
      current.userId === row.userId &&
      current.emailVerified === true &&
      current.exactDeliveryEmail === row.email;
  },
});
if (!result.complete) throw new Error('Backfill requires supervised recovery');
```

This is an operator integration example, not a standalone script: the application must supply the fixed-policy engine, complete export and trusted provider reader. Verification flags copied from client metadata are not proof.

Applying re-screens eligible addresses through IronDome and can consume API quota. Each row is committed independently. On failure, completed rows remain claimed; an uncertain acknowledgement may also mean a write committed. Resume only from a current, reviewed snapshot and reconcile the same authorized operation. Do not undo unrelated claims.

For larger populations or applications that cannot coordinate a cutover, design and qualify a provider-specific adoption job before enabling enforcement. Do not split an unaudited export into arbitrary chunks and assume cross-chunk collisions or concurrent changes are covered.

### Switch to the recommended online engine

Install migration 006 and deploy `createOnlinePostgresGate` with the current policy to every reader and writer, including provider bridges and jobs. It initially bridges the existing ownership tables. Confirm complete expected ownership against fresh provider state, then enable live checks on protected operations and resume the coordinated application flow.

The online engine needs verified delivery sources to later reverse or change custom rules. Use the provider lookup described below to adopt legacy canonical-only owners. Do not supply guessed originals.

## Change the policy of an existing GATES tenant

First install [database migrations](database.md), deploy the online engine everywhere, and retire old readers and writers. Changing a process configuration alone is not a policy migration. Once an online migration begins, old writers are fenced rather than allowed to omit the target policy.

Start a job from trusted operator code:

```ts
import { createEmailPolicy } from 'irondome-gates';

const job = await engine.migration.begin({
  tenantId,
  targetPolicy: createEmailPolicy({
    'company.example': { lowercase: true, stripPlusTag: true },
  }),
});
if (!job.pendingEpoch) throw new Error('No pending migration epoch');
const epoch = job.pendingEpoch;
```

Here `engine` is your configured online engine and `tenantId` is server-selected. Persist `epoch` with the operator job before starting work. The example domain is hypothetical; use only [mailbox equivalences](email-matching.md) verified for your domain.

Run bounded batches from your existing job runner:

```ts
const progress = await engine.migration.backfill({
  tenantId,
  epoch,
  batchSize: 100,
});
```

Each invocation makes bounded progress. Resume it until the phase is `ready` or `blocked`; do not keep a public HTTP request open for an entire tenant. Defaults are 100 rows and a supported range of 1–1,000, with no total tenant row cap for this policy migration path.

### Supply verified sources for older owners

When earlier records retained only canonical keys, supply a server-side provider lookup during backfill:

```ts
const progress = await engine.migration.backfill({
  tenantId,
  epoch,
  batchSize: 100,
  async resolveLegacyEmail({ userId }) {
    const user = await trustedProvider.getUserById(userId);
    return user ? {
      userId: user.id,
      email: user.email,
      emailVerified: user.emailVerified === true,
    } : null;
  },
});
```

Map the real provider fields and stable subject correctly. Missing, unverified or mismatched sources remain gaps. Provider lookups happen outside the write locks; the engine rechecks the source against current ownership before accepting it.

### Inspect, activate and clean up

| Phase | Operator action |
| --- | --- |
| `building` | Resume bounded backfill. |
| `blocked` | Resolve missing sources, invalid addresses or collisions; then retry. |
| `ready` | Review completion and activate the recorded epoch. |
| `idle` | No pending job. Inspect the active epoch after an uncertain activation. |

```ts
const status = await engine.migration.status({ tenantId, includeCounts: true });
if (status.phase === 'ready' && status.pendingEpoch === epoch) {
  await engine.migration.activate({ tenantId, epoch });
}
const cleanup = await engine.migration.cleanup({ tenantId, batchSize: 100 });
```

Schedule more cleanup batches while `cleanup.removed` is nonzero. Exact counts are opt-in because counting large tenants adds work.

Activation briefly drains tenant writes under a bounded lock, checks coverage and gaps, then switches metadata. Reads remain available. There is no planned authentication pause, but lock waits, provider limits and database overload can still affect latency. Installation of migration 006 separately takes brief DDL locks; see [database setup](database.md).

A pending job can be abandoned with `migration.abort({ tenantId, epoch })`, followed by cleanup. This does not roll back an already activated policy. A later reversal is another reviewed policy migration.

Policy activation preserves ownership revisions, so existing authorized verification proofs can complete across the flip. Real email changes still advance revisions. Never relabel stored keys, bypass policy fences or attach a current revision to an old proof.
