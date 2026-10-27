import { betterAuth, type BetterAuthOptions } from 'better-auth';
import { getMigrations } from 'better-auth/db/migration';
import { toNodeHandler } from 'better-auth/node';
import { createIronDomeClient } from '@irondome-dev/gate';
import {
  createBetterAuthGate,
  type BetterAuthGateOptions,
} from '@irondome-dev/gate/better-auth';
import { createPostgresBetterAuthChangeStore } from '@irondome-dev/gate/better-auth/postgres';
import { createOnlinePostgresGate } from '@irondome-dev/gate/online/postgres';
import type { PgPool } from '@irondome-dev/gate/postgres';

export interface BetterAuthApplicationConfig {
  pool: PgPool & NonNullable<BetterAuthOptions['database']>;
  tenantId: string;
  baseURL: string;
  secret: string;
  ironDomeApiKey: string;
  sendVerificationEmail: BetterAuthGateOptions['sendVerificationEmail'];
}

export function configureBetterAuthApplication(config: BetterAuthApplicationConfig) {
  const schema = 'trusted_auth';
  const engine = createOnlinePostgresGate(config.pool, {
    schema,
    screening: createIronDomeClient({ apiKey: config.ironDomeApiKey }),
  });
  const changes = createPostgresBetterAuthChangeStore(config.pool, { schema });
  const integration = createBetterAuthGate({
    tenantId: config.tenantId,
    engine,
    changes,
    sendVerificationEmail: config.sendVerificationEmail,
  });
  const authOptions = {
    database: config.pool,
    baseURL: config.baseURL,
    secret: config.secret,
    ...integration.authOptions,
  } satisfies BetterAuthOptions;

  return {
    async migrateAuthSchema() {
      const migration = await getMigrations(authOptions);
      if (migration.unsafeChanges.length > 0) {
        throw new Error('Review the Better Auth schema migration before applying it.');
      }
      await migration.runMigrations();
    },
    async start() {
      // initialize the tenant before accepting requests
      await engine.getEmailPolicy(config.tenantId);
      const auth = betterAuth(authOptions);
      const bound = integration.bind(auth);
      return {
        handler: bound.handler,
        nodeHandler: toNodeHandler(bound.handler),
        getActiveSession: bound.getActiveSession,
        resumeDeletion: bound.resumeDeletion,
      };
    },
    async deleteExpiredProofs() {
      await changes.deleteExpired();
    },
  };
}
