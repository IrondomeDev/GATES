/** Durable metadata for provider-generated, signed email-change proofs. Never store the token. */
export interface BetterAuthChange {
  readonly tenantId: string;
  readonly userId: string;
  readonly tokenHash: string;
  readonly purpose: 'verify-email' | 'change-email';
  readonly previousDeliveryEmail: string;
  readonly nextDeliveryEmail: string;
  readonly expectedRevision: string;
  readonly expiresAt: Date;
}
export interface BetterAuthChangeStore {
  save(change: BetterAuthChange): Promise<void>;
  /** Expired or absent records must return null. Never synthesize a missing binding. */
  find(input: { tenantId: string; tokenHash: string }): Promise<BetterAuthChange | null>;
  deleteUser(input: { tenantId: string; userId: string }): Promise<void>;
  deleteExpired(): Promise<void>;
}
