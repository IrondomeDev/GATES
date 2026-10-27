import type { ClaimInput, ClaimResult, IdentityRegistry, OwnershipInput } from '../src/core/registry.js';
/** TEST/BENCH ONLY. Synchronous mutation is atomic in one JS process, not a database substitute. */
export class MemoryRegistry implements IdentityRegistry {
  private byCanonical = new Map<string, string>();
  private byUser = new Map<string, string>();
  private revoked = new Set<string>();
  private key(tenantId: string, value: string) { return JSON.stringify([tenantId, value]); }
  async claim(input: ClaimInput): Promise<ClaimResult> {
    const identity = this.key(input.tenantId, input.canonical);
    const account = this.key(input.tenantId, input.userId);
    if (this.revoked.has(account)) return 'revoked';
    const owner = this.byCanonical.get(identity);
    if (owner === account) return 'already-owned';
    if (owner !== undefined) return 'conflict';
    const old = this.byUser.get(account);
    if (old !== undefined) return 'conflict';
    this.byUser.set(account, identity);
    this.byCanonical.set(identity, account);
    return 'claimed';
  }
  async owns(input: OwnershipInput): Promise<boolean> {
    return this.byCanonical.get(this.key(input.tenantId, input.canonical)) === this.key(input.tenantId, input.userId);
  }
  async releaseUser(input: {tenantId: string; userId: string}): Promise<void> {
    const account = this.key(input.tenantId, input.userId);
    this.revoked.add(account);
    const old = this.byUser.get(account);
    if (old !== undefined) this.byCanonical.delete(old);
    this.byUser.delete(account);
  }
  get size() { return this.byCanonical.size; }
}
