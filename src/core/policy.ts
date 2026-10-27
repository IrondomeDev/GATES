import { normalizeStrict } from 'mail-canon';
import { createHash } from 'node:crypto';
import { GateError } from './errors.js';

/** Identifies normalization rules; not part of the unique identity key. */
export const POLICY_VERSION = 'gate-providers-v2-mailcanon-0.2.0-tr46-5.1.1';
export interface PreparedEmail {
  /** Exact accepted input. Never replace the delivery/verification destination with canonical. */
  readonly deliveryEmail: string;
  readonly canonical: string;
  readonly domain: string;
  readonly policyVersion: string;
}

/** Additive mailbox equivalences for an exact canonical domain. No suffix/MX inference. */
export interface DomainCanonicalRule {
  readonly lowercase?: boolean;
  readonly stripPlusTag?: boolean;
  readonly stripDots?: boolean;
}
export type DomainCanonicalRules = Readonly<Record<string, DomainCanonicalRule>>;
export interface EmailPolicy {
  readonly version: string;
  readonly prepareEmail: (email: unknown) => PreparedEmail;
}
export type EmailPreparation = (input: {
  tenantId: string; email: unknown; policyVersion?: string; signal?: AbortSignal;
}) => Promise<PreparedEmail>;

export function prepareEmail(email: unknown): PreparedEmail {
  if (typeof email !== 'string') throw new GateError('invalid_email');
  try {
    // Reject oversized inputs before the parser scans or allocates for them. The
    // code-unit check cheaply catches long ASCII strings; byteLength handles
    // multibyte input without first creating an encoded copy.
    if (email.length > 254 || Buffer.byteLength(email, 'utf8') > 254) throw new GateError('invalid_email');
    const identity = normalizeStrict(email);
    // Gate's supported SMTP/storage limit is narrower than mail-canon's identity buffer.
    // Select documented provider mailbox rules. Apple legacy-domain matching and
    // arbitrary custom-domain local-case folding remain outside ownership policy.
    const canonical = identity.provider === 'gmail' || identity.provider === 'microsoft' ||
      identity.provider === 'proton' || identity.provider === 'fastmail'
      ? identity.canonical
      : `${email.slice(0, email.lastIndexOf('@'))}@${identity.domain}`;
    if (Buffer.byteLength(canonical, 'utf8') > 254) throw new GateError('invalid_email');
    return Object.freeze({ deliveryEmail: email, canonical, domain: identity.domain, policyVersion: POLICY_VERSION });
  } catch {
    throw new GateError('invalid_email');
  }
}

export const DEFAULT_EMAIL_POLICY: EmailPolicy = Object.freeze({ version: POLICY_VERSION, prepareEmail });
const knownPolicies = new WeakSet<EmailPolicy>([DEFAULT_EMAIL_POLICY]);
const policyRules = new WeakMap<EmailPolicy, DomainCanonicalRules>([[DEFAULT_EMAIL_POLICY, Object.freeze({})]]);
const RULE_KEYS = ['lowercase', 'stripPlusTag', 'stripDots'] as const;

function dataObject(value: unknown): Record<string, PropertyDescriptor> {
  if (!value || typeof value !== 'object' ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('Invalid canonical rules');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value).length !== Object.keys(descriptors).length ||
      Object.values(descriptors).some(property => !('value' in property))) throw new TypeError('Invalid canonical rules');
  return descriptors;
}

/** Compile once at startup. Version fingerprints bind the built-in policy and normalized rules. */
export function createEmailPolicy(rules: DomainCanonicalRules = {}): EmailPolicy {
  const descriptors = dataObject(rules);
  const names = Object.keys(descriptors);
  if (names.length > 256) throw new TypeError('Too many canonical domains');
  const entries: Array<[string, number]> = [];
  const seen = new Set<string>();
  for (const name of names) {
    if (!name || name.endsWith('.') || /[\s*@:/\\?#\[\]]/.test(name)) throw new TypeError('Invalid canonical domain');
    let domain: string;
    try {
      const identity = prepareEmail(`x@${name}`);
      domain = identity.domain;
      if (identity.canonical.slice(identity.canonical.lastIndexOf('@') + 1) !== domain) {
        throw new TypeError('Use the canonical provider domain');
      }
    }
    catch { throw new TypeError('Invalid canonical domain'); }
    if (seen.has(domain)) throw new TypeError('Duplicate canonical domain');
    seen.add(domain);
    const fields = dataObject(descriptors[name]!.value);
    if (Object.keys(fields).some(key => !(RULE_KEYS as readonly string[]).includes(key))) throw new TypeError('Unknown canonical rule');
    let flags = 0;
    RULE_KEYS.forEach((key, index) => {
      const field = fields[key];
      if (field) {
        if (typeof field.value !== 'boolean') throw new TypeError('Canonical rule must be boolean');
        if (field.value) flags |= 1 << index;
      }
    });
    if (flags) entries.push([domain, flags]);
  }
  if (!entries.length) return DEFAULT_EMAIL_POLICY;
  entries.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  const version = `gate-domain-rules-v1-${createHash('sha256').update(JSON.stringify([POLICY_VERSION, entries])).digest('hex')}`;
  const compiled = new Map(entries);
  const policy: EmailPolicy = Object.freeze({ version, prepareEmail(email: unknown): PreparedEmail {
    const base = prepareEmail(email);
    const at = base.canonical.lastIndexOf('@');
    const domain = base.canonical.slice(at + 1);
    const flags = compiled.get(domain);
    let canonical = base.canonical;
    if (flags !== undefined) {
      let local = canonical.slice(0, at);
      if (flags & 2) { const plus = local.indexOf('+'); if (plus >= 0) local = local.slice(0, plus); }
      if (flags & 4) local = local.replace(/\./g, '');
      if (flags & 1) local = local.toLowerCase();
      // Removal can expose an invalid trailing dot or an empty base. Never store
      // keys that fail the same strict parser on the next login/audit.
      if (!local || local.endsWith('.') || Buffer.byteLength(local, 'utf8') > 64) throw new GateError('invalid_email');
      canonical = `${local}@${domain}`;
      if (Buffer.byteLength(canonical, 'utf8') > 254) throw new GateError('invalid_email');
    }
    return Object.freeze({ deliveryEmail: base.deliveryEmail, canonical, domain: base.domain, policyVersion: version });
  } });
  knownPolicies.add(policy);
  policyRules.set(policy, Object.freeze(Object.fromEntries(entries.map(([domain, flags]) => [domain, Object.freeze({
    ...(flags & 1 ? { lowercase: true } : {}), ...(flags & 2 ? { stripPlusTag: true } : {}), ...(flags & 4 ? { stripDots: true } : {}),
  })]))));
  return policy;
}

/** Immutable, non-personal configuration for the durable online policy catalog. */
export function serializeEmailPolicy(policy: EmailPolicy): DomainCanonicalRules {
  requireEmailPolicy(policy);
  return policyRules.get(policy)!;
}

/** Reject mutable or user-supplied policy implementations at administrative boundaries. */
export function requireEmailPolicy(value: EmailPolicy): EmailPolicy {
  if (!knownPolicies.has(value)) throw new TypeError('Expected a compiled Gate email policy');
  return value;
}

// With the Unicode flag, this class matches unpaired surrogates but treats a
// valid high/low pair as one code point. Buffer round-tripping used to provide
// the same check by allocating both an encoded buffer and decoded string.
const LONE_SURROGATE = /[\uD800-\uDFFF]/u;
const USER_ID_FORBIDDEN = /[\s\u0000-\u001f\u007f]/u;
const VALID_TENANT = /^[a-zA-Z0-9][a-zA-Z0-9_.:@/-]{0,127}$/;

function validUserId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 512 &&
    !USER_ID_FORBIDDEN.test(value) && Buffer.byteLength(value, 'utf8') <= 512 &&
    !LONE_SURROGATE.test(value);
}

export function validateContext(tenantId: unknown, ...userIds: unknown[]): asserts tenantId is string {
  const validTenant = typeof tenantId === 'string' && VALID_TENANT.test(tenantId);
  // Provider subjects are opaque (Auth0 commonly uses provider|subject). Preserve
  // exact spelling, reject whitespace/control characters and malformed Unicode,
  // and match the durable registry's byte bound instead of truncating/mapping IDs.
  if (!validTenant) throw new GateError('invalid_context');
  for (const userId of userIds) if (!validUserId(userId)) throw new GateError('invalid_context');
}
