/**
 * server-only email screening; 422 means invalid_email, 429 means monthly quota exhaustion.
 * no automatic retries: a timed-out request may already have been billed.
 */
import { prepareEmail } from './policy.js';

const ENDPOINT = 'https://api.irondome.dev/v1/check';
const MAX_RESPONSE_BYTES = 16 * 1024;
const INITIAL_RESPONSE_BYTES = 256;
const MAX_EMPTY_RESPONSE_CHUNKS = 256;
const encoder = new TextEncoder();
const providers = new Set(['gmail', 'microsoft', 'icloud', 'proton', 'yahoo', 'custom']);
const reasons = new Set(['blocked_email', 'blocked_domain', 'allowed_domain', 'not_listed']);

export type IronDomeReason = 'blocked_email' | 'blocked_domain' | 'allowed_domain' | 'not_listed';
export interface IronDomeDecision {
  readonly allowed: boolean;
  readonly reason: IronDomeReason;
}
export interface IronDomeClient {
  screen(email: string, signal?: AbortSignal): Promise<IronDomeDecision>;
}
export interface IronDomeClientOptions {
  /** Server secret; never place this client in a browser bundle. */
  apiKey: string;
  /** Includes obtaining response headers AND reading the response body. */
  timeoutMs?: number;
  /** Excess calls fail immediately rather than entering an unbounded queue. */
  maxInFlight?: number;
  /** Trusted Fetch-compatible runtime/test adapter; it must honor abort. */
  fetch?: typeof globalThis.fetch;
}
export type IronDomeErrorCode = 'configuration' | 'invalid_email' | 'busy' | 'timeout' |
  'cancelled' | 'transport' | 'protocol' | 'api';

/** Sanitized: never retains an upstream body, raw error/cause, email or key. */
export class IronDomeClientError extends Error {
  readonly code: IronDomeErrorCode;
  readonly retryable: boolean;
  readonly status: number | undefined;
  constructor(code: IronDomeErrorCode, retryable = false, status?: number) {
    super(`irondome_${code}`);
    this.name = 'IronDomeClientError';
    this.code = code;
    this.retryable = retryable;
    this.status = status;
  }
}

function positiveInteger(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new IronDomeClientError('configuration');
  }
  return value;
}

function requestBody(email: string): Uint8Array<ArrayBuffer> {
  // Direct use is just as strict as the shared engine: unsupported syntax must
  // never become a billable API request. Preserve the submitted address verbatim.
  try { prepareEmail(email); } catch { throw new IronDomeClientError('invalid_email'); }
  const body = encoder.encode(JSON.stringify({ email }));
  if (body.byteLength > 1024) throw new IronDomeClientError('invalid_email');
  return body;
}

async function responseBody(response: Response, signal: AbortSignal): Promise<unknown> {
  const reader = response.body?.getReader();
  const cancel = (): void => { void reader?.cancel().catch(() => undefined); };
  signal.addEventListener('abort', cancel, { once: true });
  let bytes: Uint8Array<ArrayBuffer> | undefined;
  let length = 0;
  let emptyChunkCount = 0;
  try {
    if (signal.aborted) throw new IronDomeClientError('cancelled');
    const declared = response.headers.get('content-length');
    const declaredLength = declared === null ? 0 : Number(declared);
    const encoding = response.headers.get('content-encoding');
    if ((declared !== null && (!/^\d+$/.test(declared) || declaredLength > MAX_RESPONSE_BYTES)) ||
        (encoding !== null && encoding.toLowerCase() !== 'identity') ||
        response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') {
      throw new IronDomeClientError('protocol');
    }
    // A bounded length hint avoids growth for declared large bodies. Small or
    // undeclared responses start at 256 B; actual bytes enforce the independent cap.
    bytes = new Uint8Array(Math.max(INITIAL_RESPONSE_BYTES, declaredLength));
    if (reader) {
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        // Transport fragmentation has no JSON semantics. Bound empty reads only;
        // nonempty read count is already bounded by the total byte limit.
        if ((chunk.value.byteLength === 0 && ++emptyChunkCount > MAX_EMPTY_RESPONSE_CHUNKS) ||
            chunk.value.byteLength > MAX_RESPONSE_BYTES - length) {
          throw new IronDomeClientError('protocol');
        }
        if (chunk.value.byteLength === 0) continue;
        const needed = length + chunk.value.byteLength;
        if (needed > bytes.byteLength) {
          // Own each chunk before the next read: a Fetch adapter may reuse its
          // backing memory. Small JSON responses do not need the full 16 KiB cap;
          // Geometric growth keeps undeclared fragmented bodies linear and bounded.
          const capacity = Math.max(needed, Math.min(MAX_RESPONSE_BYTES, bytes.byteLength * 2));
          const grown = new Uint8Array(capacity);
          grown.set(bytes.subarray(0, length));
          bytes = grown;
        }
        bytes.set(chunk.value, length);
        length = needed;
      }
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length))) as unknown;
  } catch (error) {
    cancel();
    if (error instanceof IronDomeClientError) throw error;
    throw new IronDomeClientError('protocol');
  } finally {
    signal.removeEventListener('abort', cancel);
    reader?.releaseLock();
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function createIronDomeClient(options: IronDomeClientOptions): IronDomeClient {
  if (typeof options.apiKey !== 'string' || !/^[\x21-\x7e]{1,4096}$/.test(options.apiKey)) {
    throw new IronDomeClientError('configuration');
  }
  const authorization = `Bearer ${options.apiKey}`;
  const timeoutMs = positiveInteger(options.timeoutMs ?? 3000, 2_147_483_647);
  const maxInFlight = positiveInteger(options.maxInFlight ?? 64, 65536);
  const fetcher = options.fetch ?? globalThis.fetch;
  if (typeof fetcher !== 'function') throw new IronDomeClientError('configuration');
  let active = 0;

  return Object.freeze({
    async screen(email: string, signal?: AbortSignal): Promise<IronDomeDecision> {
      const body = requestBody(email);
      if (signal?.aborted) throw new IronDomeClientError('cancelled');
      if (active >= maxInFlight) throw new IronDomeClientError('busy', true);
      active++;
      const controller = new AbortController();
      let terminal: IronDomeClientError | undefined;
      let rejectDeadline: (reason: IronDomeClientError) => void = () => undefined;
      const deadline = new Promise<never>((_, reject) => { rejectDeadline = reject; });
      const stop = (code: 'cancelled' | 'timeout'): void => {
        if (terminal) return;
        terminal = new IronDomeClientError(code, code === 'timeout');
        rejectDeadline(terminal);
        controller.abort();
      };
      const cancel = (): void => stop('cancelled');
      signal?.addEventListener('abort', cancel, { once: true });
      const timer = setTimeout(() => stop('timeout'), timeoutMs);
      try {
        const operation = async (): Promise<IronDomeDecision> => {
          const response = await fetcher(ENDPOINT, {
            method: 'POST', body,
            headers: { authorization, accept: 'application/json', 'content-type': 'application/json',
              'accept-encoding': 'identity', 'cache-control': 'no-store' },
            signal: controller.signal, redirect: 'manual', credentials: 'omit',
            cache: 'no-store', referrerPolicy: 'no-referrer',
          });
          if (response.redirected || (response.url !== '' && response.url !== ENDPOINT) ||
              (response.status >= 300 && response.status < 400)) {
            void response.body?.cancel().catch(() => undefined);
            throw new IronDomeClientError('protocol');
          }
          if (controller.signal.aborted) {
            void response.body?.cancel().catch(() => undefined);
            throw terminal ?? new IronDomeClientError('cancelled');
          }
          if (response.status !== 200) {
            // Status is authoritative except for the documented 422 invalid_email
            // contract. Cancel other bodies immediately; do not wait for an
            // irrelevant or stalled error payload (notably monthly quota 429).
            if (response.status !== 422) {
              void response.body?.cancel().catch(() => undefined);
              throw new IronDomeClientError('api', response.status >= 500, response.status);
            }
            let data: unknown;
            try { data = await responseBody(response, controller.signal); } catch { /* status remains authoritative */ }
            if (response.status === 422 && record(data) && record(data.error) && data.error.code === 'invalid_email') {
              throw new IronDomeClientError('invalid_email', false, 422);
            }
            throw new IronDomeClientError('api', response.status >= 500, response.status);
          }
          const data = await responseBody(response, controller.signal);
          if (!record(data) || data.valid !== true || typeof data.provider !== 'string' ||
              !providers.has(data.provider) || typeof data.reason !== 'string' || !reasons.has(data.reason) ||
              typeof data.disposable !== 'boolean' ||
              data.disposable !== (data.reason === 'blocked_email' || data.reason === 'blocked_domain')) {
            throw new IronDomeClientError('protocol');
          }
          return Object.freeze({ allowed: !data.disposable, reason: data.reason as IronDomeReason });
        };
        return await Promise.race([operation(), deadline]);
      } catch (error) {
        if (terminal) throw terminal;
        if (error instanceof IronDomeClientError) throw error;
        throw new IronDomeClientError('transport', true);
      } finally {
        clearTimeout(timer);
        signal?.removeEventListener('abort', cancel);
        active--;
      }
    },
  });
}
