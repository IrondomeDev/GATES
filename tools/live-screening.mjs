// Explicit, billable smoke check. Never invoked by npm test. No emails are sent.
// Keep secrets in the environment or supply one line through a pipe, never CLI arguments.
import { createIronDomeClient } from '../.build/src/index.js';
import { performance } from 'node:perf_hooks';
import { createInterface } from 'node:readline';

async function main() {
  let apiKey = process.env.IRONDOME_API_KEY;
  if (process.argv.includes('--key-stdin')) {
    const reader = createInterface({ input: process.stdin, terminal: false });
    apiKey = await new Promise(resolve => { reader.once('line', resolve); reader.once('close', () => resolve(undefined)); });
    reader.close();
    process.stdin.pause();
  }
  if (!apiKey) throw new Error('configuration');
  const client = createIronDomeClient({ apiKey, timeoutMs: 5000, maxInFlight: 1 });
  apiKey = undefined;
  const results = [];
  for (const fixture of [
    { name: 'reserved-example-domain', email: 'gate-validation@example.com' },
    { name: 'disposable-domain', email: 'gate-validation@mailinator.com' },
  ]) {
    const started = performance.now();
    try {
      const decision = await client.screen(fixture.email);
      results.push({ fixture: fixture.name, allowed: decision.allowed, reason: decision.reason, elapsedMs: Math.round(performance.now() - started) });
    } catch (error) {
      const safeCodes = new Set(['configuration', 'invalid_email', 'busy', 'timeout', 'cancelled', 'transport', 'protocol', 'api']);
      results.push({ fixture: fixture.name, error: safeCodes.has(error?.code) ? error.code : 'failed',
        retryable: error?.retryable === true, ...(Number.isInteger(error?.status) ? { status: error.status } : {}), elapsedMs: Math.round(performance.now() - started) });
    }
  }
  console.log(JSON.stringify({ notes: 'Two synthetic screening calls only; no email delivery, identity writes or SLA measurement.', results }, null, 2));
  if (results.some(result => 'error' in result)) process.exitCode = 1;
}
main().catch(() => { console.error('live_screening_failed'); process.exitCode = 1; });
