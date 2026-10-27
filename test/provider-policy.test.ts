import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createGate } from '../src/core/engine.js';
import { GateError } from '../src/core/errors.js';
import { prepareEmail, POLICY_VERSION } from '../src/core/policy.js';
import { MemoryRegistry } from './memory-registry.js';

const fastmailDomains = `
123mail.org 150mail.com 150ml.com 16mail.com 2-mail.com 4email.net 50mail.com airpost.net aliencamel.com allmail.net bestmail.us cluemail.com elitemail.org emailcorner.net emailengine.net emailengine.org emailgroups.net emailplus.org emailuser.net eml.cc f-m.fm fast-email.com fast-mail.org fastem.com fastemail.us fastemailer.com fastest.cc fastimap.com fastmail.ca fastmail.cn fastmail.co.uk fastmail.com fastmail.com.au fastmail.de fastmail.es fastmail.fm fastmail.fr fastmail.im fastmail.in fastmail.jp fastmail.mx fastmail.net fastmail.nl fastmail.org fastmail.se fastmail.to fastmail.tw fastmail.uk fastmail.us fastmailbox.net fastmessaging.com fea.st fmail.co.uk fmailbox.com fmgirl.com fmguy.com foobox.com foobox.net ftml.net h-mail.us hailmail.net imap-mail.com imap.cc imapmail.org immerbox.com immermail.com inoutbox.com internet-e-mail.com internet-mail.org internetemails.net internetmailing.net jetemail.net justemail.net letterboxes.org lifetimeaddress.com mail-central.com mail-page.com mailas.com mailbolt.com mailc.net mailcan.com mailforce.net mailhaven.com mailingaddress.org mailite.com mailmight.com mailnew.com mailsent.net mailservice.ms mailup.net mailworks.org mailzone.com ml1.net mm.st myfastmail.com mymacmail.com nospammail.net onepost.net ownmail.net penguinmail.com permanentmail.com petml.com pobox.com postinbox.com postpro.net proinbox.com promessage.com realemail.net reallyfast.biz reallyfast.info rushpost.com sent.as sent.at sent.com siemprebox.com siempremail.com speedpost.net speedymail.org ssl-mail.com swift-mail.com the-fastest.net the-quickest.com theinternetemail.com veribox.net veryfast.biz veryspeedy.net warpmail.net xsmail.com yepmail.net your-mail.com
`.trim().split(/\s+/);

const allow = { async screen() { return { allowed: true, reason: 'not_listed' }; } };
const gateError = (code: string) => (error: unknown) => error instanceof GateError && error.code === code;

test('policy v2 applies Microsoft rules but keeps provider domains distinct', () => {
  const first = prepareEmail('A.B+tag@outlook.com');
  assert.equal(first.canonical, 'a.b@outlook.com');
  assert.equal(first.deliveryEmail, 'A.B+tag@outlook.com');
  assert.equal(first.policyVersion, POLICY_VERSION);
  assert.notEqual(first.canonical, prepareEmail('a.b@hotmail.com').canonical);
  assert.notEqual(prepareEmail('a+b@live.com').canonical, prepareEmail('a@msn.com').canonical);
});

test('policy v2 folds Proton separators and plus suffix while preserving exact domains', () => {
  const domains = ['proton.me', 'protonmail.com', 'protonmail.ch', 'pm.me'];
  for (const domain of domains) {
    const prepared = prepareEmail(`U_s-e.r+tag@${domain}`);
    assert.equal(prepared.canonical, `user@${domain}`);
    assert.equal(prepared.domain, domain);
    assert.equal(prepared.deliveryEmail, `U_s-e.r+tag@${domain}`);
    assert.equal(prepareEmail(`user@${domain}`).canonical, prepared.canonical);
  }
  for (let i = 0; i < domains.length; i++) {
    for (let j = i + 1; j < domains.length; j++) {
      assert.notEqual(prepareEmail(`user@${domains[i]}`).canonical, prepareEmail(`user@${domains[j]}`).canonical);
    }
  }
});

test('policy v2 recognizes all 130 Fastmail roots and strips only plus tags', () => {
  assert.equal(fastmailDomains.length, 130);
  for (const domain of fastmailDomains) {
    const prepared = prepareEmail(`Dot.Keep+tag@${domain}`);
    assert.equal(prepared.canonical, `dot.keep@${domain}`, domain);
    assert.equal(prepared.domain, domain, domain);
    assert.equal(prepared.deliveryEmail, `Dot.Keep+tag@${domain}`, domain);
  }
  assert.notEqual(prepareEmail('dot.keep@fastmail.com').canonical, prepareEmail('dot.keep@fastmail.fm').canonical);
});

test('Fastmail one-level subdomain aliasing is exact and keeps submitted domain metadata', () => {
  const alias = prepareEmail('anything+ignored@User.fastmail.co.uk');
  assert.deepEqual(alias, {
    deliveryEmail: 'anything+ignored@User.fastmail.co.uk',
    canonical: 'user@fastmail.co.uk',
    domain: 'user.fastmail.co.uk',
    policyVersion: POLICY_VERSION,
  });
  assert.notEqual(alias.canonical, prepareEmail('user@fastmail.com').canonical);
  for (const email of [
    'tag@user.sub.fastmail.com',
    'tag@user.example.com',
    'tag@fastmail.com.example',
  ]) {
    const identity = prepareEmail(email);
    assert.equal(identity.canonical, email.slice(0, email.lastIndexOf('@')).replace(/[A-Z]/g, c => c.toLowerCase()) + '@' + email.slice(email.lastIndexOf('@') + 1).toLowerCase());
  }
});

test('Fastmail and Proton aliases race for one Gate owner, then enforce active ownership', async () => {
  for (const [emailA, emailB] of [
    ['Alice+one@outlook.com', 'alice+two@outlook.com'],
    ['a.b+one@fastmail.com', 'a.b+two@fastmail.com'],
    ['U_s-e.r+one@protonmail.ch', 'user+two@protonmail.ch'],
  ]) {
    const registry = new MemoryRegistry();
    const gate = createGate({ registry, screening: allow });
    const attempts = [emailA, emailB].map((email, index) => ({ tenantId: 'provider-tenant', userId: `u${index}`, email }));
    const results = await Promise.allSettled(attempts.map(input => gate.claimVerified(input)));
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    assert.equal(results.filter(result => result.status === 'rejected' && gateError('identity_conflict')(result.reason)).length, 1);
    const winnerIndex = results.findIndex(result => result.status === 'fulfilled');
    await gate.assertActive(attempts[winnerIndex]!);
    await assert.rejects(gate.assertActive(attempts[1 - winnerIndex]!), gateError('ownership_required'));
  }
});

test('Fastmail and Proton canonical ownership is tenant-scoped', async () => {
  const registry = new MemoryRegistry();
  const gate = createGate({ registry, screening: allow });
  await gate.claimVerified({ tenantId: 'tenant-a', userId: 'a', email: 'a+b@fastmail.com' });
  await gate.claimVerified({ tenantId: 'tenant-b', userId: 'b', email: 'a@fastmail.com' });
  await gate.claimVerified({ tenantId: 'tenant-a', userId: 'c', email: 'a@pm.me' });
  assert.equal(registry.size, 3);
});
