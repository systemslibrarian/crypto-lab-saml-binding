import { beforeAll, describe, expect, it } from 'vitest';
import { honestSpec } from '../src/saml/build.js';
import {
  issueSignedResponse,
  newParties,
  runBaseline,
  runWrapping,
  type Parties,
} from '../src/saml/lesson.js';
import { siblingAssertionFirst, wrapInAdvice } from '../src/saml/attacks.js';
import { libraryVerify } from '../src/saml/verify.js';
import { NS, allElements, parseXml } from '../src/saml/dom.js';
import { repairedConsume, vulnerableConsume } from '../src/saml/consumers.js';
import { freshState } from '../src/saml/checks.js';
import { ACS_URL, IDP_ENTITY_ID, SP_ENTITY_ID } from '../src/saml/profile.js';

/**
 * The lesson itself.
 *
 * Four things have to be true at once for this to be the signature-wrapping
 * lesson rather than a tampering demo wearing its label, and each is asserted
 * separately:
 *
 *   1. the signature on the malicious document really verifies;
 *   2. the attacker holds no key and altered no signed byte;
 *   3. the vulnerable consumer authorizes the attacker's subject;
 *   4. the repaired consumer refuses the same document, at L2, by name.
 *
 * If 1 ever stopped holding, this file would fail rather than quietly become a
 * demonstration of something else.
 */

let parties: Parties;

beforeAll(async () => {
  parties = await newParties();
}, 60_000);

describe('the malicious document', () => {
  it('keeps the original signed assertion byte-for-byte', async () => {
    const spec = honestSpec();
    const honest = await issueSignedResponse(parties, spec);
    const wrapped = wrapInAdvice(honest, spec, 'admin@lab.invalid');

    const original = allElements(parseXml(honest), NS.saml, 'Assertion')[0];
    const moved = allElements(parseXml(wrapped), NS.saml, 'Assertion').find(
      (candidate) => candidate.getAttribute('ID') === spec.assertionId,
    );
    expect(moved).toBeDefined();
    // Canonical form is the right comparison: serialization may differ, the
    // signed octets may not.
    const { canonicalize } = await import('../src/saml/verify.js');
    expect(canonicalize(moved)).toBe(canonicalize(original));
  }, 60_000);

  it('still verifies under the identity provider’s key', async () => {
    const spec = honestSpec();
    const wrapped = wrapInAdvice(await issueSignedResponse(parties, spec), spec, 'admin@lab.invalid');
    const library = await libraryVerify(parseXml(wrapped), parties.idp.publicKey);
    expect(library.verified).toBe(true);
    expect(library.error).toBeNull();
  }, 60_000);

  it('puts the attacker’s assertion first and the signed one deeper', async () => {
    const report = await runWrapping(parties);
    expect(report.census).toHaveLength(2);
    expect(report.census[0]?.subject).toBe('admin@lab.invalid');
    expect(report.census[0]?.depth).toBe(1);
    expect(report.census[1]?.subject).toBe('alice@lab.invalid');
    expect(report.census[1]?.depth).toBeGreaterThan(1);
  }, 60_000);
});

describe('the two consumers, on the same bytes', () => {
  it('agree on the honest response', async () => {
    const report = await runBaseline(parties);
    expect(report.vulnerable.authorized).toBe(true);
    expect(report.repaired.authorized).toBe(true);
    expect(report.vulnerable.subject).toBe('alice@lab.invalid');
    expect(report.repaired.subject).toBe('alice@lab.invalid');
    expect(report.vulnerable.selectedAssertionId).toBe(report.repaired.selectedAssertionId);
  }, 60_000);

  it('disagree on the wrapped response, and the cryptography is identical', async () => {
    const report = await runWrapping(parties);

    // The vulnerable consumer: signature verified, wrong principal.
    expect(report.vulnerable.signatureVerified).toBe(true);
    expect(report.vulnerable.authorized).toBe(true);
    expect(report.vulnerable.subject).toBe('admin@lab.invalid');
    expect(report.vulnerable.role).toBe('administrator');

    // Every SAML profile rule passed for it, too. Profile validation is not a
    // defence against validating the wrong element.
    expect(report.vulnerable.checks.every((check) => check.passed)).toBe(true);

    // The repaired consumer: same signature, refused on the binding.
    expect(report.repaired.authorized).toBe(false);
    expect(report.repaired.failedLayer).toBe('L2 binding');
    expect(report.repaired.bindingFailures.map((f) => f.rule)).toEqual([
      'verified-node-wrong-position',
    ]);

    // And the two consumers read different elements, which is the mechanism.
    expect(report.vulnerable.selectedAssertionId).toBe('_s12forged0000000000000000000001');
    expect(report.verification.verifiedElementId).toBeNull();
    expect(report.verification.structure.referenceUri).toBe(`#${honestSpec().assertionId}`);
  }, 60_000);

  it('grants materially different rights, not just a different string', async () => {
    const report = await runWrapping(parties);
    expect(report.vulnerable.rights).toContain('export the user table');
    expect(report.repaired.rights).toEqual([]);
  }, 60_000);
});

describe('the sibling variant, where position alone is not the repair', () => {
  function sp() {
    return freshState(SP_ENTITY_ID, ACS_URL, IDP_ENTITY_ID, honestSpec().inResponseTo);
  }

  it('leaves the signed assertion exactly where the position rule wants it', async () => {
    const spec = honestSpec();
    const attacked = siblingAssertionFirst(
      await issueSignedResponse(parties, spec),
      spec,
      'admin@lab.invalid',
    );
    const { verifyBound } = await import('../src/saml/verify.js');
    const verification = await verifyBound(attacked, parties.idp.publicKey);
    // Position passes. Every binding rule passes. The document is still hostile.
    expect(verification.failures).toEqual([]);
    expect(verification.verifiedElementId).toBe(spec.assertionId);
  }, 60_000);

  it('fools the vulnerable consumer, which re-queries and gets the attacker', async () => {
    const spec = honestSpec();
    const attacked = siblingAssertionFirst(
      await issueSignedResponse(parties, spec),
      spec,
      'admin@lab.invalid',
    );
    const outcome = await vulnerableConsume(attacked, parties.idp.publicKey, sp());
    expect(outcome.authorized).toBe(true);
    expect(outcome.subject).toBe('admin@lab.invalid');
    expect(outcome.selectedAssertionId).toBe('_s12sibling000000000000000000001');
  }, 60_000);

  it('does not fool the repaired consumer, which authorizes the RIGHT person', async () => {
    // This is the case that shows the repair is the element binding itself and
    // not the position rule: here the repaired consumer does not refuse, it
    // succeeds correctly, because it never asks the document a second time.
    const spec = honestSpec();
    const attacked = siblingAssertionFirst(
      await issueSignedResponse(parties, spec),
      spec,
      'admin@lab.invalid',
    );
    const outcome = await repairedConsume(attacked, parties.idp.publicKey, sp());
    expect(outcome.authorized).toBe(true);
    expect(outcome.subject).toBe('alice@lab.invalid');
    expect(outcome.role).toBe('reader');
    expect(outcome.selectedAssertionId).toBe(spec.assertionId);
  }, 60_000);
});
