import { beforeAll, describe, expect, it } from 'vitest';
import { buildResponse, honestSpec, type ResponseSpec } from '../src/saml/build.js';
import { issueSignedResponse, newParties, runControls, type Parties } from '../src/saml/lesson.js';
import { repairedConsume } from '../src/saml/consumers.js';
import { freshState } from '../src/saml/checks.js';
import { ACS_URL, CLOCK_SKEW_SECONDS, IDP_ENTITY_ID, SP_ENTITY_ID } from '../src/saml/profile.js';
import { signResponse } from '../src/saml/sign.js';
import { NS, allElements, childElements, type XmlDocument, type XmlElement } from '../src/saml/dom.js';

/**
 * L3 - SAML profile validation, including the boundaries.
 *
 * Boundary cases matter more than the obvious ones here: an implementation that
 * compares the wrong way round, or forgets the allowed skew, passes every
 * "clearly expired" test and fails on the minute it matters.
 */

let parties: Parties;
const PENDING = honestSpec().inResponseTo;

function state(pending: string | null = PENDING) {
  return freshState(SP_ENTITY_ID, ACS_URL, IDP_ENTITY_ID, pending);
}

beforeAll(async () => {
  parties = await newParties();
}, 60_000);

async function consume(overrides: Partial<ResponseSpec>, pending: string | null = PENDING) {
  const spec = { ...honestSpec(), ...overrides } as ResponseSpec;
  const xml = await issueSignedResponse(parties, spec);
  return repairedConsume(xml, parties.idp.publicKey, state(pending));
}

async function consumeDocument(doc: XmlDocument, pending: string | null = PENDING) {
  const spec = honestSpec();
  const xml = await signResponse(doc, parties.idp.privateKey, {
    referenceId: spec.assertionId,
    placeInside: 'referenced-element',
  });
  return repairedConsume(xml, parties.idp.publicKey, state(pending));
}

function honestAssertion(doc: XmlDocument): XmlElement {
  const assertion = allElements(doc, NS.saml, 'Assertion')[0];
  if (!assertion) throw new Error('the fixture has no saml:Assertion');
  return assertion;
}

function check(outcome: Awaited<ReturnType<typeof consume>>, name: string) {
  const found = outcome.checks.find((row) => row.name === name);
  expect(found, `no check named ${name}`).toBeDefined();
  return found!;
}

describe('the honest response passes every rule', () => {
  it('passes all of them, and there are no checks left unevaluated', async () => {
    const outcome = await consume({});
    expect(outcome.authorized).toBe(true);
    expect(outcome.checks.filter((row) => !row.passed)).toEqual([]);
    expect(outcome.checks.map((row) => row.name)).toEqual([
      'destination',
      'response-in-response-to',
      'status',
      'issuer',
      'audience',
      'subject-confirmation-method',
      'subject-present',
      'authentication-statement-present',
      'confirmation-notbefore-absent',
      'recipient',
      'in-response-to',
      'conditions-validity',
      'confirmation-validity',
      'single-use',
    ]);
  }, 60_000);
});

describe('each rule fails on its own, for its own reason', () => {
  it('audience', async () => {
    const outcome = await consume({ audience: 'https://other.lab.invalid/saml2/sp' });
    expect(check(outcome, 'audience').passed).toBe(false);
    expect(check(outcome, 'recipient').passed).toBe(true);
    expect(outcome.authorized).toBe(false);
    expect(outcome.failedLayer).toBe('L3 profile');
  }, 60_000);

  it('recipient', async () => {
    const outcome = await consume({ recipient: 'https://other.lab.invalid/saml2/acs' });
    expect(check(outcome, 'recipient').passed).toBe(false);
    expect(check(outcome, 'audience').passed).toBe(true);
  }, 60_000);

  it('subject confirmation method', async () => {
    const outcome = await consume({
      subjectConfirmationMethod: 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key',
    });
    expect(check(outcome, 'subject-confirmation-method').passed).toBe(false);
  }, 60_000);

  it('a forbidden NotBefore on SubjectConfirmationData', async () => {
    const outcome = await consume({ confirmationNotBeforeOffsetSeconds: -120 });
    expect(check(outcome, 'confirmation-notbefore-absent').passed).toBe(false);
    // The window itself is satisfiable; the attribute is forbidden regardless.
    expect(check(outcome, 'confirmation-validity').passed).toBe(true);
  }, 60_000);

  it('InResponseTo that answers a different request', async () => {
    const outcome = await consume({ inResponseTo: '_s12authnrequest00000000000000999' });
    expect(check(outcome, 'response-in-response-to').passed).toBe(false);
    expect(check(outcome, 'in-response-to').passed).toBe(false);
  }, 60_000);

  it('InResponseTo present on a response the service provider did not solicit', async () => {
    const outcome = await consume({}, null);
    expect(check(outcome, 'response-in-response-to').passed).toBe(false);
    expect(check(outcome, 'in-response-to').passed).toBe(false);
    expect(check(outcome, 'in-response-to').expected).toMatch(/unsolicited/);
  }, 60_000);

  it('an unsolicited response with no InResponseTo is accepted', async () => {
    const outcome = await consume({ inResponseTo: null }, null);
    expect(check(outcome, 'response-in-response-to').passed).toBe(true);
    expect(check(outcome, 'in-response-to').passed).toBe(true);
    expect(outcome.authorized).toBe(true);
  }, 60_000);

  it('an issuer the service provider does not trust', async () => {
    const outcome = await consume({ issuer: 'https://evil.lab.invalid/saml2/idp' });
    expect(check(outcome, 'issuer').passed).toBe(false);
  }, 60_000);

  it('requires the selected assertion to contain an authentication statement', async () => {
    const doc = buildResponse(honestSpec());
    const assertion = honestAssertion(doc);
    const statement = childElements(assertion, NS.saml, 'AuthnStatement')[0];
    if (!statement) throw new Error('the honest fixture has no saml:AuthnStatement');
    assertion.removeChild(statement);

    const outcome = await consumeDocument(doc);
    expect(check(outcome, 'authentication-statement-present').passed).toBe(false);
    expect(outcome.authorized).toBe(false);
  }, 60_000);
});

describe('multiple bearer confirmations are evaluated as complete tuples', () => {
  function appendConfirmationCopy(doc: XmlDocument): {
    first: XmlElement;
    second: XmlElement;
  } {
    const assertion = honestAssertion(doc);
    const subject = childElements(assertion, NS.saml, 'Subject')[0];
    const first = subject ? childElements(subject, NS.saml, 'SubjectConfirmation')[0] : null;
    if (!subject || !first) throw new Error('the honest fixture has no bearer confirmation');
    const second = first.cloneNode(true) as XmlElement;
    subject.appendChild(second);
    return { first, second };
  }

  function dataOf(confirmation: XmlElement): XmlElement {
    const data = childElements(confirmation, NS.saml, 'SubjectConfirmationData')[0];
    if (!data) throw new Error('the bearer confirmation has no data');
    return data;
  }

  it('accepts when the first candidate fails but a later complete candidate succeeds', async () => {
    const doc = buildResponse(honestSpec());
    const { first } = appendConfirmationCopy(doc);
    dataOf(first).setAttribute('Recipient', 'https://wrong.lab.invalid/saml2/acs');

    const outcome = await consumeDocument(doc);
    expect(outcome.authorized).toBe(true);
    expect(check(outcome, 'recipient').observed).toBe(ACS_URL);
    expect(outcome.checks.every((row) => row.passed)).toBe(true);
  }, 60_000);

  it('never combines individually passing fields from two invalid candidates', async () => {
    const doc = buildResponse(honestSpec());
    const { first, second } = appendConfirmationCopy(doc);
    dataOf(first).setAttribute('Recipient', 'https://wrong.lab.invalid/saml2/acs');
    dataOf(second).setAttribute('InResponseTo', '_another-request');

    const outcome = await consumeDocument(doc);
    expect(outcome.authorized).toBe(false);
    const tupleChecks = ['recipient', 'in-response-to', 'confirmation-validity'];
    expect(outcome.checks.filter((row) => tupleChecks.includes(row.name)).some((row) => !row.passed))
      .toBe(true);
  }, 60_000);
});

describe('validity windows, at the boundary', () => {
  const skew = CLOCK_SKEW_SECONDS;

  it('accepts an assertion that expires exactly at the edge of the allowed skew', async () => {
    const outcome = await consume({
      notOnOrAfterOffsetSeconds: -skew + 1,
      confirmationNotOnOrAfterOffsetSeconds: -skew + 1,
    });
    expect(check(outcome, 'conditions-validity').passed).toBe(true);
    expect(check(outcome, 'confirmation-validity').passed).toBe(true);
  }, 60_000);

  it('refuses one second past that edge', async () => {
    const outcome = await consume({
      notOnOrAfterOffsetSeconds: -skew,
      confirmationNotOnOrAfterOffsetSeconds: -skew,
    });
    expect(check(outcome, 'conditions-validity').passed).toBe(false);
    expect(check(outcome, 'confirmation-validity').passed).toBe(false);
  }, 60_000);

  it('accepts a NotBefore exactly at the edge of the allowed skew', async () => {
    const outcome = await consume({ notBeforeOffsetSeconds: skew });
    expect(check(outcome, 'conditions-validity').passed).toBe(true);
  }, 60_000);

  it('refuses a NotBefore one second beyond it', async () => {
    const outcome = await consume({ notBeforeOffsetSeconds: skew + 1 });
    expect(check(outcome, 'conditions-validity').passed).toBe(false);
  }, 60_000);

  it('rejects malformed and impossible Conditions instants instead of treating them as absent', async () => {
    for (const instant of ['not-a-saml-instant', '2026-02-30T12:00:00Z']) {
      const doc = buildResponse(honestSpec());
      const conditions = childElements(honestAssertion(doc), NS.saml, 'Conditions')[0];
      if (!conditions) throw new Error('the honest fixture has no saml:Conditions');
      conditions.setAttribute('NotOnOrAfter', instant);

      const outcome = await consumeDocument(doc);
      expect(check(outcome, 'conditions-validity').passed).toBe(false);
      expect(outcome.authorized).toBe(false);
    }
  }, 60_000);

  it('rejects a malformed bearer-confirmation expiry', async () => {
    const doc = buildResponse(honestSpec());
    const assertion = honestAssertion(doc);
    const subject = childElements(assertion, NS.saml, 'Subject')[0];
    const confirmation = subject
      ? childElements(subject, NS.saml, 'SubjectConfirmation')[0]
      : null;
    const data = confirmation
      ? childElements(confirmation, NS.saml, 'SubjectConfirmationData')[0]
      : null;
    if (!data) throw new Error('the honest fixture has no SubjectConfirmationData');
    data.setAttribute('NotOnOrAfter', 'not-a-saml-instant');

    const outcome = await consumeDocument(doc);
    expect(check(outcome, 'confirmation-validity').passed).toBe(false);
    expect(outcome.authorized).toBe(false);
  }, 60_000);
});

describe('the control table as a whole', () => {
  it('has every control behave the way the page predicts', async () => {
    const rows = await runControls(parties);
    const unexpected = rows.filter((row) => !row.asExpected);
    expect(unexpected.map((row) => `${row.name} -> ${row.repairedLayer}`)).toEqual([]);
    expect(rows).toHaveLength(23);
  }, 120_000);

  it('lets the vulnerable consumer authorize an attacker in exactly the binding rows', async () => {
    const rows = await runControls(parties);
    const authorizing = rows.filter((row) =>
      row.vulnerableOutcome.startsWith('authorized admin@'),
    );
    // Both wrapping variants, and nothing else. Every other control is caught
    // by cryptography or by the profile, which both consumers run identically.
    expect(authorizing.map((row) => row.name)).toEqual([
      'XML Signature Wrapping',
      'An unsigned assertion placed first',
    ]);
    expect(authorizing.every((row) => row.family === 'binding')).toBe(true);
  }, 120_000);

  it('shows the repaired consumer getting the right answer, not merely refusing', async () => {
    const rows = await runControls(parties);
    const sibling = rows.find((row) => row.name === 'An unsigned assertion placed first');
    expect(sibling?.vulnerableOutcome).toBe('authorized admin@lab.invalid as administrator');
    expect(sibling?.repairedOutcome).toBe('authorized alice@lab.invalid as reader');
    expect(sibling?.asExpected).toBe(true);
  }, 120_000);

  it('separates signature-byte tampering from wrapping', async () => {
    const rows = await runControls(parties);
    const tamper = rows.find((row) => row.name === 'Signature bytes altered');
    const wrap = rows.find((row) => row.name === 'XML Signature Wrapping');
    expect(tamper?.family).toBe('signature');
    expect(tamper?.repairedLayer).toBe('L1 signature');
    expect(tamper?.vulnerableOutcome).toBe('refused at L1 signature');
    expect(wrap?.family).toBe('binding');
    expect(wrap?.repairedLayer).toBe('L2 binding');
    expect(wrap?.vulnerableOutcome).toMatch(/^authorized/);
  }, 120_000);
});
