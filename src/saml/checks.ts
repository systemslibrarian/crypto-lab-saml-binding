/**
 * L3 - SAML profile validation.
 *
 * Every rule here is evaluated on ONE assertion element handed in by the
 * caller. Which element that is, is L2's answer, and the whole lesson is that
 * these checks cannot repair a wrong answer: an attacker who supplies the
 * element also supplies its audience, its recipient and its InResponseTo, so a
 * forged assertion passes all of them.
 *
 * Sources, per rule, are carried in the result so the interface can show them.
 * The profile rules are saml-profiles-2.0-os (OASIS Standard, 15 March 2005)
 * section 4.1.4.2, 4.1.4.3 and 4.1.4.5 as replaced by SAML Version 2.0
 * Errata 05 (OASIS Approved Errata, 01 May 2012) item E26, and the condition
 * semantics are saml-core-2.0-os sections 2.5.1.2 and 2.5.1.4.
 */
import { NS, allElements, attr, childElements, textOf, type XmlElement } from './dom.js';
import { BEARER, CLOCK_SKEW_SECONDS, NOW_MS } from './profile.js';

export interface CheckResult {
  name: string;
  label: string;
  passed: boolean;
  expected: string;
  observed: string;
  source: string;
}

export interface ServiceProviderState {
  readonly entityId: string;
  readonly acsUrl: string;
  readonly trustedIssuer: string;
  /** The AuthnRequest this service provider is waiting for, or null. */
  readonly pendingRequestId: string | null;
  /** Assertion IDs already consumed, mapped to the instant they may be forgotten. */
  readonly consumed: Map<string, number>;
}

export function freshState(
  entityId: string,
  acsUrl: string,
  trustedIssuer: string,
  pendingRequestId: string | null,
): ServiceProviderState {
  return { entityId, acsUrl, trustedIssuer, pendingRequestId, consumed: new Map() };
}

function firstChild(parent: XmlElement | null, local: string): XmlElement | null {
  if (!parent) return null;
  return childElements(parent, NS.saml, local)[0] ?? null;
}

/** The bearer `<SubjectConfirmationData>` this profile's rules all speak about. */
function bearerConfirmationData(assertion: XmlElement): {
  confirmation: XmlElement | null;
  data: XmlElement | null;
  method: string | null;
} {
  const subject = firstChild(assertion, 'Subject');
  const confirmations = subject ? childElements(subject, NS.saml, 'SubjectConfirmation') : [];
  const confirmation = confirmations[0] ?? null;
  return {
    confirmation,
    data: confirmation ? firstChild(confirmation, 'SubjectConfirmationData') : null,
    method: confirmation ? attr(confirmation, 'Method') : null,
  };
}

export function subjectOf(assertion: XmlElement): string {
  const subject = firstChild(assertion, 'Subject');
  return textOf(firstChild(subject, 'NameID'));
}

function parseInstant(value: string | null): number | null {
  if (value === null) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * The profile checks, in the order the processing rules state them.
 *
 * `consume` is false while a document is only being inspected, so the replay
 * check can be evaluated without burning the assertion ID.
 */
export function runProfileChecks(
  assertion: XmlElement,
  state: ServiceProviderState,
  options: { consume: boolean },
): CheckResult[] {
  const results: CheckResult[] = [];
  const skewMs = CLOCK_SKEW_SECONDS * 1000;

  const issuer = textOf(firstChild(assertion, 'Issuer'));
  results.push({
    name: 'issuer',
    label: 'Issuer is the identity provider this service provider trusts',
    passed: issuer === state.trustedIssuer,
    expected: state.trustedIssuer,
    observed: issuer || 'absent',
    source: 'SAMLSec 6.4.3; SAMLProf 4.1.4.2',
  });

  const conditions = firstChild(assertion, 'Conditions');
  const restrictions = conditions
    ? childElements(conditions, NS.saml, 'AudienceRestriction')
    : [];
  const audiences = restrictions.flatMap((restriction) =>
    childElements(restriction, NS.saml, 'Audience').map((a) => textOf(a)),
  );
  results.push({
    name: 'audience',
    label: 'Audience restriction names this service provider',
    // Core 2.5.1.4: audiences inside one restriction are a disjunction, and
    // separate restrictions are a conjunction. With a single restriction the
    // two readings coincide, which is the only shape this profile emits.
    passed: restrictions.length > 0 && restrictions.every((restriction) =>
      childElements(restriction, NS.saml, 'Audience').some((a) => textOf(a) === state.entityId),
    ),
    expected: state.entityId,
    observed: audiences.length > 0 ? audiences.join(', ') : 'no AudienceRestriction',
    source: 'SAMLCore 2.5.1.4; SAMLProf 4.1.4.2',
  });

  const { data, method } = bearerConfirmationData(assertion);
  results.push({
    name: 'subject-confirmation-method',
    label: 'Subject confirmation is bearer',
    passed: method === BEARER,
    expected: BEARER,
    observed: method ?? 'absent',
    source: 'SAMLProf 4.1.4.2',
  });

  const nameId = subjectOf(assertion);
  results.push({
    name: 'subject-present',
    label: 'The assertion names a subject',
    passed: nameId.length > 0,
    expected: 'a non-empty saml:NameID',
    observed: nameId || 'absent',
    source: 'SAMLProf 4.1.4.2',
  });

  const confirmationNotBefore = attr(data, 'NotBefore');
  results.push({
    name: 'confirmation-notbefore-absent',
    label: 'SubjectConfirmationData carries no NotBefore',
    passed: confirmationNotBefore === null,
    expected: 'absent',
    observed: confirmationNotBefore ?? 'absent',
    source: 'SAMLProf 4.1.4.2 ("It MUST NOT contain a NotBefore attribute")',
  });

  const recipient = attr(data, 'Recipient');
  results.push({
    name: 'recipient',
    label: 'Recipient is the assertion consumer service URL the response arrived at',
    passed: recipient === state.acsUrl,
    expected: state.acsUrl,
    observed: recipient ?? 'absent',
    source: 'SAMLProf 4.1.4.3 (Errata 05 E26); SAMLSec 6.4.2',
  });

  const inResponseTo = attr(data, 'InResponseTo');
  const expectedRequest = state.pendingRequestId;
  results.push({
    name: 'in-response-to',
    label:
      expectedRequest === null
        ? 'An unsolicited response carries no InResponseTo'
        : 'InResponseTo equals the pending AuthnRequest ID',
    passed: expectedRequest === null ? inResponseTo === null : inResponseTo === expectedRequest,
    expected: expectedRequest ?? 'absent (unsolicited)',
    observed: inResponseTo ?? 'absent',
    source: 'SAMLProf 4.1.4.3 (Errata 05 E26); SAMLProf 4.1.5',
  });

  const notBefore = parseInstant(attr(conditions, 'NotBefore'));
  const notOnOrAfter = parseInstant(attr(conditions, 'NotOnOrAfter'));
  const conditionsValid =
    (notBefore === null || NOW_MS + skewMs >= notBefore) &&
    (notOnOrAfter === null || NOW_MS - skewMs < notOnOrAfter);
  results.push({
    name: 'conditions-validity',
    label: 'The assertion is inside its Conditions validity window',
    passed: conditionsValid,
    expected: `${attr(conditions, 'NotBefore') ?? 'unspecified'} ≤ now < ${
      attr(conditions, 'NotOnOrAfter') ?? 'unspecified'
    } (±${CLOCK_SKEW_SECONDS}s skew)`,
    observed: new Date(NOW_MS).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    source: 'SAMLCore 2.5.1.2',
  });

  const confirmationExpiry = parseInstant(attr(data, 'NotOnOrAfter'));
  results.push({
    name: 'confirmation-validity',
    label: 'The bearer confirmation window has not passed',
    passed: confirmationExpiry !== null && NOW_MS - skewMs < confirmationExpiry,
    expected: `now < ${attr(data, 'NotOnOrAfter') ?? 'absent'} (±${CLOCK_SKEW_SECONDS}s skew)`,
    observed: new Date(NOW_MS).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    source: 'SAMLProf 4.1.4.3 (Errata 05 E26); SAMLSec 6.4.1',
  });

  const assertionId = attr(assertion, 'ID') ?? '';
  const alreadyUsed = state.consumed.has(assertionId);
  results.push({
    name: 'single-use',
    label: 'This assertion ID has not been consumed before',
    passed: !alreadyUsed,
    expected: 'an ID not in the consumed set',
    observed: alreadyUsed ? `${assertionId} was already consumed` : assertionId || 'absent',
    source: 'SAMLProf 4.1.4.5; SAMLSec 6.4.4, 6.4.5',
  });

  // Only a run that otherwise succeeds burns the ID. Recording a replayed or
  // rejected assertion would let a rejected document poison a later honest one.
  if (options.consume && !alreadyUsed && results.every((r) => r.passed)) {
    const expiry = confirmationExpiry ?? NOW_MS;
    state.consumed.set(assertionId, expiry);
  }

  return results;
}

/** Response-level checks that do not depend on which assertion was selected. */
export function checkResponseDestination(
  responseRoot: XmlElement,
  state: ServiceProviderState,
): CheckResult {
  const destination = attr(responseRoot, 'Destination');
  return {
    name: 'destination',
    label: 'Response Destination is this assertion consumer service URL',
    passed: destination === state.acsUrl,
    expected: state.acsUrl,
    observed: destination ?? 'absent',
    source: 'SAMLCore 3.2.2; SAMLBind 3.5',
  };
}

export function statusOf(responseRoot: XmlElement): string {
  const status = childElements(responseRoot, NS.samlp, 'Status')[0] ?? null;
  const code = status ? childElements(status, NS.samlp, 'StatusCode')[0] : null;
  return attr(code ?? null, 'Value') ?? 'absent';
}

export function assertionsInDocumentOrder(doc: unknown): XmlElement[] {
  return allElements(doc, NS.saml, 'Assertion');
}
