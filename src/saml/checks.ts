/**
 * L3 - SAML profile validation.
 *
 * Every assertion-level rule in `runProfileChecks` is evaluated on ONE assertion handed in by the
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

interface ConfirmationCandidate {
  confirmation: XmlElement | null;
  data: XmlElement | null;
  method: string | null;
  notBefore: string | null;
  recipient: string | null;
  inResponseTo: string | null;
  expiryRaw: string | null;
  expiry: number | null;
  accepted: boolean;
}

function parseInstant(value: string | null): number | null {
  if (value === null) return null;
  // SAML Core 1.3.3 requires UTC and the canonical `Z` timezone form. Keep the
  // parser narrower than Date.parse, which accepts many strings that are not
  // SAML time values.
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/.exec(value);
  if (!match) return null;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    year === 0 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > (days[month - 1] ?? 0) ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return null;
  }
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * Select one complete bearer confirmation tuple.
 *
 * Errata 05 E26 permits several SubjectConfirmation elements and says one
 * successful evaluation is enough. The fields may not be mixed across them:
 * the method, forbidden NotBefore, Recipient, InResponseTo and expiry below
 * must all belong to the same candidate.
 */
function bearerConfirmationData(
  assertion: XmlElement,
  state: ServiceProviderState,
  skewMs: number,
): ConfirmationCandidate {
  const subject = firstChild(assertion, 'Subject');
  const confirmations = subject ? childElements(subject, NS.saml, 'SubjectConfirmation') : [];
  const candidates = confirmations.map((confirmation): ConfirmationCandidate => {
    const data = firstChild(confirmation, 'SubjectConfirmationData');
    const method = attr(confirmation, 'Method');
    const notBefore = attr(data, 'NotBefore');
    const recipient = attr(data, 'Recipient');
    const inResponseTo = attr(data, 'InResponseTo');
    const expiryRaw = attr(data, 'NotOnOrAfter');
    const expiry = parseInstant(expiryRaw);
    const requestMatches =
      state.pendingRequestId === null
        ? inResponseTo === null
        : inResponseTo === state.pendingRequestId;
    const accepted =
      method === BEARER &&
      notBefore === null &&
      recipient === state.acsUrl &&
      requestMatches &&
      expiry !== null &&
      NOW_MS - skewMs < expiry;
    return {
      confirmation,
      data,
      method,
      notBefore,
      recipient,
      inResponseTo,
      expiryRaw,
      expiry,
      accepted,
    };
  });

  return (
    candidates.find((candidate) => candidate.accepted) ??
    candidates.find((candidate) => candidate.method === BEARER) ??
    candidates[0] ?? {
      confirmation: null,
      data: null,
      method: null,
      notBefore: null,
      recipient: null,
      inResponseTo: null,
      expiryRaw: null,
      expiry: null,
      accepted: false,
    }
  );
}

export function subjectOf(assertion: XmlElement): string {
  const subject = firstChild(assertion, 'Subject');
  return textOf(firstChild(subject, 'NameID'));
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

  const confirmation = bearerConfirmationData(assertion, state, skewMs);
  const { method } = confirmation;
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

  const authnStatements = childElements(assertion, NS.saml, 'AuthnStatement');
  results.push({
    name: 'authentication-statement-present',
    label: 'The selected assertion contains an authentication statement',
    passed: authnStatements.length > 0,
    expected: 'at least one direct saml:AuthnStatement',
    observed: `${authnStatements.length} direct saml:AuthnStatement element(s)`,
    source: 'SAMLProf 4.1.4.2 (Errata 05 E26); bounded one-assertion adaptation',
  });

  const confirmationNotBefore = confirmation.notBefore;
  results.push({
    name: 'confirmation-notbefore-absent',
    label: 'SubjectConfirmationData carries no NotBefore',
    passed: confirmationNotBefore === null,
    expected: 'absent',
    observed: confirmationNotBefore ?? 'absent',
    source: 'SAMLProf 4.1.4.2 ("It MUST NOT contain a NotBefore attribute")',
  });

  const recipient = confirmation.recipient;
  results.push({
    name: 'recipient',
    label: 'Recipient is the assertion consumer service URL the response arrived at',
    passed: recipient === state.acsUrl,
    expected: state.acsUrl,
    observed: recipient ?? 'absent',
    source: 'SAMLProf 4.1.4.3 (Errata 05 E26); SAMLSec 6.4.2',
  });

  const inResponseTo = confirmation.inResponseTo;
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

  const notBeforeRaw = attr(conditions, 'NotBefore');
  const notOnOrAfterRaw = attr(conditions, 'NotOnOrAfter');
  const notBefore = parseInstant(notBeforeRaw);
  const notOnOrAfter = parseInstant(notOnOrAfterRaw);
  const conditionsValid =
    (notBeforeRaw === null || (notBefore !== null && NOW_MS + skewMs >= notBefore)) &&
    (notOnOrAfterRaw === null ||
      (notOnOrAfter !== null && NOW_MS - skewMs < notOnOrAfter));
  results.push({
    name: 'conditions-validity',
    label: 'The assertion is inside its Conditions validity window',
    passed: conditionsValid,
    expected: `${notBeforeRaw ?? 'unspecified'} ≤ now < ${
      notOnOrAfterRaw ?? 'unspecified'
    } (valid UTC SAML instants; ±${CLOCK_SKEW_SECONDS}s skew)`,
    observed: new Date(NOW_MS).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    source: 'SAMLCore 2.5.1.2',
  });

  const confirmationExpiry = confirmation.expiry;
  results.push({
    name: 'confirmation-validity',
    label: 'The bearer confirmation window has not passed',
    passed: confirmationExpiry !== null && NOW_MS - skewMs < confirmationExpiry,
    expected: `now < ${confirmation.expiryRaw ?? 'absent'} (valid UTC SAML instant; ±${CLOCK_SKEW_SECONDS}s skew)`,
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

/**
 * Correlate the protocol Response itself with the request held in local state.
 *
 * This is separate from SubjectConfirmationData.InResponseTo. SAML Core
 * 3.2.2 requires the Response attribute when a response answers a request,
 * while Profiles 4.1.5 forbids it on an unsolicited response. Checking only
 * the assertion-level copy leaves the unsigned Response field unchecked.
 */
export function checkResponseInResponseTo(
  responseRoot: XmlElement,
  state: ServiceProviderState,
): CheckResult {
  const inResponseTo = attr(responseRoot, 'InResponseTo');
  const expectedRequest = state.pendingRequestId;
  const responseMatchesRequest =
    expectedRequest === null ? inResponseTo === null : inResponseTo === expectedRequest;
  return {
    name: 'response-in-response-to',
    label:
      expectedRequest === null
        ? 'An unsolicited Response carries no InResponseTo'
        : 'Response InResponseTo equals the pending AuthnRequest ID',
    passed: responseMatchesRequest,
    expected: expectedRequest ?? 'absent (unsolicited)',
    observed: inResponseTo ?? 'absent',
    source: 'SAMLCore 3.2.2; SAMLProf 4.1.5',
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
