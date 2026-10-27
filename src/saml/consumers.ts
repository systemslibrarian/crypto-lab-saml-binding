/**
 * The two service providers.
 *
 * They differ at one security boundary, and it is not a UI control, a schema check
 * or a better query. It is the SHAPE OF THE VERIFICATION API:
 *
 *   vulnerable:  const ok = await verify(document);        // boolean
 *                const assertion = document.find(...);     // ask again
 *
 *   repaired:    const assertion = await verify(document); // the element
 *
 * Everything downstream of that line is identical - the same profile checks,
 * the same authorization table, the same code. So any difference in outcome is
 * attributable to the one difference, which is what makes this a comparison
 * rather than two programs.
 */
import { NS, allElements, attr, parseXml, type XmlElement } from './dom.js';
import {
  assertionsInDocumentOrder,
  checkResponseDestination,
  checkResponseInResponseTo,
  runProfileChecks,
  statusOf,
  subjectOf,
  type CheckResult,
  type ServiceProviderState,
} from './checks.js';
import { libraryVerify, verifyBound, type BindingFailure, type BoundVerification } from './verify.js';
import { STATUS_SUCCESS, rightsOf } from './profile.js';

export type Layer = 'L1 signature' | 'L2 binding' | 'L3 profile' | 'L4 authorization';

export interface ConsumeOutcome {
  consumer: 'vulnerable' | 'repaired';
  /** Did the consumer establish a security context, and for whom? */
  authorized: boolean;
  subject: string | null;
  role: string | null;
  rights: readonly string[];
  /** Which layer stopped it, when it stopped. */
  failedLayer: Layer | null;
  reason: string | null;
  /** L1 as the consumer itself observed it. */
  signatureVerified: boolean;
  /** The ID of the assertion the consumer actually read. */
  selectedAssertionId: string | null;
  /** The ID of the assertion the signature actually covered, where known. */
  verifiedAssertionId: string | null;
  checks: CheckResult[];
  bindingFailures: BindingFailure[];
  /** How the consumer chose its assertion, in its own words. */
  selectionMethod: string;
}

function roleFor(nameId: string): string {
  // A deliberately boring directory. The lesson is upstream of it.
  return nameId.startsWith('admin@') ? 'administrator' : 'reader';
}

function emptyOutcome(consumer: 'vulnerable' | 'repaired', selectionMethod: string): ConsumeOutcome {
  return {
    consumer,
    authorized: false,
    subject: null,
    role: null,
    rights: [],
    failedLayer: null,
    reason: null,
    signatureVerified: false,
    selectedAssertionId: null,
    verifiedAssertionId: null,
    checks: [],
    bindingFailures: [],
    selectionMethod,
  };
}

/**
 * Run the response-level and assertion-level profile rules as one transaction.
 * The assertion ID may be recorded only when both groups pass; otherwise a
 * response with a bad Destination, request correlation or Status could poison
 * a later honest use of the same assertion.
 */
function profileChecks(
  root: XmlElement,
  assertion: XmlElement,
  state: ServiceProviderState,
): CheckResult[] {
  const destination = checkResponseDestination(root, state);
  const responseInResponseTo = checkResponseInResponseTo(root, state);
  const status = statusOf(root);
  const statusCheck: CheckResult = {
    name: 'status',
    label: 'Response status is Success',
    passed: status === STATUS_SUCCESS,
    expected: STATUS_SUCCESS,
    observed: status,
    source: 'SAMLCore 3.2.2.2',
  };
  const responsePassed = destination.passed && responseInResponseTo.passed && statusCheck.passed;
  return [
    destination,
    responseInResponseTo,
    statusCheck,
    ...runProfileChecks(assertion, state, { consume: responsePassed }),
  ];
}

/**
 * The deliberately vulnerable consumer.
 *
 * It is not careless about cryptography: it really verifies, with a real
 * library, against the right trust anchor, and it runs all profile checks
 * implemented by this declared teaching subset. Its deliberate defect is
 * the one Somorovsky et al. section 8 names - it
 * asks the library a yes/no question and then asks the DOCUMENT, separately,
 * which assertion to use.
 *
 * This is the brief's permitted anti-pattern, and it is labelled as such
 * wherever it is shown.
 */
export async function vulnerableConsume(
  xml: string,
  trustedKey: CryptoKey,
  state: ServiceProviderState,
): Promise<ConsumeOutcome> {
  const outcome = emptyOutcome(
    'vulnerable',
    'getElementsByTagNameNS(saml, "Assertion")[0] - a second, independent query',
  );
  const doc = parseXml(xml);

  const library = await libraryVerify(doc, trustedKey);
  outcome.signatureVerified = library.verified;
  if (!library.verified) {
    outcome.failedLayer = 'L1 signature';
    outcome.reason = library.error ?? 'the XML signature did not verify';
    return outcome;
  }

  const root = doc.documentElement as unknown as XmlElement;
  // The defect, in one line.
  const assertion = assertionsInDocumentOrder(doc)[0];
  if (!assertion) {
    outcome.failedLayer = 'L3 profile';
    outcome.reason = 'the response carries no assertion';
    return outcome;
  }
  outcome.selectedAssertionId = attr(assertion, 'ID');

  const checks = profileChecks(root, assertion, state);
  outcome.checks = checks;

  const failed = checks.find((check) => !check.passed);
  if (failed) {
    outcome.failedLayer = 'L3 profile';
    outcome.reason = `${failed.label}: expected ${failed.expected}, saw ${failed.observed}`;
    return outcome;
  }

  const subject = subjectOf(assertion);
  outcome.authorized = true;
  outcome.subject = subject;
  outcome.role = roleFor(subject);
  outcome.rights = rightsOf(outcome.role);
  return outcome;
}

/**
 * The repaired consumer.
 *
 * `verifyBound` hands back the element, so there is no second query to get
 * wrong, and it refuses outright every document in which "which element" has
 * more than one answer. The profile checks and the authorization table below
 * are the same code the vulnerable consumer runs.
 */
export async function repairedConsume(
  xml: string,
  trustedKey: CryptoKey,
  state: ServiceProviderState,
): Promise<ConsumeOutcome & { verification: BoundVerification }> {
  const outcome = emptyOutcome(
    'repaired',
    'the element returned by verification - no second query exists',
  );
  const verification = await verifyBound(xml, trustedKey);
  outcome.signatureVerified =
    verification.libraryVerified &&
    (verification.recomputed?.digestMatches ?? false) &&
    (verification.recomputed?.signatureValid ?? false);
  outcome.bindingFailures = verification.failures;
  outcome.verifiedAssertionId = verification.verifiedElementId;

  if (!verification.verifiedElement) {
    const first = verification.failures[0];
    const cryptographic =
      first &&
      (first.rule === 'signature-invalid' ||
        first.rule === 'digest-mismatch' ||
        first.rule === 'library-verification-failed');
    outcome.failedLayer = cryptographic ? 'L1 signature' : 'L2 binding';
    outcome.reason = first ? `${first.rule}: ${first.detail}` : 'verification produced no element';
    return { ...outcome, verification };
  }

  const assertion = verification.verifiedElement;
  outcome.selectedAssertionId = attr(assertion, 'ID');

  const root = parseXml(xml).documentElement as unknown as XmlElement;
  const checks = profileChecks(root, assertion, state);
  outcome.checks = checks;

  const failed = checks.find((check) => !check.passed);
  if (failed) {
    outcome.failedLayer = 'L3 profile';
    outcome.reason = `${failed.label}: expected ${failed.expected}, saw ${failed.observed}`;
    return { ...outcome, verification };
  }

  const subject = subjectOf(assertion);
  outcome.authorized = true;
  outcome.subject = subject;
  outcome.role = roleFor(subject);
  outcome.rights = rightsOf(outcome.role);
  return { ...outcome, verification };
}

/** How many assertions a document carries, for the structural panel. */
export function assertionCensus(xml: string): { id: string | null; subject: string; depth: number }[] {
  const doc = parseXml(xml);
  return allElements(doc, NS.saml, 'Assertion').map((assertion) => {
    let depth = 0;
    let node: unknown = (assertion as unknown as { parentNode: unknown }).parentNode;
    while (node && (node as { nodeType: number }).nodeType === 1) {
      depth += 1;
      node = (node as { parentNode: unknown }).parentNode;
    }
    return { id: attr(assertion, 'ID'), subject: subjectOf(assertion), depth };
  });
}
