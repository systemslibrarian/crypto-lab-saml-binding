/**
 * Building the synthetic response.
 *
 * Every negative case in this lab is produced by varying this specification and
 * re-signing, never by editing serialized XML with string replacement. The
 * difference matters: a string edit cannot distinguish a document the identity
 * provider would really have issued from one nobody could have issued, so a
 * "wrong audience" case built that way would silently also be a broken
 * signature, and the test would pass for the wrong reason.
 *
 * The one place this lab does edit a signed document is the attacker's, in
 * attacks.ts, which is exactly where an attacker's edits belong.
 */
import { NS, parseXml, type XmlDocument } from './dom.js';
import {
  ACS_URL,
  AUTHN_PASSWORD_PROTECTED,
  BEARER,
  IDP_ENTITY_ID,
  NAMEID_EMAIL,
  NAMEID_ENTITY,
  NOW_MS,
  SP_ENTITY_ID,
  STATUS_SUCCESS,
} from './profile.js';

export interface ResponseSpec {
  responseId: string;
  assertionId: string;
  issuer: string;
  destination: string;
  /** The AuthnRequest this answers, or null for an unsolicited response. */
  inResponseTo: string | null;
  recipient: string;
  audience: string;
  nameId: string;
  subjectConfirmationMethod: string;
  /** Seconds either side of the frozen instant. */
  notBeforeOffsetSeconds: number;
  notOnOrAfterOffsetSeconds: number;
  confirmationNotOnOrAfterOffsetSeconds: number;
  /** Forbidden by Profiles 4.1.4.2; present only in the negative control. */
  confirmationNotBeforeOffsetSeconds: number | null;
  sessionIndex: string;
}

export function iso(offsetSeconds: number): string {
  return new Date(NOW_MS + offsetSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function honestSpec(): ResponseSpec {
  return {
    responseId: '_s12response0000000000000000000001',
    assertionId: '_s12assertion000000000000000000001',
    issuer: IDP_ENTITY_ID,
    destination: ACS_URL,
    inResponseTo: '_s12authnrequest00000000000000001',
    recipient: ACS_URL,
    audience: SP_ENTITY_ID,
    nameId: 'alice@lab.invalid',
    subjectConfirmationMethod: BEARER,
    notBeforeOffsetSeconds: -120,
    notOnOrAfterOffsetSeconds: 300,
    confirmationNotOnOrAfterOffsetSeconds: 300,
    confirmationNotBeforeOffsetSeconds: null,
    sessionIndex: '_s12session00000000000000000000001',
  };
}

function esc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * The document the identity provider emits, before signing.
 *
 * Laid out in the SAML schema's own element order, with the `<ds:Signature>`
 * slot left for sign.ts to fill immediately after `<saml:Issuer>`.
 */
export function buildResponseXml(spec: ResponseSpec): string {
  const confirmationNotBefore =
    spec.confirmationNotBeforeOffsetSeconds === null
      ? ''
      : ` NotBefore="${iso(spec.confirmationNotBeforeOffsetSeconds)}"`;
  const inResponseToResponse =
    spec.inResponseTo === null ? '' : ` InResponseTo="${esc(spec.inResponseTo)}"`;
  const inResponseToConfirmation =
    spec.inResponseTo === null ? '' : ` InResponseTo="${esc(spec.inResponseTo)}"`;

  return (
    `<samlp:Response xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}"` +
    ` ID="${esc(spec.responseId)}" Version="2.0" IssueInstant="${iso(0)}"` +
    ` Destination="${esc(spec.destination)}"${inResponseToResponse}>` +
    `<saml:Issuer Format="${NAMEID_ENTITY}">${esc(spec.issuer)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="${STATUS_SUCCESS}"/></samlp:Status>` +
    `<saml:Assertion ID="${esc(spec.assertionId)}" Version="2.0" IssueInstant="${iso(0)}">` +
    `<saml:Issuer Format="${NAMEID_ENTITY}">${esc(spec.issuer)}</saml:Issuer>` +
    `<saml:Subject>` +
    `<saml:NameID Format="${NAMEID_EMAIL}">${esc(spec.nameId)}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="${esc(spec.subjectConfirmationMethod)}">` +
    `<saml:SubjectConfirmationData${confirmationNotBefore}` +
    ` NotOnOrAfter="${iso(spec.confirmationNotOnOrAfterOffsetSeconds)}"` +
    ` Recipient="${esc(spec.recipient)}"${inResponseToConfirmation}/>` +
    `</saml:SubjectConfirmation>` +
    `</saml:Subject>` +
    `<saml:Conditions NotBefore="${iso(spec.notBeforeOffsetSeconds)}"` +
    ` NotOnOrAfter="${iso(spec.notOnOrAfterOffsetSeconds)}">` +
    `<saml:AudienceRestriction><saml:Audience>${esc(spec.audience)}</saml:Audience>` +
    `</saml:AudienceRestriction>` +
    `</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${iso(-30)}"` +
    ` SessionIndex="${esc(spec.sessionIndex)}">` +
    `<saml:AuthnContext>` +
    `<saml:AuthnContextClassRef>${AUTHN_PASSWORD_PROTECTED}</saml:AuthnContextClassRef>` +
    `</saml:AuthnContext>` +
    `</saml:AuthnStatement>` +
    `</saml:Assertion>` +
    `</samlp:Response>`
  );
}

export function buildResponse(spec: ResponseSpec): XmlDocument {
  return parseXml(buildResponseXml(spec));
}
