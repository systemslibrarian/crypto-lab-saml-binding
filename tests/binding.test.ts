import { beforeAll, describe, expect, it } from 'vitest';
import { buildResponse, honestSpec } from '../src/saml/build.js';
import { issueSignedResponse, newParties, type Parties } from '../src/saml/lesson.js';
import { signResponse } from '../src/saml/sign.js';
import { verifyBound } from '../src/saml/verify.js';
import {
  addUnsupportedTransform,
  duplicateAssertionId,
  removeReferencedId,
  wrapInAdvice,
} from '../src/saml/attacks.js';
import { NS, allElements, parseXml, serializeXml } from '../src/saml/dom.js';

/**
 * L2 - node and reference binding.
 *
 * These are the rules no signature library answers for the application, plus
 * the two it happens to answer here. Both kinds are asserted, because "the
 * dependency already does this" is a claim that has to be checked and then
 * stated, not assumed.
 */

let parties: Parties;
let signed: string;

beforeAll(async () => {
  parties = await newParties();
  signed = await issueSignedResponse(parties, honestSpec());
}, 60_000);

function rules(failures: { rule: string }[]): string[] {
  return failures.map((failure) => failure.rule);
}

describe('reference resolution', () => {
  it('returns the element, not a boolean, when everything is in order', async () => {
    const result = await verifyBound(signed, parties.idp.publicKey);
    expect(result.verifiedElement).not.toBeNull();
    expect(result.verifiedElementId).toBe(honestSpec().assertionId);
    expect(result.verifiedElement?.localName).toBe('Assertion');
    expect(result.verifiedElement?.namespaceURI).toBe(NS.saml);
  }, 60_000);

  it('refuses a reference that resolves to nothing, before any cryptography runs', async () => {
    const result = await verifyBound(removeReferencedId(signed, honestSpec()), parties.idp.publicKey);
    expect(rules(result.failures)).toContain('reference-unresolved');
    expect(result.independent).toBeNull();
    expect(result.libraryError).toMatch(/not attempted/);
  }, 60_000);

  it('refuses two elements carrying one ID', async () => {
    const result = await verifyBound(
      duplicateAssertionId(signed, honestSpec(), 'admin@lab.invalid'),
      parties.idp.publicKey,
    );
    expect(rules(result.failures)).toEqual(['reference-ambiguous']);
    expect(result.verifiedElement).toBeNull();
  }, 60_000);

  it('refuses a URI that is not a same-document reference', async () => {
    const doc = parseXml(signed);
    const reference = allElements(doc, NS.ds, 'Reference')[0];
    reference?.setAttribute('URI', 'https://idp.lab.invalid/assertion.xml');
    const result = await verifyBound(serializeXml(doc), parties.idp.publicKey);
    expect(rules(result.failures)).toContain('reference-uri-not-same-document');
    expect(result.independent).toBeNull();
  }, 60_000);

  it('refuses an empty URI, which would mean the whole document', async () => {
    const doc = parseXml(signed);
    allElements(doc, NS.ds, 'Reference')[0]?.setAttribute('URI', '');
    const result = await verifyBound(serializeXml(doc), parties.idp.publicKey);
    expect(rules(result.failures)).toContain('reference-uri-not-same-document');
  }, 60_000);
});

describe('the declared algorithm and structure subset', () => {
  it('refuses a third transform', async () => {
    const result = await verifyBound(addUnsupportedTransform(signed), parties.idp.publicKey);
    expect(rules(result.failures)).toContain('transforms-unsupported');
    expect(result.independent).toBeNull();
  }, 60_000);

  it('refuses an unsupported signature algorithm', async () => {
    const doc = parseXml(signed);
    allElements(doc, NS.ds, 'SignatureMethod')[0]?.setAttribute(
      'Algorithm',
      'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    );
    const result = await verifyBound(serializeXml(doc), parties.idp.publicKey);
    expect(rules(result.failures)).toContain('signature-method-unsupported');
  }, 60_000);

  it('refuses inclusive canonicalization in SignedInfo', async () => {
    const doc = parseXml(signed);
    allElements(doc, NS.ds, 'CanonicalizationMethod')[0]?.setAttribute(
      'Algorithm',
      'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
    );
    const result = await verifyBound(serializeXml(doc), parties.idp.publicKey);
    expect(rules(result.failures)).toContain('canonicalization-unsupported');
  }, 60_000);

  it('refuses a second signature', async () => {
    const doc = parseXml(signed);
    const signature = allElements(doc, NS.ds, 'Signature')[0];
    const clone = (signature as unknown as { cloneNode: (deep: boolean) => unknown }).cloneNode(true);
    (doc.documentElement as unknown as { appendChild: (n: unknown) => void }).appendChild(clone);
    const result = await verifyBound(serializeXml(doc), parties.idp.publicKey);
    expect(rules(result.failures)).toContain('signature-not-unique');
  }, 60_000);

  it('refuses a document with no signature at all', async () => {
    const result = await verifyBound(
      serializeXml(buildResponse(honestSpec())),
      parties.idp.publicKey,
    );
    expect(rules(result.failures)).toEqual(['signature-absent']);
  }, 60_000);
});

describe('name and position, per W3C XML Signature Best Practice 14', () => {
  it('refuses a verified node nested where the response does not deliver it', async () => {
    const result = await verifyBound(
      wrapInAdvice(signed, honestSpec(), 'admin@lab.invalid'),
      parties.idp.publicKey,
    );
    expect(rules(result.failures)).toEqual(['verified-node-wrong-position']);
    // Everything cryptographic still passes. That is the whole point.
    expect(result.independent?.digestMatches).toBe(true);
    expect(result.independent?.signatureValid).toBe(true);
    expect(result.libraryVerified).toBe(true);
  }, 60_000);

  it('refuses a signature over the Response, which this profile does not implement', async () => {
    // Errata 05 E26 permits signing the Response instead of each assertion.
    // This profile implements the assertion case only, so the other shape is
    // refused by name rather than silently accepted.
    const spec = honestSpec();
    const xml = await signResponse(buildResponse(spec), parties.idp.privateKey, {
      referenceId: spec.responseId,
      placeInside: 'response-root',
    });
    const result = await verifyBound(xml, parties.idp.publicKey);
    expect(rules(result.failures)).toEqual(['verified-node-wrong-name']);
    expect(result.independent?.signatureValid).toBe(true);
  }, 60_000);
});
