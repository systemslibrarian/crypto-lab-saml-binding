import { beforeAll, describe, expect, it, vi } from 'vitest';
import * as xmldsig from 'xmldsigjs';
import { honestSpec } from '../src/saml/build.js';
import { issueSignedResponse, newParties, type Parties } from '../src/saml/lesson.js';
import { libraryVerify, verifyBound } from '../src/saml/verify.js';
import { parseXml } from '../src/saml/dom.js';
import { fromBase64, utf8 } from '../src/saml/bytes.js';
import { WEBCRYPTO_ALGORITHM } from '../src/saml/keys.js';
import { tamperSignatureBytes, tamperSignedSubject } from '../src/saml/attacks.js';
import { ACCEPTED } from '../src/saml/profile.js';
import { canonicalize } from '../src/saml/verify.js';
import { NS, allElements } from '../src/saml/dom.js';

/**
 * L1 - signature validation.
 *
 * The lab's bounded recomputation and the dependency's answer are both
 * asserted here, and asserted to agree. The paths share the XML parser and
 * canonicalizer, so the hand-derived canonicalization vectors are the separate
 * anchor for that shared machinery.
 */

let parties: Parties;
let signed: string;

beforeAll(async () => {
  parties = await newParties();
  signed = await issueSignedResponse(parties, honestSpec());
}, 60_000);

describe('the signature the identity provider produced', () => {
  it('declares exactly the enforced signature subset', async () => {
    const result = await verifyBound(signed, parties.idp.publicKey);
    expect(result.structure.signatureCount).toBe(1);
    expect(result.structure.referenceCount).toBe(1);
    expect(result.structure.referenceUri).toBe(`#${honestSpec().assertionId}`);
    expect(result.structure.signatureMethod).toBe(ACCEPTED.signatureMethod);
    expect(result.structure.digestMethod).toBe(ACCEPTED.digestMethod);
    expect(result.structure.canonicalization).toBe(ACCEPTED.canonicalization);
    expect(result.structure.transforms).toEqual([
      ACCEPTED.envelopedTransform,
      ACCEPTED.excC14nTransform,
    ]);
  }, 60_000);

  it('verifies, and this lab and the dependency agree that it does', async () => {
    const result = await verifyBound(signed, parties.idp.publicKey);
    expect(result.failures).toEqual([]);
    expect(result.recomputed?.digestMatches).toBe(true);
    expect(result.recomputed?.signatureValid).toBe(true);
    expect(result.libraryVerified).toBe(true);
  }, 60_000);

  it('fails closed if the dependency and bounded recomputation disagree', async () => {
    const verify = vi.spyOn(xmldsig.SignedXml.prototype, 'Verify').mockResolvedValue(false);
    try {
      const result = await verifyBound(signed, parties.idp.publicKey);
      expect(result.recomputed?.digestMatches).toBe(true);
      expect(result.recomputed?.signatureValid).toBe(true);
      expect(result.libraryVerified).toBe(false);
      expect(result.failures.map((failure) => failure.rule)).toContain(
        'library-verification-failed',
      );
      expect(result.verifiedElement).toBeNull();
    } finally {
      verify.mockRestore();
    }
  }, 60_000);

  it('verifies when Web Crypto is driven separately after canonicalization', async () => {
    // Signature validation redone from the canonicalized bytes: verify
    // RSASSA-PKCS1-v1_5 directly through Web Crypto. This intentionally shares
    // the canonicalizer, whose bytes are pinned by canonicalization.test.ts,
    // but does not call SignedXml.Verify or the lab's bound verifier.
    const doc = parseXml(signed);
    const signedInfo = allElements(doc, NS.ds, 'SignedInfo')[0];
    const signatureValue = allElements(doc, NS.ds, 'SignatureValue')[0];
    const bytes = fromBase64((signatureValue?.textContent ?? '').trim());
    const canonical = canonicalize(signedInfo);
    const ok = await crypto.subtle.verify(
      WEBCRYPTO_ALGORITHM as never,
      parties.idp.publicKey,
      bytes as unknown as BufferSource,
      utf8(canonical) as unknown as BufferSource,
    );
    expect(ok).toBe(true);
    expect(canonical).toContain(ACCEPTED.signatureMethod);
  }, 60_000);

  it('does not verify under a key that did not produce it', async () => {
    const result = await verifyBound(signed, parties.attacker.publicKey);
    expect(result.recomputed?.signatureValid).toBe(false);
    expect(result.failures.map((f) => f.rule)).toContain('signature-invalid');
    // The digest is over the document, not the key, so it still matches: these
    // are two separate properties and the lab reports them separately.
    expect(result.recomputed?.digestMatches).toBe(true);
  }, 60_000);
});

describe('tampering, which is not the wrapping lesson', () => {
  it('fails the SIGNATURE when the signature bytes are altered', async () => {
    const result = await verifyBound(tamperSignatureBytes(signed), parties.idp.publicKey);
    expect(result.recomputed?.digestMatches).toBe(true);
    expect(result.recomputed?.signatureValid).toBe(false);
    expect(result.libraryVerified).toBe(false);
  }, 60_000);

  it('fails the DIGEST when the signed payload is altered', async () => {
    const result = await verifyBound(
      tamperSignedSubject(signed, 'admin@lab.invalid'),
      parties.idp.publicKey,
    );
    expect(result.recomputed?.digestMatches).toBe(false);
    // SignedInfo itself was not touched, so the signature over it still checks
    // out. Reference validation is what catches this, per XMLDSIG 1.1 3.2.1.
    expect(result.recomputed?.signatureValid).toBe(true);
    expect(result.libraryVerified).toBe(false);
    expect(result.failures.map((f) => f.rule)).toContain('digest-mismatch');
  }, 60_000);

  it('is caught by the dependency on its own, with no help from this lab', async () => {
    const library = await libraryVerify(
      parseXml(tamperSignatureBytes(signed)),
      parties.idp.publicKey,
    );
    expect(library.verified).toBe(false);
  }, 60_000);
});
