/**
 * The synthetic identity provider's signing step.
 *
 * Enveloped, one same-document reference, exclusive canonicalization in both
 * places, exactly two transforms, RSA-SHA256 — the subset declared in
 * profile.ts, which is SAML Core 5.4 read at its strictest.
 */
import './dom.js';
import * as xmldsig from 'xmldsigjs';
import { NS, allElements, childElements, serializeXml, type XmlDocument } from './dom.js';
import { ACCEPTED } from './profile.js';
import { WEBCRYPTO_ALGORITHM } from './keys.js';

let engineReady = false;

function ensureEngine(): void {
  if (engineReady) return;
  xmldsig.Application.setEngine('S12', globalThis.crypto);
  engineReady = true;
}

export interface SignOptions {
  /** The ID of the element to reference, without the leading '#'. */
  referenceId: string;
  /** Where the enveloped `<ds:Signature>` is placed. */
  placeInside: 'referenced-element' | 'response-root';
}

/**
 * Sign, and return the serialized document.
 *
 * The signature goes immediately after `<saml:Issuer>` inside the assertion,
 * which is where the SAML assertion schema's sequence puts it.
 */
export async function signResponse(
  doc: XmlDocument,
  privateKey: CryptoKey,
  options: SignOptions,
): Promise<string> {
  ensureEngine();

  const signed = new xmldsig.SignedXml(doc as never);
  // The library defaults SignedInfo to inclusive canonicalization. Core 5.4.3
  // asks for exclusive in BOTH places, so this is set before signing rather
  // than left at the default.
  signed.XmlSignature.SignedInfo.CanonicalizationMethod.Algorithm = ACCEPTED.canonicalization;

  await signed.Sign(WEBCRYPTO_ALGORITHM as never, privateKey, doc as never, {
    references: [
      {
        uri: `#${options.referenceId}`,
        hash: 'SHA-256',
        transforms: ['enveloped', 'exc-c14n'],
      },
    ],
  });

  const signatureNode = signed.XmlSignature.GetXml();
  if (!signatureNode) throw new Error('the signing step produced no ds:Signature element');

  const host =
    options.placeInside === 'response-root'
      ? (doc.documentElement as never)
      : (findById(doc, options.referenceId) as never);
  if (!host) throw new Error(`no element carries ID ${options.referenceId}`);

  const issuers = childElements(host, NS.saml, 'Issuer');
  const anchor = issuers.length > 0 ? (issuers[0] as never) : null;
  const after = anchor ? ((anchor as { nextSibling: unknown }).nextSibling as never) : null;
  (host as { insertBefore: (a: unknown, b: unknown) => void }).insertBefore(
    signatureNode,
    after ?? null,
  );

  return serializeXml(doc);
}

/** First element carrying the SAML identifier attribute `ID`. */
export function findById(doc: XmlDocument, id: string): unknown | null {
  const all = (doc as unknown as { getElementsByTagName: (n: string) => ArrayLike<unknown> })
    .getElementsByTagName('*');
  for (let i = 0; i < all.length; i += 1) {
    const element = all[i] as { getAttribute?: (n: string) => string | null };
    if (element.getAttribute && element.getAttribute('ID') === id) return element;
  }
  return null;
}

/** Every element carrying this `ID`, so duplicates are visible rather than hidden. */
export function elementsWithId(doc: XmlDocument, id: string): unknown[] {
  const all = (doc as unknown as { getElementsByTagName: (n: string) => ArrayLike<unknown> })
    .getElementsByTagName('*');
  const out: unknown[] = [];
  for (let i = 0; i < all.length; i += 1) {
    const element = all[i] as { getAttribute?: (n: string) => string | null };
    if (element.getAttribute && element.getAttribute('ID') === id) out.push(element);
  }
  return out;
}

export function signatureElements(doc: XmlDocument): unknown[] {
  return allElements(doc, NS.ds, 'Signature');
}
