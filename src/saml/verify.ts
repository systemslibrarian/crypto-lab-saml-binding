/**
 * L1 signature validation and L2 node/reference binding.
 *
 * XML Signature 1.1 (W3C Recommendation 11 April 2013) section 3.2 splits core
 * validation into two REQUIRED steps: reference validation, "the verification
 * of the digest contained in each Reference in SignedInfo", and signature
 * validation, "the cryptographic signature validation of the signature
 * calculated over SignedInfo". A library performs both and returns one boolean.
 *
 * That boolean is the whole problem. Somorovsky, Mayer, Schwenk, Kampmann and
 * Jensen put it plainly in "On Breaking SAML: Be Whoever You Want to Be"
 * (USENIX Security 2012), section 8: "the developer uses a DOM-based signature
 * library, which returns true or false according to the message validity.
 * However, the developer does not exactly know which elements were validated."
 *
 * So `verifyBound` returns the ELEMENT, never a boolean, and refuses every
 * shape in which "which element" would be ambiguous: more than one reference,
 * a URI that is not a same-document reference, an ID carried by zero or by
 * several elements, a transform or algorithm outside the declared subset, or a
 * verified node that is not a `saml:Assertion` directly under the
 * `samlp:Response`. That last rule is W3C's own XML Signature Best Practices
 * (Working Group Note 11 April 2013) Best Practice 14: "When checking a
 * reference URI, don't just check the name of the element ... verifiers should
 * check both the name and position of an element".
 */
import './dom.js';
import * as xmldsig from 'xmldsigjs';
import {
  NS,
  allElements,
  attr,
  childElements,
  parseXml,
  serializeXml,
  type XmlDocument,
  type XmlElement,
} from './dom.js';
import { fromBase64, hex, utf8 } from './bytes.js';
import { ACCEPTED, ACCEPTED_TRANSFORMS } from './profile.js';
import { WEBCRYPTO_ALGORITHM } from './keys.js';
import { elementsWithId } from './sign.js';

export interface SignatureStructure {
  signatureCount: number;
  referenceCount: number;
  referenceUri: string | null;
  canonicalization: string | null;
  signatureMethod: string | null;
  digestMethod: string | null;
  transforms: string[];
  digestValue: string | null;
  signatureValue: string | null;
}

export interface BindingFailure {
  /** A stable machine name, so the interface and the tests agree on which rule fired. */
  rule: string;
  detail: string;
}

export interface RecomputedCheck {
  /** SHA-256 over the exclusively canonicalized, enveloped-transformed reference target. */
  recomputedDigest: string;
  /** The digest the document claims, hex-encoded from its base64 DigestValue. */
  claimedDigest: string;
  digestMatches: boolean;
  /** Web Crypto verify over the exclusively canonicalized SignedInfo. */
  signatureValid: boolean;
  canonicalSignedInfoLength: number;
  canonicalReferenceLength: number;
}

export interface BoundVerification {
  structure: SignatureStructure;
  failures: BindingFailure[];
  /** What a boolean-returning library call reports, on its own. */
  libraryVerified: boolean;
  libraryError: string | null;
  /** Bounded recomputation; it shares the dependency's parser and canonicalizer. */
  recomputed: RecomputedCheck | null;
  /** The element the reference actually resolved to, or null if nothing may be trusted. */
  verifiedElement: XmlElement | null;
  verifiedElementId: string | null;
}

const EXCLUSIVE = () => new xmldsig.XmlCanonicalizer(false, true);

/** Read the signature's own declarations, before handing anything to a library. */
export function inspectSignature(doc: XmlDocument): SignatureStructure {
  const signatures = allElements(doc, NS.ds, 'Signature');
  const first = signatures[0];
  if (!first) {
    return {
      signatureCount: 0,
      referenceCount: 0,
      referenceUri: null,
      canonicalization: null,
      signatureMethod: null,
      digestMethod: null,
      transforms: [],
      digestValue: null,
      signatureValue: null,
    };
  }
  const signedInfo = childElements(first, NS.ds, 'SignedInfo')[0] ?? null;
  const references = signedInfo ? childElements(signedInfo, NS.ds, 'Reference') : [];
  const reference = references[0] ?? null;
  const transformsHost = reference ? childElements(reference, NS.ds, 'Transforms')[0] : null;
  const transforms = transformsHost
    ? childElements(transformsHost, NS.ds, 'Transform')
        .map((t) => attr(t, 'Algorithm'))
        .filter((a): a is string => a !== null)
    : [];

  return {
    signatureCount: signatures.length,
    referenceCount: references.length,
    referenceUri: reference ? attr(reference, 'URI') : null,
    canonicalization: signedInfo
      ? attr(childElements(signedInfo, NS.ds, 'CanonicalizationMethod')[0], 'Algorithm')
      : null,
    signatureMethod: signedInfo
      ? attr(childElements(signedInfo, NS.ds, 'SignatureMethod')[0], 'Algorithm')
      : null,
    digestMethod: reference
      ? attr(childElements(reference, NS.ds, 'DigestMethod')[0], 'Algorithm')
      : null,
    transforms,
    digestValue: reference
      ? (childElements(reference, NS.ds, 'DigestValue')[0]?.textContent ?? '').trim()
      : null,
    signatureValue: (childElements(first, NS.ds, 'SignatureValue')[0]?.textContent ?? '').trim(),
  };
}

/** Every structural rule the declared subset imposes, each failing by name. */
function checkStructure(structure: SignatureStructure): BindingFailure[] {
  const failures: BindingFailure[] = [];
  if (structure.signatureCount === 0) {
    failures.push({ rule: 'signature-absent', detail: 'the document carries no ds:Signature' });
    return failures;
  }
  if (structure.signatureCount > 1) {
    failures.push({
      rule: 'signature-not-unique',
      detail: `${structure.signatureCount} ds:Signature elements; this profile accepts exactly one`,
    });
  }
  if (structure.referenceCount !== 1) {
    failures.push({
      rule: 'reference-not-single',
      detail:
        `${structure.referenceCount} ds:Reference elements; SAML Core 5.4.2 requires ` +
        'exactly one',
    });
  }
  if (structure.signatureMethod !== ACCEPTED.signatureMethod) {
    failures.push({
      rule: 'signature-method-unsupported',
      detail: `${structure.signatureMethod ?? 'absent'} is outside the declared subset`,
    });
  }
  if (structure.digestMethod !== ACCEPTED.digestMethod) {
    failures.push({
      rule: 'digest-method-unsupported',
      detail: `${structure.digestMethod ?? 'absent'} is outside the declared subset`,
    });
  }
  if (structure.canonicalization !== ACCEPTED.canonicalization) {
    failures.push({
      rule: 'canonicalization-unsupported',
      detail: `${structure.canonicalization ?? 'absent'} is not Exclusive XML Canonicalization 1.0`,
    });
  }
  const sameTransforms =
    structure.transforms.length === ACCEPTED_TRANSFORMS.length &&
    structure.transforms.every((value, index) => value === ACCEPTED_TRANSFORMS[index]);
  if (!sameTransforms) {
    failures.push({
      rule: 'transforms-unsupported',
      detail:
        `[${structure.transforms.join(', ') || 'none'}] is not the enveloped-signature then ` +
        'exclusive-c14n pair SAML Core 5.4.4 allows',
    });
  }
  return failures;
}

/**
 * Same-document reference resolution, with every ambiguity refused.
 *
 * XML Signature 1.1 section 4.4.3.3 defines a same-document reference as a URI
 * of the form `#id`. Anything else here - an empty URI meaning the whole
 * document, an external URI, an XPointer - is refused rather than resolved,
 * because each would widen what "the signed object" means.
 */
function resolveReference(
  doc: XmlDocument,
  uri: string | null,
): { element: XmlElement | null; failures: BindingFailure[] } {
  const failures: BindingFailure[] = [];
  if (uri === null) {
    failures.push({ rule: 'reference-uri-absent', detail: 'the ds:Reference carries no URI' });
    return { element: null, failures };
  }
  if (!/^#[A-Za-z_][\w.\-]*$/.test(uri)) {
    failures.push({
      rule: 'reference-uri-not-same-document',
      detail: `URI "${uri}" is not a same-document reference of the form #id`,
    });
    return { element: null, failures };
  }
  const id = uri.slice(1);
  const matches = elementsWithId(doc, id) as XmlElement[];
  if (matches.length === 0) {
    failures.push({
      rule: 'reference-unresolved',
      detail: `no element carries ID "${id}"`,
    });
    return { element: null, failures };
  }
  if (matches.length > 1) {
    failures.push({
      rule: 'reference-ambiguous',
      detail: `${matches.length} elements carry ID "${id}", so "the signed element" has no answer`,
    });
    return { element: null, failures };
  }
  return { element: matches[0] ?? null, failures };
}

/**
 * Name AND position, per W3C Best Practice 14.
 *
 * Checking only that the verified node is called `saml:Assertion` is what the
 * wrapping attack is built to satisfy: the attacker's assertion is called that
 * too. The position rule is what it cannot satisfy while still being the node
 * the signature covers.
 */
function checkPosition(doc: XmlDocument, element: XmlElement): BindingFailure[] {
  const failures: BindingFailure[] = [];
  const root = doc.documentElement as unknown as XmlElement;
  if (root.namespaceURI !== NS.samlp || root.localName !== 'Response') {
    failures.push({
      rule: 'response-root-wrong-name',
      detail:
        `the document root is <${root.nodeName}>, not samlp:Response; a direct-child test ` +
        'has meaning only inside the response shape this profile declares',
    });
  }
  if (element.namespaceURI !== NS.saml || element.localName !== 'Assertion') {
    failures.push({
      rule: 'verified-node-wrong-name',
      detail: `the signature covers <${element.nodeName}>, not a saml:Assertion`,
    });
    return failures;
  }
  const direct = childElements(root, NS.saml, 'Assertion');
  if (!direct.some((candidate) => candidate === element)) {
    failures.push({
      rule: 'verified-node-wrong-position',
      detail:
        'the signature covers a saml:Assertion that is not a direct child of the ' +
        'samlp:Response, so it is not the assertion this response delivers',
    });
  }

  // SAML Core 5.4.1 and the Assertion schema place the optional Signature
  // immediately after the one direct Issuer. The enveloped-signature transform
  // can still verify if a Signature is moved outside its assertion or later in
  // the assertion, so this position is an application check, not a consequence
  // of a true cryptographic verdict.
  const elementChildren: XmlElement[] = [];
  for (let i = 0; i < element.childNodes.length; i += 1) {
    const child = element.childNodes[i] as unknown as XmlElement;
    if (child.nodeType === 1) elementChildren.push(child);
  }
  const issuers = elementChildren.filter(
    (child) => child.namespaceURI === NS.saml && child.localName === 'Issuer',
  );
  const signatures = elementChildren.filter(
    (child) => child.namespaceURI === NS.ds && child.localName === 'Signature',
  );
  const issuerIndex = issuers.length === 1 ? elementChildren.indexOf(issuers[0] as XmlElement) : -1;
  const signatureIndex =
    signatures.length === 1 ? elementChildren.indexOf(signatures[0] as XmlElement) : -1;
  if (issuerIndex < 0 || signatureIndex !== issuerIndex + 1) {
    failures.push({
      rule: 'signature-wrong-position',
      detail:
        'this subset requires one ds:Signature directly inside the verified assertion, ' +
        'immediately after its one direct saml:Issuer',
    });
  }
  return failures;
}

/**
 * Reference validation and signature validation, recomputed here.
 *
 * This repeats what the library already did, through a different code path: the
 * canonicalizer is the dependency's, but the enveloped-signature transform, the
 * digest and the RSA verification are this lab's, straight onto Web Crypto. The
 * interface shows both answers. They are asserted equal in the suite, and if
 * they ever disagreed the honest move would be to say so rather than pick one.
 */
async function recompute(
  xml: string,
  referenceId: string,
  structure: SignatureStructure,
  publicKey: CryptoKey,
): Promise<RecomputedCheck> {
  const working = parseXml(xml);
  const target = (elementsWithId(working, referenceId) as XmlElement[])[0];
  if (!target) throw new Error(`recomputation found no element with ID ${referenceId}`);

  // The enveloped-signature transform: remove the ds:Signature this reference
  // lives in. In this profile that is the signature's direct host, so the
  // removal is exact rather than a search for "any signature anywhere".
  const enveloped = childElements(target, NS.ds, 'Signature')[0];
  if (enveloped) {
    (target as unknown as { removeChild: (n: unknown) => void }).removeChild(enveloped);
  }

  const canonicalReference = EXCLUSIVE().Canonicalize(target as never);
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', utf8(canonicalReference) as unknown as BufferSource),
  );
  const claimed = structure.digestValue ? hex(fromBase64(structure.digestValue)) : '';

  // SignedInfo is canonicalized in its ORIGINAL document, not in the working
  // copy the transform mutated.
  const live = parseXml(xml);
  const signedInfo = allElements(live, NS.ds, 'SignedInfo')[0];
  const canonicalSignedInfo = signedInfo ? EXCLUSIVE().Canonicalize(signedInfo as never) : '';
  const signatureBytes = structure.signatureValue
    ? fromBase64(structure.signatureValue)
    : new Uint8Array(0);
  const signatureValid =
    signatureBytes.length > 0 &&
    (await crypto.subtle.verify(
      WEBCRYPTO_ALGORITHM as never,
      publicKey,
      signatureBytes as unknown as BufferSource,
      utf8(canonicalSignedInfo) as unknown as BufferSource,
    ));

  return {
    recomputedDigest: hex(digest),
    claimedDigest: claimed,
    digestMatches: hex(digest) === claimed,
    signatureValid,
    canonicalSignedInfoLength: canonicalSignedInfo.length,
    canonicalReferenceLength: canonicalReference.length,
  };
}

/** What a library alone establishes: one boolean. */
export async function libraryVerify(
  doc: XmlDocument,
  publicKey: CryptoKey,
): Promise<{ verified: boolean; error: string | null }> {
  const signature = allElements(doc, NS.ds, 'Signature')[0];
  if (!signature) return { verified: false, error: 'no ds:Signature element' };
  try {
    const signed = new xmldsig.SignedXml(doc as never);
    signed.LoadXml(signature as never);
    return { verified: await signed.Verify(publicKey), error: null };
  } catch (error) {
    return { verified: false, error: (error as Error).message };
  }
}

/**
 * The binding-aware verification the repaired consumer uses.
 *
 * Returns the element, or null plus the named rules that fired.
 */
export async function verifyBound(xml: string, publicKey: CryptoKey): Promise<BoundVerification> {
  const doc = parseXml(xml);
  const structure = inspectSignature(doc);
  const failures = checkStructure(structure);

  if (failures.length > 0) {
    return {
      structure,
      failures,
      libraryVerified: false,
      libraryError: 'not attempted: the signature is outside the declared subset',
      recomputed: null,
      verifiedElement: null,
      verifiedElementId: null,
    };
  }

  const resolution = resolveReference(doc, structure.referenceUri);
  failures.push(...resolution.failures);
  if (!resolution.element) {
    return {
      structure,
      failures,
      libraryVerified: false,
      libraryError: 'not attempted: the reference does not resolve to exactly one element',
      recomputed: null,
      verifiedElement: null,
      verifiedElementId: null,
    };
  }

  const referenceId = (structure.referenceUri ?? '').slice(1);
  const library = await libraryVerify(doc, publicKey);
  const recomputed = await recompute(xml, referenceId, structure, publicKey);

  if (!recomputed.digestMatches) {
    failures.push({
      rule: 'digest-mismatch',
      detail: 'the referenced element does not hash to the DigestValue in SignedInfo',
    });
  }
  if (!recomputed.signatureValid) {
    failures.push({
      rule: 'signature-invalid',
      detail: 'SignedInfo does not verify under the service provider’s trusted key',
    });
  }
  if (!library.verified) {
    failures.push({
      rule: 'library-verification-failed',
      detail:
        library.error ??
        'the XML Signature verifier returned false even though the bounded recomputation passed',
    });
  }
  failures.push(...checkPosition(doc, resolution.element));

  const ok = failures.length === 0;
  return {
    structure,
    failures,
    libraryVerified: library.verified,
    libraryError: library.error,
    recomputed,
    verifiedElement: ok ? resolution.element : null,
    verifiedElementId: ok ? referenceId : null,
  };
}

/** Canonical bytes of an element, exposed so tests can pin them against the spec. */
export function canonicalize(element: unknown): string {
  return EXCLUSIVE().Canonicalize(element as never);
}

export { serializeXml };
