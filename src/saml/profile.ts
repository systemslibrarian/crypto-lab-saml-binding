/**
 * S12-WBSSO-POST-SYNTH/1 — the profile this lab implements, named.
 *
 * A synthetic, bounded subset of the SAML V2.0 Web Browser SSO Profile
 * (saml-profiles-2.0-os, OASIS Standard 15 March 2005, section 4.1) over the
 * HTTP POST binding (saml-bindings-2.0-os section 3.5), in the identity
 * provider to service provider direction only.
 *
 * The name is a label this lab invented for a subset this lab defined. It is
 * not an OASIS profile identifier, it is registered nowhere, and nothing that
 * has to interoperate with a real deployment should be built from it.
 *
 * Everything below is synthetic. The identity provider, the service provider
 * and the attacker are three modules in one browser tab; no network request
 * leaves the page; key material is generated locally on every run; and the two
 * identities live on the RFC 2606 reserved `.invalid` top-level domain so they
 * cannot be mistaken for anyone.
 */

export const PROFILE_ID = 'S12-WBSSO-POST-SYNTH/1';

export const IDP_ENTITY_ID = 'https://idp.lab.invalid/saml2/idp';
export const SP_ENTITY_ID = 'https://sp.lab.invalid/saml2/sp';
export const ACS_URL = 'https://sp.lab.invalid/saml2/acs';

/** The SAML subject confirmation method the Web Browser SSO profile requires. */
export const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
export const NAMEID_EMAIL = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
export const NAMEID_ENTITY = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity';
export const AUTHN_PASSWORD_PROTECTED =
  'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
export const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

/**
 * The accepted algorithm and structure subset.
 *
 * SAML Core section 5.4 already narrows XML Signature sharply, and this lab
 * takes each implemented MAY and SHOULD at a strict reading. For fields listed
 * in this table, unsupported algorithms and reference shapes are refused before
 * cryptography, binding rules after verification, and profile rules at L3. This
 * declared teaching subset is not a complete schema or profile validator.
 *
 * One cryptographic policy choice relative to Core 5.4.1 is deliberate and is stated rather than hidden.
 * That section says processors SHOULD support rsa-sha1. SHA-1 is not collision
 * resistant and is unfit for signatures, so this lab implements rsa-sha256 from
 * XML Signature 1.1 instead and supports no SHA-1 algorithm at all.
 */
export const ACCEPTED = {
  signatureMethod: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  digestMethod: 'http://www.w3.org/2001/04/xmlenc#sha256',
  canonicalization: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  envelopedTransform: 'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
  excC14nTransform: 'http://www.w3.org/2001/10/xml-exc-c14n#',
} as const;

/** Exactly these two transforms, in exactly this order (Core 5.4.4). */
export const ACCEPTED_TRANSFORMS: readonly string[] = [
  ACCEPTED.envelopedTransform,
  ACCEPTED.excC14nTransform,
];

/** Allowable clock skew between providers, per Profiles 4.1.4.3. */
export const CLOCK_SKEW_SECONDS = 60;

/**
 * A frozen clock.
 *
 * Every displayed verdict has to come from the current run, and a wall clock
 * would make "this assertion is still valid" depend on the minute the learner
 * pressed the button. The fixtures are therefore dated against this instant,
 * which the interface shows, and the time controls move the fixture rather than
 * the clock.
 */
export const NOW_ISO = '2026-10-26T12:00:00Z';
export const NOW_MS = Date.parse(NOW_ISO);

export interface Identity {
  readonly nameId: string;
  readonly role: string;
  readonly display: string;
}

export const ALICE: Identity = {
  nameId: 'alice@lab.invalid',
  role: 'reader',
  display: 'Alice, an ordinary reader',
};

export const MALLORY: Identity = {
  nameId: 'admin@lab.invalid',
  role: 'administrator',
  display: 'the administrator account the attacker wants',
};

/** What each role may do, so an authorization outcome is more than a string. */
export const RIGHTS: Record<string, readonly string[]> = {
  reader: ['read own borrowing history'],
  administrator: ['read every account', 'change any password', 'export the user table'],
};

export function rightsOf(role: string): readonly string[] {
  return RIGHTS[role] ?? [];
}

/**
 * The declared subset, as data, so the page states it rather than describes it.
 */
export function declaredSubset(): { field: string; value: string; source: string }[] {
  return [
    {
      field: 'Profile',
      value: `${PROFILE_ID} — synthetic Web Browser SSO, HTTP POST, IdP to SP only`,
      source: 'SAMLProf 4.1; SAMLBind 3.5',
    },
    {
      field: 'Signature placement',
      value: 'enveloped, inside saml:Assertion, immediately after saml:Issuer',
      source: 'SAMLCore 5.4.1',
    },
    {
      field: 'SignatureMethod',
      value: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 (RSA-2048)',
      source: 'XMLDSIG 1.1 6.4.2',
    },
    {
      field: 'DigestMethod',
      value: 'http://www.w3.org/2001/04/xmlenc#sha256',
      source: 'XMLDSIG 1.1 6.2.2',
    },
    {
      field: 'CanonicalizationMethod',
      value: 'http://www.w3.org/2001/10/xml-exc-c14n# in SignedInfo and as a transform',
      source: 'SAMLCore 5.4.3; Excl-C14N 1.0',
    },
    {
      field: 'Transforms',
      value: 'exactly enveloped-signature then exclusive-c14n, in that order',
      source: 'SAMLCore 5.4.4',
    },
    {
      field: 'Reference',
      value: 'exactly one, URI="#id", same-document, resolving to exactly one element',
      source: 'SAMLCore 5.4.2',
    },
    {
      field: 'Verified node',
      value: 'a saml:Assertion that is a direct child of the samlp:Response',
      source: 'W3C XMLDSIG Best Practice 14 (name and position)',
    },
    {
      field: 'Document root',
      value: 'samlp:Response',
      source: 'SAMLProf 4.1.4.2; W3C XMLDSIG Best Practice 14',
    },
    {
      field: 'KeyInfo',
      value: 'ignored; the verifying key is the service provider’s pinned trust anchor',
      source: 'SAMLCore 5.4.5',
    },
    {
      field: 'Subject confirmation',
      value: `one complete ${BEARER} candidate must pass; fields are never mixed`,
      source: 'SAMLProf 4.1.4.2 and 4.1.4.3 (Errata 05 E26)',
    },
    {
      field: 'Authentication statement',
      value: 'the one selected assertion has at least one direct saml:AuthnStatement',
      source: 'SAMLProf 4.1.4.2 (Errata 05 E26); bounded stricter adaptation',
    },
    {
      field: 'Time syntax',
      value: 'bounded four-digit UTC form YYYY-MM-DDThh:mm:ss[.fraction]Z',
      source: 'SAMLCore 1.3.3; bounded teaching subset',
    },
  ];
}
