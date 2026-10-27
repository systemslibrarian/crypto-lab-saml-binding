# crypto-lab-saml-binding

## What It Is

A browser-based teaching lab about the gap between verifying an XML signature and
authorizing from the object that signature actually covered. It builds a synthetic
SAML 2.0 Web Browser SSO response, signs the assertion with an RSA-2048 key generated
in the page by Web Crypto, and feeds the same bytes to two service providers that
differ at one load-bearing interface boundary: one asks a signature library a yes/no question and then
asks the document, separately, which assertion to use, while the other takes the
element verification returned and never queries again. On an honest response they
agree. On an XML Signature Wrapping document — where the original, still-signed
assertion is moved into a forged one and nothing cryptographic is touched — the
signature still verifies, every implemented check passes on the attacker's selected
assertion, and the first consumer authorizes an administrator account that no identity
provider ever asserted. The hostile document is not claimed to be conforming identity-
provider output; it is an adversarial input that isolates a consumer-side binding bug.
Nothing here contacts a real identity provider, processes a real identity, or is a
production SAML stack.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-saml-binding](https://systemslibrarian.github.io/crypto-lab-saml-binding/)**

## The profile, named

This lab implements **`S12-WBSSO-POST-SYNTH/1`**: a synthetic, bounded subset of the
SAML V2.0 Web Browser SSO Profile (`saml-profiles-2.0-os` §4.1) over the HTTP POST
binding (`saml-bindings-2.0-os` §3.5), identity provider to service provider only.

That name is a label this lab invented for a subset this lab defined. **It is not an
OASIS profile identifier, it is registered nowhere, and nothing that must interoperate
with a real deployment should be built from it.**

Everything is local and synthetic: no network request leaves the page, the identity
provider / service provider / attacker are three modules in one browser tab, key
material is generated per run and never stored or sent, and both identities are
fixtures on the RFC 2606 reserved `.invalid` domain.

### The enforced subset

For each field and shape listed below, anything outside the accepted value is refused by a
named rule. Unsupported algorithms and reference shapes stop before cryptography; position
rules are evaluated after verification. This is not a complete XML Schema or SAML profile
validator, and unlisted Core requirements are not silently claimed.

| Field | Accepted | Source |
|---|---|---|
| Signature placement | enveloped, inside `saml:Assertion`, immediately after `saml:Issuer` | SAMLCore 5.4.1 |
| `SignatureMethod` | `…xmldsig-more#rsa-sha256`, RSA-2048 | XMLDSIG 1.1 6.4.2 |
| `DigestMethod` | `…xmlenc#sha256` | XMLDSIG 1.1 6.2.2 |
| `CanonicalizationMethod` | `…xml-exc-c14n#`, in `SignedInfo` and as a transform | SAMLCore 5.4.3 |
| `Transforms` | exactly enveloped-signature then exclusive-c14n, in that order | SAMLCore 5.4.4 |
| `Reference` | exactly one, `URI="#id"`, same-document, resolving to exactly one element | SAMLCore 5.4.2 |
| Verified node | a `saml:Assertion` that is a **direct child** of the `samlp:Response` | W3C XMLDSIG Best Practice 14 |
| Document root | `samlp:Response` | SAMLProf 4.1.4.2; W3C XMLDSIG Best Practice 14 |
| `KeyInfo` | ignored; the key is the service provider's pinned trust anchor | SAMLCore 5.4.5 |

At L3, the Response Destination and Response-level `InResponseTo` are checked against local
service-provider state, one complete bearer `SubjectConfirmation` candidate must pass, and
this one-relied-upon-assertion subset requires the selected assertion to carry an
`AuthnStatement`. It accepts four-digit UTC SAML instants in
`YYYY-MM-DDThh:mm:ss[.fraction]Z` form. Fields from separate confirmation candidates are
never combined. Errata 05 E26 states the authentication-statement rule over the set of
bearer assertions; requiring it on the one selected assertion is this lab's bounded,
stricter adaptation.

**One cryptographic policy choice relative to SAML Core 5.4.1 is deliberate.** That section says processors
SHOULD support `rsa-sha1`. SHA-1 is not collision resistant and is unfit for
signatures, so this lab implements `rsa-sha256` from XML Signature 1.1 instead and
supports no SHA-1 algorithm at all. Other bounded adaptations and omissions are named
where they occur rather than being treated as full profile conformance.

## Four questions a single boolean hides

XML Signature 1.1 §3.2 splits core validation into reference validation and signature
validation. A library does both and returns one value. This lab answers four questions
separately, on every run, and every negative control names which one it failed.

| Layer | Question | Established by |
|---|---|---|
| **L1 signature** | Is `SignatureValue` valid over the canonical `SignedInfo`, under the trusted key? | the dependency, plus a bounded Web Crypto recomputation that shares the parser and canonicalizer |
| **L2 binding** | Which single element does the one `Reference` resolve to, is that unambiguous, and **is it the element the application is about to read?** | the digest half by the dependency; the rest by the application |
| **L3 profile** | Response correlation and status, audience, recipient, an authentication statement, one complete bearer-confirmation tuple, validity windows and single use — on the L2 element and local SP state | SAMLProf 4.1.4.2/3/5 as amended by Errata 05 E26; SAMLCore 1.3.3/2.5.1.2/2.5.1.4/3.2.2 |
| **L4 authorization** | Which principal, and which role? | the application |

### What the library establishes, and what it cannot

`xmldsigjs` performs exclusive canonicalization, applies the enveloped-signature
transform, resolves the same-document reference, digests and verifies the RSA
signature over `SignedInfo`. It also, on its own, refuses a document carrying two
elements with the same ID — checked here rather than assumed, and stated because it
is a real thing the dependency does.

What it returns is a **boolean**. It does not tell the application which element it
validated. Whether the element the application then reads is that element is a
question no signature library answers for you, and it is the one this lab is about.

## What the comparison shows

| Scenario | Signature | Vulnerable consumer | Repaired consumer |
|---|---|---|---|
| Honest signed response | verifies | authorizes `alice`, `reader` | authorizes `alice`, `reader` |
| **XML Signature Wrapping** — original moved into the forged assertion's `saml:Advice` | **verifies** | **authorizes `admin`, `administrator`** | refuses at L2, `verified-node-wrong-position` |
| **Unsigned assertion placed first** — original left exactly where it was | **verifies** | **authorizes `admin`, `administrator`** | authorizes `alice`, `reader` — the right answer, not a refusal |

The third row is why the repair is the element binding and not the position rule: the
verified node is in the right position there, and only a consumer that never asks the
document a second time gets it right.

Both malicious rows are adversarial documents, not conforming IdP output. In particular,
the sibling-assertion document does not satisfy the POST profile's rule that every relied-
upon assertion be signature-protected. The row tests a narrower and important property:
authorization stays bound to the assertion that was actually verified.

**Signature-byte tampering is a different row on purpose.** It breaks the cryptography
and both consumers catch it at L1. Wrapping breaks nothing cryptographic at all. A lab
that presented the first as the wrapping lesson would teach the opposite of the lesson.

## Threat model and limitations

**The attacker holds no key.** The only powers used are "observe one valid response"
and "edit XML" — the weak adversary of Somorovsky et al. Every malicious document here
starts from a response the synthetic identity provider really signed.

**Not implemented, and claimed about in no way:**

- **Metadata exchange** (`[SAMLMeta]`). The trust anchor is one pinned raw public key
  set in code, not a parsed, signed metadata document.
- **Identity provider discovery** and the scoping machinery around it.
- **Single Logout** (SAMLProf §4.4) and session management. `SessionIndex` rides in the
  fixtures; no session is established, enforced or terminated.
- **Name identifier management and the federation lifecycle** — persistent pseudonyms,
  account linking, defederation.
- **Real trust-anchor administration.** No X.509 chain building, path validation or
  revocation, and `ds:KeyInfo` is ignored entirely. Certificate chains are
  [PKI Chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/)'s subject.
- **XML Encryption.** No `EncryptedAssertion`. SAMLSec §6.1.2 notes encryption would not
  stop replay anyway.
- **Production XML-parser hardening.** Parsing uses `@xmldom/xmldom`'s defaults. No
  claim is made about entity expansion, external entities, or schema-validation and
  round-tripping differences between parsers — and that last class is itself a known
  source of wrapping variants. Required Core attributes and constructs outside the
  explicitly listed checks are generated by the fixtures but are not comprehensively
  validated.
- **Full multi-assertion profile conformance.** The attack documents are hostile inputs,
  not conforming IdP output. This bounded consumer does not use E26's same-principal and
  every-relied-upon-assertion protection rules as its binding repair; a production
  consumer must enforce those rules as well.
- **The other wrapping permutations.** Somorovsky et al. Figure 7 enumerates twelve
  two-level permutations alone; this lab executes two, plus related reference defects.
- **Other bindings and profiles** — no HTTP Redirect binding and its query-string
  signatures, no Artifact binding, no SOAP or ECP, no SAML 1.1.

**Specifically not claimed:** that any named SAML library or deployment is vulnerable —
the only consumer broken here is one this lab wrote in order to break it; that the
repair shown defeats every wrapping permutation; or that passing these checks would make
a real service provider secure.

## Primary sources

Exact versions and the sections read are in
[`docs/design-and-sources.md`](docs/design-and-sources.md).

- OASIS, *Assertions and Protocols for the OASIS SAML V2.0* (`saml-core-2.0-os`), OASIS
  Standard, 15 March 2005 — §2.5.1.2, §2.5.1.4, §5.1–5.3, §5.4.1–5.4.5.
- OASIS, *Profiles for the OASIS SAML V2.0* (`saml-profiles-2.0-os`), OASIS Standard,
  15 March 2005 — §4.1.4.2, §4.1.4.3, §4.1.4.5, §4.1.5.
- OASIS, *Bindings for the OASIS SAML V2.0* (`saml-bindings-2.0-os`), OASIS Standard,
  15 March 2005 — §3.5.
- OASIS, *Security and Privacy Considerations for the OASIS SAML V2.0*
  (`saml-sec-consider-2.0-os`), OASIS Standard, 15 March 2005 — §6.1.2, §6.4.1–6.4.6.
- OASIS, *SAML Version 2.0 Errata 05*, OASIS Approved Errata, 01 May 2012 — item E26.
- W3C, *XML Signature Syntax and Processing Version 1.1*, Recommendation 11 April 2013 —
  §3.2, §3.2.1, §3.2.2, §4.4.3.
- W3C, *Exclusive XML Canonicalization Version 1.0*, Recommendation 18 July 2002.
- W3C, *XML Signature Best Practices*, Working Group Note 11 April 2013 — Best Practice
  14, which the repaired consumer implements.
- J. Somorovsky, A. Mayer, J. Schwenk, M. Kampmann, M. Jensen, "On Breaking SAML: Be
  Whoever You Want to Be", 21st USENIX Security Symposium, 2012 — §3.4, §4.3, §7.5–7.6,
  §8.
- M. McIntosh, P. Austel, "XML signature element wrapping attacks and countermeasures",
  Workshop on Secure Web Services, 2005 — the origin of the attack class, cited for
  attribution. **Not obtained in full**; no claim here rests on its text.
- F. Biennier, "Web Single Sign On and SAML", *Encyclopedia of Cryptography, Security
  and Privacy*, Springer Nature Switzerland, 2025, original pp. 6803–6814, DOI
  `10.1007/978-3-030-71522-9_906` — the entry this lab answers. Read in full for
  framing: it names the four standardized SAML elements and walks the browser SSO
  exchange, and it contains no XML Signature detail, so no technical decision below
  rests on it.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-saml-binding
cd crypto-lab-saml-binding
npm ci
npm run dev
```

## Testing

```bash
npm run typecheck      # tsc --noEmit over src, tests, e2e and the configs
npm test               # vitest run (88 tests, 7 files)
npm run test:mutation  # clean baseline, 26 named mutations, byte-for-byte restore
npm run build          # tsc --noEmit && vite build
npm run test:a11y      # playwright: claims, WCAG A/AA, forced colors, 320/380/1280 reflow
```

What the suites assert, beyond "it runs":

- **Canonicalization against the specification, not against itself.** The expected
  canonical octets for eight fixed documents are written out by hand from Exclusive XML
  Canonicalization 1.0 §3 and Canonical XML 1.0 — the visibly-utilized rule, namespace
  and attribute ordering, empty-element form, and the different escaping rules for text
  and for attribute values. Every digest claim in this lab rests on those bytes, so they
  are checked against the specification rather than captured from a run.
- **Two cross-checking verification paths, with the shared machinery named.** The lab
  reapplies the enveloped transform, recomputes the reference digest, and verifies
  `SignatureValue` through Web Crypto without calling `SignedXml.Verify`. It shares the
  dependency's XML parser and exclusive canonicalizer, so this is not described as an
  end-to-end independent implementation; the hand-derived vectors above check that shared
  canonicalizer against the specification.
- **The wrapping premise.** Four things are asserted separately, so this cannot quietly
  become a tampering demo: the malicious document's signature really verifies, the moved
  assertion is byte-identical in canonical form, the vulnerable consumer authorizes the
  attacker's subject, and the repaired consumer refuses by name at L2.
- **Boundaries, not just the obvious cases.** Validity windows are tested one second
  either side of the allowed clock skew in both directions.
- **Profile boundaries and state.** Multiple bearer confirmations are tested both with a
  later valid tuple and with two partial tuples that must never be combined. Malformed
  SAML instants and a missing `AuthnStatement` are refused. A rejected assertion —
  including one under a bad Response Destination, Response correlation, or Status — must not burn its ID, and
  one service provider's consumed set must not leak into another's.
- **Browser claims that recompute, with no parser at all.** The rendered SAML document is
  re-read in the test by a token scanner that walks the serialized bytes and tracks
  element nesting directly — it uses neither the lab's XML parser nor the browser's, so it
  shares no machinery with the implementation. The `DigestValue` is base64-decoded there,
  and the page's displayed digests, reference URI, assertion census, control count and
  authorization outcome are all checked against that independent read rather than against
  the page's own sentences.
- **The mutation gate** asserts a clean baseline first, runs 26 named mutations each
  against one named owning test, allows no retries and no skips, refuses a mutation whose
  anchor no longer applies, verifies byte-for-byte restoration by hash, and re-runs the
  clean baseline afterwards.

## Stack

Vite · TypeScript strict · `@xmldom/xmldom` · `xmldsigjs` · Web Crypto API · Vitest ·
Playwright · axe-core · GitHub Pages

CI runs clean-install, dependency audit, type-check, unit, mutation and build gates on
Node 22/24/26, then the browser claim and accessibility gates, then CodeQL. Every action
is pinned to an immutable commit SHA. Only the no-checkout deploy job receives
Pages/OIDC authority, and both artifact packaging and deployment require the `main` ref.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*
