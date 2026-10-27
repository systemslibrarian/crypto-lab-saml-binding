# S12 — SAML assertion and signature-binding failures: design and source record

Written before implementation. Base: `systemslibrarian/crypto-lab-saml-binding`
at `cb0ccfa` (the empty baseline), branch `s12-saml-binding-20261026`.

This record exists because the lesson's whole subject is a gap that looks like
nothing: a signature that really does verify, over a document that really was
signed by the right key, consumed by an application that nevertheless acts on a
different element. Nothing in a boolean `verify()` result shows it. So the
design has to name, in advance, which profile is implemented, which XML
Signature subset is accepted, which layer establishes which property, and what
is deliberately not built.

---

## 1. Sources read, with exact versions and sections

### 1.1 The encyclopedia entry the roadmap points at

The roadmap cites "Web Single Sign On and SAML (original PDF pp. 6803–6814)",
DOI `10.1007/978-3-030-71522-9_906`.

**Position mapping, verified rather than assumed.** The local split PDF
`Encyclopedia of Cryptography, Security and Privacy (3rd Edition) - Part 4 of 4 -
S-Z.pdf` carries the subject line *"Part 4 of 4. Original PDF pages 5338-6913;
alphabetical sections S-Z"* and has exactly 1576 pages, and
`6913 − 5338 + 1 = 1576`, so the mapping is one-to-one: `split = original −
5337`. Original 6803–6814 therefore maps to **split pages 1466–1477**, and that
range opens with the DOI `https://doi.org/10.1007/978-3-030-71522-9_906` and the
title **"Web Single Sign On and SAML"** by Frédérique Biennier (LIESP, INSA de
Lyon). The roadmap's pointer is correct and was checked, not trusted.

What the entry supplies, and what it does not. It defines the three Web-SSO
components (identity provider, service provider, user agent), walks the
eight-step browser SSO exchange, and names the four standardized SAML elements —
**Assertions, Protocols, Bindings, Profiles** — with the Web SSO profile given
as the example of a profile. On security it says only that "the binding part
integrates secured requirements as secured transport, signature of the assertion,
or time-stamped assertions". It contains **no XML Signature detail at all**, so
every technical decision below comes from the OASIS and W3C specifications and
from the primary attack literature, not from the entry. Its own Recommended
Reading is the SAML V2.0 executive and technical overviews, which are
non-normative; this lab reads the normative documents instead.

### 1.2 OASIS SAML 2.0 — the normative profile

| Document | Version read | Sections read |
|---|---|---|
| **Assertions and Protocols for the OASIS Security Assertion Markup Language (SAML) V2.0** — `saml-core-2.0-os` | **OASIS Standard, 15 March 2005** | §2.5.1.2 `NotBefore`/`NotOnOrAfter`; §2.5.1.4 `<AudienceRestriction>`/`<Audience>`; §2.5.1.5 `<OneTimeUse>`; §5 preamble; §5.1–5.3 signing and signature inheritance; **§5.4 XML Signature Profile** — §5.4.1 formats and algorithms, §5.4.2 references, §5.4.3 canonicalization, §5.4.4 transforms, §5.4.5 `KeyInfo` |
| **Profiles for the OASIS Security Assertion Markup Language (SAML) V2.0** — `saml-profiles-2.0-os` | **OASIS Standard, 15 March 2005** | §4.1 Web Browser SSO Profile; §4.1.4.1 `<AuthnRequest>` usage; §4.1.4.2 `<Response>` usage; **§4.1.4.3 `<Response>` message processing rules**; §4.1.4.5 POST-specific processing rules; §4.1.5 unsolicited responses |
| **Bindings for the OASIS Security Assertion Markup Language (SAML) V2.0** — `saml-bindings-2.0-os` | **OASIS Standard, 15 March 2005** | §3.5 HTTP POST binding (message encoding and the form control names) |
| **Security and Privacy Considerations for the OASIS Security Assertion Markup Language (SAML) V2.0** — `saml-sec-consider-2.0-os` | **OASIS Standard, 15 March 2005** | §6.1.2 replay; **§6.4 HTTP Redirect/POST binding — §6.4.1 stolen assertion, §6.4.2 man in the middle, §6.4.3 forged assertion, §6.4.4 browser state exposure, §6.4.5 replay, §6.4.6 relay state** |
| **SAML Version 2.0 Errata 05** — `saml-v2.0-errata05-os` | **OASIS Approved Errata, 01 May 2012** | E26 (the replacement text for Profiles §4.1.4.2, §4.1.4.3 and §4.1.4.5); E17; E74; E81 |

Two pieces of that are load-bearing enough to quote.

**Profiles §4.1.4.3, as replaced by Errata 05 E26 — the service provider MUST:**

> • Verify that the Recipient attribute in the bearer `<SubjectConfirmationData>`
> matches the assertion consumer service URL to which the `<Response>` or artifact
> was delivered
> • Verify that the NotOnOrAfter attribute in the bearer
> `<SubjectConfirmationData>` has not passed, subject to allowable clock skew
> between the providers
> • Verify that the InResponseTo attribute in the bearer
> `<SubjectConfirmationData>` equals the ID of its original `<AuthnRequest>`
> message, unless the response is unsolicited … in which case the attribute MUST
> NOT be present
> • Verify that any assertions relied upon are valid in other respects. … each
> assertion, if more than one is present, MUST be evaluated independently.

**Profiles §4.1.4.5, as replaced by E26:**

> If the HTTP POST binding is used to deliver the `<Response>`, each assertion MUST
> be protected by a digital signature. This can be accomplished by signing each
> individual `<Assertion>` element or by signing the `<Response>` element.

and, unchanged by the errata:

> The service provider MUST ensure that bearer assertions are not replayed, by
> maintaining the set of used ID values for the length of time for which the
> assertion would be considered valid based on the NotOnOrAfter attribute in the
> `<SubjectConfirmationData>`.

Audience is **not** in the §4.1.4.3 list; it arrives through §4.1.4.2 ("The
assertion(s) containing a bearer subject confirmation MUST contain an
`<AudienceRestriction>` including the service provider's unique identifier as an
`<Audience>`") together with Core §2.5.1.4 ("The audience restriction condition
evaluates to Valid if and only if the SAML relying party is a member of one or
more of the audiences specified"). The lab enforces it as its own check and cites
both, rather than pretending §4.1.4.3 lists it.

### 1.3 OASIS SAML 2.0 — the normative XML Signature subset

Core §5.4 is what makes a bounded implementation honest rather than a
simplification, because the specification itself narrows XML Signature:

- **§5.4.1** — "SAML assertions and protocols MUST use enveloped signatures when
  signing assertions and protocol messages."
- **§5.4.2** — "Signatures MUST contain a single `<ds:Reference>` containing a
  same-document reference to the ID attribute value of the root element of the
  assertion or protocol message being signed. For example, if the ID attribute
  value is "foo", then the URI attribute in the `<ds:Reference>` element MUST be
  "#foo"."
- **§5.4.3** — "SAML implementations SHOULD use Exclusive Canonicalization
  [Excl-C14N] … both in the `<ds:CanonicalizationMethod>` element of
  `<ds:SignedInfo>`, and as a `<ds:Transform>` algorithm."
- **§5.4.4** — "Signatures in SAML messages SHOULD NOT contain transforms other
  than the enveloped signature transform … or the exclusive canonicalization
  transforms … Verifiers of signatures MAY reject signatures that contain other
  transform algorithms as invalid."

The lab takes every one of those MAYs and SHOULDs at its strictest reading and
**rejects** anything outside the subset, before any cryptography runs. §5.4.4's
alternative — accept other transforms but "ensure that no content of the SAML
message is excluded from the signature" — is deliberately not implemented, and
that is recorded as a limit rather than presented as rigour.

### 1.4 W3C XML Signature and canonicalization

| Document | Version read | Sections read |
|---|---|---|
| **XML Signature Syntax and Processing Version 1.1** | **W3C Recommendation 11 April 2013** (`REC-xmldsig-core1-20130411`) | §2.1 simple example; §3.1 signature generation; **§3.2 core validation — §3.2.1 reference validation, §3.2.2 signature validation**; §4.4.3 the `Reference` element, §4.4.3.1 the URI attribute, §4.4.3.2 the reference processing model, §4.4.3.3 same-document URI references, §4.4.3.4 transforms; §4.5 `KeyInfo` |
| **Exclusive XML Canonicalization Version 1.0** | **W3C Recommendation 18 July 2002** (`REC-xml-exc-c14n-20020718`) | §1 introduction; §2 use cases; §3 the canonicalization method and the visibly-utilized rule; §4 `InclusiveNamespaces` |
| **XML Signature Best Practices** | **W3C Working Group Note 11 April 2013** (`NOTE-xmldsig-bestpractices-20130411`) | §3.1.5 "Modified Approval Example: Wrapping attack" and **Best Practice 14**; §3.2.1 "Sign what matters" and Best Practice 15; §3.2.2 Best Practice 16 |

XMLDSIG 1.1 §3.2 is the decomposition the lab's interface is built around: "The
REQUIRED steps of core validation include (1) **reference validation**, the
verification of the digest contained in each `Reference` in `SignedInfo`, and (2)
the cryptographic **signature validation** of the signature calculated over
`SignedInfo`."

Best Practice 14 is the countermeasure the repaired consumer implements, stated
by W3C over an `Object`-wrapping example whose shape is identical to the SAML
one:

> **Best Practice 14: Applications: When checking a reference URI, don't just
> check the name of the element.** To mitigate attacks where the content that is
> present in the document is not what was actually signed due to various
> transformations, verifiers should check both the name and **position** of an
> element as part of signature verification.

### 1.5 Primary attack research

**Juraj Somorovsky, Andreas Mayer, Jörg Schwenk, Marco Kampmann, Meiko Jensen,
"On Breaking SAML: Be Whoever You Want to Be", 21st USENIX Security Symposium
(USENIX Security '12), Bellevue WA, August 2012.** Read from the USENIX
open-access proceedings PDF `sec12-final91.pdf` (6 pp., two-column). Sections
read: abstract; §1; §3.2 XML Schema `any`/`processContents`; §3.3 SAML; **§3.4
XML Signature Wrapping Attacks**; §4 XSW attacks on SAML including §4.3 attack
permutations and Figure 7; §5.5; §7 analysis and countermeasures, §7.5
"Countermeasure 1: Only-process-what-is-hashed", §7.6 "Countermeasure 2: Mark
signed elements"; **§8 practical countermeasures, §8.1 see-what-is-signed
(Figure 14), §8.2 unique identification (tainting) of signed data (Figure 15)**.

The sentence the whole lab is built to make executable, from §3.4:

> XML documents containing XML Signatures are typically processed in two
> independent steps: signature validation and function invocation (business
> logic). If both modules have different views on the data, a new class of
> vulnerabilities named XML Signature Wrapping attacks (XSW) exists. … the
> receiver verifies the XML Signature successfully but the application logic
> processes the bogus element.

and §8, on exactly why a mature library does not save the application:

> **Using a signature validation library:** Before evaluating the incoming
> assertion elements, the developer uses a DOM-based signature library, which
> returns true or false according to the message validity. However, the developer
> does not exactly know which elements were validated.

The paper also supplies the scope sentence this lab must not exceed: its measured
result is that "roughly 80% of the SAML frameworks that we evaluated could be
broken", about **the frameworks they evaluated in 2012**. This lab demonstrates
one consumer it wrote itself and claims nothing about any library or deployment,
then or now.

**Michael McIntosh and Paula Austel, "XML signature element wrapping attacks and
countermeasures", Workshop on Secure Web Services (SWS '05), 2005.** This is the
origin of the attack class and is cited by both sources above ([MCINTOSH-WRAP] in
the W3C note, [27] in the USENIX paper). **It was not obtained in full** — it is
behind the ACM Digital Library paywall and no open version was retrieved. It is
therefore cited as the attribution for the attack class only, and no claim in
this lab rests on its text. Recording that is the point: an unread source is
named as unread.

### 1.6 Pinned fleet baselines reviewed before design

Reconciled at the roadmap's pinned SHAs and confirmed identical to each repo's
current `origin/main` on 2026-10-26:

- **JWT Forge** `eeb81b2a1035e47ba686a5a3a5cd06672b4bfa48` — JWS verification with
  a correct-versus-vulnerable verifier contrast (`alg:none`, key confusion). The
  structural precedent for this lab's two-consumer comparison, and the reason
  this lab's defect must be a *different* one: JWT Forge's vulnerable verifier
  gets the cryptography wrong, while this lab's vulnerable consumer gets the
  cryptography **right** and the node selection wrong.
- **PKI Chain** `0ee9ca34cecdc1d434f013fa07b23865c56c382b` — certificate chains
  and trust anchors. This lab deliberately does **not** reimplement path
  validation; its trust anchor is one directly pinned raw public key, and X.509
  chain handling is named as an omission that PKI Chain already covers.
- **WebAuthn** `b9267eb6861c8a6793de2d492f37e0868c28e3d2` — origin and challenge
  binding for a different federation technology.

A fleet-wide check found **no SAML implementation anywhere**: no catalog card
mentions SAML, and no `crypto-lab-*` README does. There is nothing to duplicate
and nothing to extend, which is why S12 gets a new repository.

---

## 2. The profile implemented, named explicitly

**`S12-WBSSO-POST-SYNTH/1` — a synthetic, bounded subset of the SAML V2.0 Web
Browser SSO Profile (SAMLProf §4.1) over the HTTP POST binding (SAMLBind §3.5),
IdP-to-SP direction only, with a signed `<saml:Assertion>` inside a
`<samlp:Response>` delivered to one assertion consumer service URL.**

The name is a label this lab invented for a subset this lab defined. It is not an
OASIS profile identifier, it is not registered anywhere, and nothing that
interoperates with a real SAML deployment should be built from it.

Everything in it is synthetic and local:

- no network request of any kind leaves the page;
- the identity provider, the service provider and the attacker are three modules
  in one browser tab;
- key material is generated locally by Web Crypto on each run and never leaves
  the page;
- the only identities are the fixtures `alice@lab.invalid` (role `reader`) and
  `admin@lab.invalid` (role `administrator`), both on the reserved-by-RFC-2606
  `.invalid` TLD.

### Declared cryptographic and structural subset

The consumer accepts **exactly** this and rejects everything else by name, before
any cryptography runs:

| Element | Accepted value | Source |
|---|---|---|
| Signature placement | enveloped, inside `<saml:Assertion>`, immediately after `<saml:Issuer>` | Core §5.4.1; SAML assertion schema sequence |
| `SignatureMethod` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` (RSASSA-PKCS1-v1_5, SHA-256, RSA-2048) | XMLDSIG 1.1 §6.4.2 / RFC 6931 |
| `DigestMethod` | `http://www.w3.org/2001/04/xmlenc#sha256` | XMLDSIG 1.1 §6.2.2 |
| `CanonicalizationMethod` | `http://www.w3.org/2001/10/xml-exc-c14n#` | Core §5.4.3; Excl-C14N 1.0 |
| `Transforms` | exactly two, in order: `#enveloped-signature` then `xml-exc-c14n#` | Core §5.4.4 |
| `Reference` | exactly one, `URI="#<ID>"`, same-document, resolving to exactly one element | Core §5.4.2; XMLDSIG 1.1 §4.4.3.3 |
| Reference target | a `saml:Assertion` that is a **direct child** of the `samlp:Response` | W3C BP14 (name *and* position) |
| `KeyInfo` | ignored entirely; the verifying key comes only from the SP's pinned trust anchor | Core §5.4.5 permits absence; trusting `KeyInfo` would make the signature self-authenticating |

**One deliberate deviation from Core §5.4.1, stated rather than hidden.** That
section says processors SHOULD support `rsa-sha1`. SHA-1 is not collision
resistant and is unfit for signatures; the lab implements `rsa-sha256` from
XMLDSIG 1.1 instead and supports no SHA-1 algorithm at all. A 2005 SHOULD is not
followed, on purpose, and that is the only place the lab knowingly departs from
the specification text.

---

## 3. The four layers, kept apart

The interface and the code separate four questions that a boolean `verify()`
collapses into one. Each has its own panel, its own verdict and its own tests.

| Layer | Question | Established by |
|---|---|---|
| **L1 — Signature validation** | Is `SignatureValue` a valid RSA-SHA256 signature over the canonical form of `SignedInfo`, under the key the SP trusts? | XMLDSIG 1.1 §3.2.2. The library, and independently this lab's own Web Crypto recomputation. |
| **L2 — Node and reference binding** | Which single element does the one `Reference` resolve to, is that resolution unambiguous, do the transforms stay inside the subset, does the digest match, and **is that element the one the application is about to use**? | XMLDSIG 1.1 §3.2.1 for the digest; **the application** for everything else. No library establishes the last clause. |
| **L3 — SAML profile validation** | Audience, recipient, subject confirmation, `InResponseTo`, time validity, single use — evaluated **on the L2 element and on nothing else**. | SAMLProf §4.1.4.2/§4.1.4.3/§4.1.4.5 as amended by Errata 05 E26; Core §2.5.1.2/§2.5.1.4. |
| **L4 — Application authorization** | Which principal, and which role? | The application, from the L3-validated subject of the L2 element. |

**What the dependency establishes, and what it cannot.** `xmldsigjs` performs
exclusive canonicalization, applies the enveloped-signature transform, resolves
the same-document reference, digests, and verifies the RSA signature over
`SignedInfo`. That is L1 and the digest half of L2, and it is genuinely better
than hand-rolled code at it. What it returns is a **boolean**. It does not and
cannot tell the application which element it validated, whether another element
with the same ID exists, or whether the element the application is about to read
is that element. Those are the three things the repaired consumer adds, and they
are the lesson.

---

## 4. The executable comparison

Five states, every figure derived from the current run, each retired the moment
any input changes.

1. **Baseline.** The synthetic IdP signs a well-formed assertion for
   `alice@lab.invalid`. Both consumers accept. Both authorize `alice`, role
   `reader`. L1, L2, L3 and L4 all pass, shown separately.
2. **The vulnerable consumer, on the honest document.** It verifies the signature
   through the library, gets `true`, then **re-queries the document** for
   `saml:Assertion` and authorizes from the first hit. On the honest document the
   first hit happens to be the signed assertion, so it is right — by luck, which
   the panel says in those words. This is the deliberately vulnerable control the
   brief permits, and it is labelled as the anti-pattern everywhere it appears.
3. **The malicious document (XSW).** The attacker, holding only the honest signed
   response and no key, builds a new `<samlp:Response>` whose assertion child is a
   forged assertion for `admin@lab.invalid`, and moves the **unmodified, still
   signed** original assertion into that forged assertion's `<saml:Advice>`
   element. This is permutation 3(a) of Somorovsky et al. Figure 7 adapted to
   `<saml:Advice>`, whose schema admits assertions. Result: the signature still
   verifies (the reference still resolves to an unmodified element the IdP really
   signed), and the vulnerable consumer authorizes **`admin`**.
4. **The repaired consumer.** `verify()` returns the verified `Element` itself
   rather than a boolean, and every later layer takes that handle. It additionally
   rejects duplicate IDs, more than one reference, a non-same-document URI, a
   reference that resolves to zero or several elements, any transform or algorithm
   outside §2's subset, and any verified node that is not a `saml:Assertion`
   directly under the `samlp:Response`. On the same malicious document it refuses,
   naming which rule fired.
5. **Negative controls**, each failing for its own named reason at its own layer:
   audience mismatch; recipient mismatch; wrong subject-confirmation method;
   `NotBefore` present in `<SubjectConfirmationData>` (forbidden by §4.1.4.2);
   `InResponseTo` mismatch; `InResponseTo` present on an unsolicited response;
   expired assertion; not-yet-valid assertion; replay of an already-consumed
   assertion ID; duplicate IDs; an unresolved reference (`URI="#absent"`); a
   reference pointing at a different element than the one consumed; a transform
   outside the subset; a signature over a valid document by an **untrusted** key;
   and signature-byte tampering.

**Signature-byte tampering and wrapping are kept apart on purpose.** Tampering
breaks L1 — the digest or the signature no longer matches, and every consumer,
vulnerable or repaired, rejects it. Wrapping does not break L1 at all; it is an
L2 defect, and only the repaired consumer sees it. Presenting the first as the
lesson would teach the opposite of the lesson, so the interface shows them as
different rows with different failing layers.

---

## 5. Independent verification, not self-agreement

Three anchors, so that no displayed verdict rests only on the implementation
agreeing with itself:

1. **Hand-derived exclusive canonicalization vectors.** For small fixed
   documents, the expected canonical octets are written out in the tests as
   literal strings, derived by reading Exclusive C14N 1.0 §3 — in particular the
   visibly-utilized rule, which drops namespace declarations an element does not
   use. The library's canonicalizer must reproduce those bytes exactly. This is
   the one place the lab can check the dependency against the specification rather
   than against itself.
2. **Independent signature recomputation.** The lab recomputes the SHA-256 digest
   of the canonicalized reference target, and verifies `SignatureValue` over the
   canonicalized `SignedInfo`, directly through Web Crypto — a separate code path
   from the library's `Verify()`. Both results are displayed, and a test asserts
   they agree on every fixture. Where they ever disagreed, the lab would have to
   say so rather than pick one.
3. **Browser claim tests that recompute the page's own numbers**, including
   re-deriving the authorization outcome the page claims from the rendered
   document and the rendered rights, rather than reading a status string.

---

## 6. Visible omissions

Stated on the page and in the README, not only here. None of these is
implemented, and the lab claims nothing about any of them:

- **Metadata exchange** ([SAMLMeta]). The SP's trust anchor is one pinned raw
  public key set by the code, not a parsed, signed metadata document.
- **Identity provider discovery**, and the whole `<IDPList>`/scoping machinery.
- **Single Logout** (SAMLProf §4.4), and session management generally:
  `SessionIndex` and `SessionNotOnOrAfter` are carried in the fixtures but no
  session is established, enforced or terminated.
- **Name identifier management and federation lifecycle** — persistent
  pseudonyms, `<ManageNameIDRequest>`, account linking, defederation.
- **Real trust-anchor administration**: no X.509 chain building, no path
  validation, no revocation, no `KeyInfo` processing. PKI Chain is the lab for
  that, and this lab links to it instead of imitating it.
- **XML Encryption**: no `<EncryptedAssertion>`, `<EncryptedID>` or
  `<EncryptedAttribute>`. Note from SAMLSec §6.1.2 that encryption would not help
  here anyway — "since the potential replayer does not need to understand the
  message to replay it, schemes such as XML Encryption do not provide protection
  against replay".
- **Production XML-parser hardening**. The lab parses with `@xmldom/xmldom`'s
  defaults. It does not claim defence against XXE, DTD or entity-expansion
  attacks, schema-validation differentials, or parser round-tripping differences
  between implementations — and the last of those is itself a known source of
  wrapping variants.
- **The other XSW permutations.** Somorovsky et al. Figure 7 enumerates twelve
  two-level permutations plus the one-level cases. This lab executes one, plus
  the reference-substitution variant, and says so.
- **Other bindings and profiles**: no HTTP Redirect binding with its
  `DEFLATE`-encoded query-string signatures, no HTTP Artifact binding, no SOAP or
  PAOS/ECP, no attribute query, no SAML 1.1.

---

## 7. Claims and non-claims

**Claimed:** a faithful bounded implementation of the declared subset of the SAML
2.0 Web Browser SSO POST profile's response processing rules, with real RSA-2048
/ SHA-256 XML signatures over exclusively canonicalized content, real reference
resolution and digest checking, an executable XML signature wrapping document
that verifies cryptographically while changing who gets authorized, and a
repaired consumer that refuses it by binding every decision to the exact verified
element.

**Not claimed:** that this is a production SAML stack or usable for
interoperability; that any named SAML library or deployment — in 2012 or now — is
vulnerable, since the only consumer broken here is one this lab wrote to be
broken; that the demonstrated repair defeats every XSW permutation, when one is
executed out of a published enumeration of many; that the parser is hardened;
that `KeyInfo`, metadata, encryption or session management are handled; or that
passing this lab's checks would make a real service provider secure.

**And specifically not:** that a client-side form check is a signature or a
profile repair, that signature-byte tampering is the wrapping lesson, or that the
synthetic documents here are anything but synthetic.

---

## 8. Engineering plan

- **Stack:** Vite, TypeScript strict, no backend, dark theme pinned as the fleet
  requires, Playwright port **4675** (unused in the catalog's registry as read on
  2026-10-26).
- **Dependencies, pinned in the lockfile:** `@xmldom/xmldom` for parsing and
  serialization, `xmldsigjs` for XMLDSIG processing and exclusive
  canonicalization, Web Crypto for key generation and the independent
  recomputation. `@xmldom/xmldom` is used in **both** the page and the tests on
  purpose: the browser's own `DOMParser` and the test environment's differ in
  namespace handling, and a lesson about which node was selected must not depend
  on which DOM parsed it.
- **Gates:** `npm ci`, `npm audit --audit-level=high`, `npm run typecheck`,
  `npm test`, `npm run test:mutation`, `npm run build`, `npm run test:a11y`;
  CodeQL; immutable SHA-pinned actions; Pages artifact and deployment gated on
  the browser suite and on `main`.
- **Mutation gate:** a clean-baseline source-mutation harness. Every named
  mutation must be killed by a named owning test, with no retries and no skips,
  and the sources restored byte for byte afterwards.
- **Accessibility and reflow:** keyboard operation and focus, axe WCAG A/AA,
  forced colors, reduced motion, and 320 / 380 / 1280 px with no hidden
  horizontal overflow.

---

## 9. What would stop this being honest

Recorded in advance so the audit can check it was not quietly crossed.

- If the signature in state 3 did **not** actually verify, the lesson would be a
  tampering demo wearing a wrapping label. **Checked before implementation**: a
  standalone probe built the wrapped document and the library returned `true`
  with the reference still reading `#<original id>`, while a first-match
  `saml:Assertion` query selected the forged element.
- If the "repair" were a UI change, a schema check, or a second query with better
  filters, it would not be a repair. The repair is an API change: verification
  returns the element, and no later layer is given the document to query again.
- If the canonicalization were hand-rolled, a wrapping demo could be an artefact
  of a canonicalization bug. It is a mature dependency's, checked against
  hand-derived vectors from the specification.
