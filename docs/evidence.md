# S12 evidence record

Everything below was measured on this branch on 2026-10-26 and is reproducible by the
commands shown. Figures that are not derived are not here: where a number could only be
inherited from a target, a budget or an adjacent measurement, it is absent rather than
published.

## 1. Repository

| | |
|---|---|
| Repository | `systemslibrarian/crypto-lab-saml-binding`, **created 2026-10-26** as part of this work |
| Visibility | public |
| Default branch | `main`, baseline commit `cb0ccfa` (an empty baseline carrying no lesson and no claim) |
| Implementation branch | `s12-saml-binding-20261026` |
| Live URL | `https://systemslibrarian.github.io/crypto-lab-saml-binding/` |
| Playwright port | 4675, `--strictPort`, unused in the catalog's registry as read on 2026-10-26 |

### Independent audit corrections before merge

The first pull-request head passed its gates but was not merged. A separate review found
and corrected ten claims or behaviors before integration:

1. a cryptographically valid assertion under a non-SAML root was accepted;
2. the verifier did not enforce its declared direct, post-Issuer signature position;
3. a successful bounded recomputation could override a `false` dependency verdict;
4. a bad Response Destination or Status could consume an otherwise valid assertion ID;
5. Errata 05 E26's required authentication statement and any-one-complete bearer
   confirmation semantics were missing;
6. a malformed Conditions instant could be treated as an absent bound; and
7. prose called two paths independent although they share the XML parser and
   canonicalizer, while other prose incorrectly said the pinned dependency could not
   notice duplicate IDs even though an executable test shows that it does;
8. only `SubjectConfirmationData.InResponseTo` was checked, leaving the separate
   Response-level `InResponseTo` field uncorrelated with local request state;
9. prose turned E26's set-level authentication-statement requirement into a false
   per-assertion quotation instead of naming this lab's stricter one-selected-assertion
   adaptation; and
10. learner-facing claims described the hostile document as passing every SAML profile
    rule, although it passes only this lab's implemented selected-assertion checks and is
    not claimed to be conforming identity-provider output.

The controls, unit tests and mutation table below describe the corrected head, not the
superseded initial run.

## 2. Source mapping, verified rather than assumed

The roadmap cites "Web Single Sign On and SAML (original PDF pp. 6803–6814)". The local
split PDF declares *"Part 4 of 4. Original PDF pages 5338-6913"* and has exactly 1576
pages; `6913 − 5338 + 1 = 1576`, so `split = original − 5337` and original 6803–6814 maps
to **split pages 1466–1477**. That range opens with DOI
`https://doi.org/10.1007/978-3-030-71522-9_906` and the title **"Web Single Sign On and
SAML"** by Frédérique Biennier. The pointer was checked, not trusted.

The entry supplies framing only: the three Web-SSO components, the eight-step browser
exchange, and the four standardized SAML elements. It contains **no XML Signature
detail**, which is why every technical decision in this lab is sourced to OASIS, W3C or
the attack literature instead. Exact versions and sections are in
[`design-and-sources.md`](design-and-sources.md).

## 3. The feasibility question, settled before implementation

The lesson only exists if a wrapped document's signature **really verifies**. That was
established by a standalone probe before any lab code was written, and is now asserted by
the suite on every run:

- the library returns `true` on the wrapped document;
- the reference still reads `#<original assertion id>`;
- this lab's bounded Web Crypto recomputation agrees: digest matches, signature valid;
- a first-match `saml:Assertion` query selects the attacker's element.

If any of those stopped holding, `tests/wrapping.test.ts` fails rather than quietly
becoming a demonstration of something else.

## 4. Outcomes measured on this build

| Scenario | L1 signature | Vulnerable consumer | Repaired consumer |
|---|---|---|---|
| Honest signed response | valid | authorizes `alice@lab.invalid`, `reader` | authorizes `alice@lab.invalid`, `reader` |
| XML Signature Wrapping | **valid** | **authorizes `admin@lab.invalid`, `administrator`** | refuses at L2, rule `verified-node-wrong-position` |
| Unsigned assertion placed first | **valid** | **authorizes `admin@lab.invalid`, `administrator`** | authorizes `alice@lab.invalid`, `reader` |

On the wrapped document **every implemented selected-assertion check passed for the
vulnerable consumer** (asserted, not assumed). Running those checks on the wrong element is
not a binding defence. The hostile document is explicitly not presented as conforming IdP
output or as having passed every rule in the full SAML profile.

### Negative controls: 23 rows, all behaving as predicted

| Family | Controls | Repaired consumer stops at |
|---|---|---|
| signature | signature bytes altered; signed subject altered; signed by an untrusted key | L1 |
| binding | XML Signature Wrapping; an unsigned assertion placed first; two elements carry one ID; reference resolves to nothing; a transform outside the declared subset; non-SAML root; misplaced valid signature | L2, except the sibling case which is **accepted with the correct subject** |
| profile | audience; Response Destination; Response-level `InResponseTo`; recipient; subject confirmation method; selected assertion missing `AuthnStatement`; forbidden `NotBefore`; assertion-level `InResponseTo` mismatch; unsolicited response carrying `InResponseTo`; expired; not yet valid; malformed Conditions time | L3 |
| replay | the same assertion delivered twice | L3 |

The two malicious binding documents are adversarial inputs, not profile-conforming IdP
output. “Accepted with the correct subject” in the sibling row proves the narrow element-
binding property; it is not a claim that a production SP should accept that whole Response.

The two binding rows are the **only** rows in which the vulnerable consumer authorizes
the attacker; that exclusivity is itself asserted, so a future change that made another
control fool it would turn something red.

## 5. Local gate results

```
npm ci                 clean
npm audit --audit-level=high    found 0 vulnerabilities
npm run typecheck      clean
npm test               88 passed, 7 files
npm run test:mutation  baseline passes; 26/26 caught; restored byte for byte; baseline passes again
npm run build          dist/index.html 0.87 kB, index js 25.70 kB (9.18 kB gzip),
                       lesson chunk 577.06 kB (137.90 kB gzip), built in 153 ms
npx playwright test --list    17 tests discovered
npm run test:a11y      local Chromium could not launch on this Mac (Mach rendezvous error 141);
                       no browser test began, so hosted Linux supplies this gate
```

Hosted corrected-head run `40441448660` passed all Node 22/24/26 quality jobs and 16 of
17 browser tests, then correctly failed the omissions claim because an exact substring
assertion treated HTML line-wrapping whitespace as content. The page carried the complete
sentence. The test now collapses whitespace before checking the full learner-visible
sentence. Exact-head pull-request run `40441775524` on `3378f95` then passed all three
Node quality jobs (**88/88 tests**, clean baseline, **26/26 mutations caught**, restored
sources, clean build), plus all **17/17** browser claims, accessibility, forced-colors,
keyboard and reflow checks. CodeQL run `40441775511` on the same head also completed
successfully. The deploy and Pages-publication steps were correctly skipped because this
was a pull request.

### Unit coverage of the protocol modules

`npx vitest run --coverage`, scoped to `src/saml/**`:

```
All files     |   94.84 % stmts |   75.07 % branch |   96.59 % funcs |   97.59 % lines
```

The branch figure is the honest one to look at: it is held down by defensive `?? null`
and "this cannot happen" paths in the DOM helpers, not by unexercised protocol rules.
Every rule in `verify.ts` and `checks.ts` has at least one test that fails when it is
removed — which is what the mutation gate measures and coverage does not.

### Bundle split

The XML Signature machinery is loaded on first use. The page that explains the profile,
the four layers and the omissions arrives in 25.70 kB of JavaScript; the 577.06 kB lesson chunk
loads when a learner presses a button. This is recorded because it is a deliberate choice
rather than an accident of bundling.

## 6. The 26 named mutations, and their owning tests

Each mutation edits exactly one source line, runs exactly one test file, and must make
that file fail. No retries, no skips. The harness refuses a mutation whose anchor no
longer matches or is not unique, verifies restoration by hashing every touched file, and
re-runs the clean baseline afterwards.

| # | Mutation | Owning test |
|---|---|---|
| 1 | the document root no longer has to be a SAML Response | `binding` |
| 2 | the assertion signature no longer has to follow its Issuer | `binding` |
| 3 | the verified node no longer has to be where the response delivers it | `wrapping` |
| 4 | the repaired consumer stops binding to the verified element | `wrapping` |
| 5 | two elements carrying one ID are no longer ambiguous | `binding` |
| 6 | a reference that resolves to nothing is tolerated | `binding` |
| 7 | the transform allow-list stops being a list | `binding` |
| 8 | any URI shape is treated as a same-document reference | `binding` |
| 9 | the reference digest is reported as matching whatever it is | `signature` |
| 10 | dependency disagreement is ignored | `signature` |
| 11 | exclusive canonicalization is swapped for inclusive | `canonicalization` |
| 12 | the audience restriction is no longer compared with this service provider | `profile` |
| 13 | the recipient is no longer compared with the consumer URL | `profile` |
| 14 | assertion `InResponseTo` is no longer compared with the pending request | `profile` |
| 15 | Response `InResponseTo` is no longer compared with the pending request | `replay` |
| 16 | a forbidden `NotBefore` on `SubjectConfirmationData` is allowed | `profile` |
| 17 | the selected assertion no longer needs an authentication statement | `profile` |
| 18 | only the first bearer confirmation is considered | `profile` |
| 19 | the validity window loses its upper bound | `profile` |
| 20 | a malformed Conditions expiry is treated as an absent bound | `profile` |
| 21 | the allowed clock skew swallows the boundary | `profile` |
| 22 | consumed assertion IDs are never recorded | `replay` |
| 23 | a rejected assertion burns its ID anyway | `replay` |
| 24 | a bad Response envelope check still burns the assertion ID | `replay` |
| 25 | the issuer is no longer compared with the trusted identity provider | `profile` |
| 26 | the page stops retiring stale output | `page-contract` |

**Mutations 3 and 4 are the pair worth reading.** Mutation 4 — replacing the repaired
consumer's bound element with a fresh document query — **survived** when it was first
written, because on the wrapped document the position rule already refused before the
mutated line was reached. That survival was a real coverage gap and it was closed by
adding a document the position rule cannot catch: an unsigned assertion placed *first*,
leaving the signed one exactly where the position rule wants it. The repaired consumer
authorizes the right person there, and only because it never queries the document again.
The pair is now the proof that both rules are load-bearing and neither is decoration.

## 7. Verification anchors and shared machinery

Three places where this lab is checked against something other than itself.

1. **Eight hand-derived exclusive-canonicalization vectors**
   (`tests/canonicalization.test.ts`). The expected octets are written out from Exclusive
   XML Canonicalization 1.0 §3 and Canonical XML 1.0 — the visibly-utilized rule, the
   dropped unused default namespace, prefix re-declaration when a subset is canonicalized
   alone, namespace-before-attribute ordering, empty-element form, and the fact that `>`
   is escaped in text but not in attribute values. Every digest claim in the lab rests on
   these bytes. If the dependency and this file ever disagree, the specification is right.
2. **A bounded second verification path.** The lab reapplies the enveloped-signature
   transform, recomputes the reference digest, and verifies `SignatureValue` through Web
   Crypto without calling the dependency's `Verify()`. It shares the XML parser and
   canonicalizer with the dependency, so it is not an end-to-end independent
   implementation; the hand-derived vectors above constrain that shared canonicalizer.
   Both answers are displayed, and disagreement fails closed.
3. **Browser claims that recompute, using no XML parser at all.** The rendered SAML
   document is re-read by a token scanner in the test that walks the serialized bytes and
   tracks element nesting directly. It shares no machinery with the implementation —
   neither the lab's parser nor the browser's. The `DigestValue` is base64-decoded there,
   and the page's displayed digests, reference URI, assertion census, control count and
   authorization outcome are all checked against that independent read rather than against
   the page's own sentences.

   The first version of this helper re-parsed the displayed text in the browser with
   `DOMParser`, and **CodeQL flagged it as `js/xss-through-dom`** — DOM text reinterpreted
   as markup. The finding was fair and was fixed rather than suppressed, and the
   replacement is a stronger independent check as well as a safer one.

## 8. Accessibility and reflow

Exact-head hosted run `40441775524` drove the page through its own controls, never
injecting state, and passed all 17 browser checks after the independent corrections:

- axe `wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa` — zero violations at **320, 380 and
  1280 px**, in the un-run state, the baseline, the wrapping attack and the full control
  table;
- **no horizontal page scroll** in any of those states, asserted against
  `documentElement.scrollWidth`, with the widest offending element named on failure;
- **forced colors**: scanned and operated under `forced-colors: active`;
- **reduced motion**: the page is asserted to have zero animated or transitioned elements
  under `prefers-reduced-motion: reduce`;
- **keyboard**: the skip link is the first tab stop, every control is reachable and
  operable by keyboard alone, the focus indicator is asserted present, activation by
  `Enter` produces a result, and every scrollable region carries `tabindex="0"`,
  `role="region"` and an `aria-label`;
- **result and error states** are announced through `role="status"` / `aria-live="polite"`
  regions, and the controls re-enable after a run.

Two real defects were found and fixed by these gates rather than by inspection: a
`minmax(290px, 1fr)` grid floor that pushed the page sideways at 320 px, and a
`forced-colors` block that changed text colour without changing the background, which
would have painted system text on this lab's dark ground.

## 9. Supply chain

- `npm audit --audit-level=high`: **0 vulnerabilities**.
- Two runtime dependencies, both pinned to exact versions in `package.json` and locked in
  `package-lock.json`: `@xmldom/xmldom@0.9.12` and `xmldsigjs@2.8.8`.
- Every GitHub Action is pinned to an immutable 40-character commit SHA, and each pin was
  resolved against the GitHub API on 2026-10-26 rather than copied.
- CodeQL (`javascript-typescript`, `security-and-quality`) runs on push, on pull request
  and weekly.
- The deploy job performs no checkout and is the only job with Pages and OIDC authority;
  artifact packaging and deployment both require the `main` ref.

## 10. What is not established here

- **No claim about any real SAML implementation.** The only consumer broken in this lab is
  one written to be broken. Somorovsky et al.'s "roughly 80% of the SAML frameworks that
  we evaluated" is a 2012 measurement of *their* sample and is quoted as such, never
  extended.
- **No parser-hardening claim.** Entity expansion, external entities and parser
  round-tripping differences are untested here and named as omissions.
- **No completeness claim about wrapping.** Two permutations are executed out of a
  published enumeration of many.
- **The McIntosh and Austel paper was not obtained.** It is cited for attribution of the
  attack class only, and that limitation is stated wherever it is cited.
