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
- this lab's independent Web Crypto recomputation agrees: digest matches, signature valid;
- a first-match `saml:Assertion` query selects the attacker's element.

If any of those stopped holding, `tests/wrapping.test.ts` fails rather than quietly
becoming a demonstration of something else.

## 4. Outcomes measured on this build

| Scenario | L1 signature | Vulnerable consumer | Repaired consumer |
|---|---|---|---|
| Honest signed response | valid | authorizes `alice@lab.invalid`, `reader` | authorizes `alice@lab.invalid`, `reader` |
| XML Signature Wrapping | **valid** | **authorizes `admin@lab.invalid`, `administrator`** | refuses at L2, rule `verified-node-wrong-position` |
| Unsigned assertion placed first | **valid** | **authorizes `admin@lab.invalid`, `administrator`** | authorizes `alice@lab.invalid`, `reader` |

On the wrapped document **every SAML profile check passed for the vulnerable consumer**
(asserted, not assumed). Profile validation is not a defence against validating the wrong
element, and the page is built so a reader cannot conclude otherwise.

### Negative controls: 17 rows, all behaving as predicted

| Family | Controls | Repaired consumer stops at |
|---|---|---|
| signature | signature bytes altered; signed subject altered; signed by an untrusted key | L1 |
| binding | XML Signature Wrapping; an unsigned assertion placed first; two elements carry one ID; reference resolves to nothing; a transform outside the declared subset | L2, except the sibling case which is **accepted with the correct subject** |
| profile | audience; recipient; subject confirmation method; forbidden `NotBefore`; `InResponseTo` mismatch; unsolicited response carrying `InResponseTo`; expired; not yet valid | L3 |
| replay | the same assertion delivered twice | L3 |

The two binding rows are the **only** rows in which the vulnerable consumer authorizes
the attacker; that exclusivity is itself asserted, so a future change that made another
control fool it would turn something red.

## 5. Local gate results

```
npm ci                 clean
npm audit --audit-level=high    found 0 vulnerabilities
npm run typecheck      clean
npm test               76 passed, 7 files
npm run test:mutation  baseline passes; 18/18 caught; restored byte for byte; baseline passes again
npm run build          dist/index.html 0.87 kB, index js 24.23 kB (8.63 kB gzip),
                       lesson chunk 572.20 kB (136.56 kB gzip), built in 326 ms
npm run test:a11y      17 passed
```

### Unit coverage of the protocol modules

`npx vitest run --coverage`, scoped to `src/saml/**`:

```
All files     |   94.43 % stmts |   71.42 % branch |   96.29 % funcs |   97.21 % lines
```

The branch figure is the honest one to look at: it is held down by defensive `?? null`
and "this cannot happen" paths in the DOM helpers, not by unexercised protocol rules.
Every rule in `verify.ts` and `checks.ts` has at least one test that fails when it is
removed — which is what the mutation gate measures and coverage does not.

### Bundle split

The XML Signature machinery is loaded on first use. The page that explains the profile,
the four layers and the omissions arrives in 24 kB of JavaScript; the 572 kB lesson chunk
loads when a learner presses a button. This is recorded because it is a deliberate choice
rather than an accident of bundling.

## 6. The 18 named mutations, and their owning tests

Each mutation edits exactly one source line, runs exactly one test file, and must make
that file fail. No retries, no skips. The harness refuses a mutation whose anchor no
longer matches or is not unique, verifies restoration by hashing every touched file, and
re-runs the clean baseline afterwards.

| # | Mutation | Owning test |
|---|---|---|
| 1 | the verified node no longer has to be where the response delivers it | `wrapping` |
| 2 | the repaired consumer stops binding to the verified element | `wrapping` |
| 3 | two elements carrying one ID are no longer ambiguous | `binding` |
| 4 | a reference that resolves to nothing is tolerated | `binding` |
| 5 | the transform allow-list stops being a list | `binding` |
| 6 | any URI shape is treated as a same-document reference | `binding` |
| 7 | the reference digest is reported as matching whatever it is | `signature` |
| 8 | exclusive canonicalization is swapped for inclusive | `canonicalization` |
| 9 | the audience restriction is no longer compared with this service provider | `profile` |
| 10 | the recipient is no longer compared with the consumer URL | `profile` |
| 11 | `InResponseTo` is no longer compared with the pending request | `profile` |
| 12 | a forbidden `NotBefore` on `SubjectConfirmationData` is allowed | `profile` |
| 13 | the validity window loses its upper bound | `profile` |
| 14 | the allowed clock skew swallows the boundary | `profile` |
| 15 | consumed assertion IDs are never recorded | `replay` |
| 16 | a rejected assertion burns its ID anyway | `replay` |
| 17 | the issuer is no longer compared with the trusted identity provider | `profile` |
| 18 | the page stops retiring stale output | `page-contract` |

**Mutations 1 and 2 are the pair worth reading.** Mutation 2 — replacing the repaired
consumer's bound element with a fresh document query — **survived** when it was first
written, because on the wrapped document the position rule already refused before the
mutated line was reached. That survival was a real coverage gap and it was closed by
adding a document the position rule cannot catch: an unsigned assertion placed *first*,
leaving the signed one exactly where the position rule wants it. The repaired consumer
authorizes the right person there, and only because it never queries the document again.
The pair is now the proof that both rules are load-bearing and neither is decoration.

## 7. Independent verification anchors

Three places where this lab is checked against something other than itself.

1. **Eight hand-derived exclusive-canonicalization vectors**
   (`tests/canonicalization.test.ts`). The expected octets are written out from Exclusive
   XML Canonicalization 1.0 §3 and Canonical XML 1.0 — the visibly-utilized rule, the
   dropped unused default namespace, prefix re-declaration when a subset is canonicalized
   alone, namespace-before-attribute ordering, empty-element form, and the fact that `>`
   is escaped in text but not in attribute values. Every digest claim in the lab rests on
   these bytes. If the dependency and this file ever disagree, the specification is right.
2. **A second verification path.** The lab recomputes the reference digest (applying the
   enveloped-signature transform itself) and verifies `SignatureValue` over the
   canonicalized `SignedInfo` through Web Crypto, independently of the dependency's
   `Verify()`. Both answers are displayed and asserted equal. One test drives Web Crypto
   with no part of the lab's verifier in the path at all.
3. **Browser claims that recompute.** The rendered SAML document is re-parsed in the test
   with the browser's native `DOMParser` — a different parser from the one the lab ships —
   the `DigestValue` is base64-decoded there, and the page's displayed digests, reference
   URI, assertion census, control count and authorization outcome are all checked against
   that independent parse rather than against the page's own sentences.

## 8. Accessibility and reflow

Driven through the page's own controls, never injected, in every scenario state:

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
