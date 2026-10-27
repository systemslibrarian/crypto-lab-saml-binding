/**
 * The learner interface.
 *
 * Every number, identifier, digest, verdict, selected subject and replay
 * outcome on this page comes from the run that produced it. Starting a
 * different scenario RETIRES the others rather than leaving a result beside
 * inputs that did not produce it.
 */
import './style.css';
import type { ControlRow, Parties, ScenarioReport } from './saml/lesson.js';
import type { ConsumeOutcome } from './saml/consumers.js';
import {
  ACS_URL,
  IDP_ENTITY_ID,
  NOW_ISO,
  PROFILE_ID,
  SP_ENTITY_ID,
  declaredSubset,
} from './saml/profile.js';
import { shortFingerprint } from './saml/keys.js';

/**
 * The XML Signature machinery is loaded on first use.
 *
 * It is the bulk of this page's JavaScript and none of it is needed to read the
 * profile, the layers or the omissions, so the page that explains the lesson
 * arrives without waiting for the code that executes it.
 */
const lesson = () => import('./saml/lesson.js');

function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function $(id: string): HTMLElement {
  const element = document.getElementById(id);
  if (!element) throw new Error(`missing element #${id}`);
  return element;
}

const RETIRED = 'Retired: a different scenario was run. Press this scenario’s button to recompute it.';

const subsetRows = declaredSubset()
  .map(
    (row) =>
      `<tr><th scope="row">${esc(row.field)}</th><td class="mono">${esc(row.value)}</td>` +
      `<td>${esc(row.source)}</td></tr>`,
  )
  .join('');

document.getElementById('app')!.innerHTML = `
<header class="hero">
  <div class="wrap">
    <span class="tag">Crypto Lab</span>
    <h1>SAML Binding</h1>
    <p class="lede">
      A real XML signature can verify perfectly over a document, and the application
      reading that document can still authorize the wrong person. This lab builds a
      synthetic SAML 2.0 Web Browser SSO response, signs it with a key generated in
      this tab, and runs it through two service providers that differ at one load-bearing
      interface boundary.
    </p>
  </div>
</header>

<main id="main" class="wrap">
  <div class="card">
    <h2 id="what">What this is, and what it is not</h2>
    <p>
      This page implements <strong>${esc(PROFILE_ID)}</strong>, a synthetic bounded subset of the
      SAML V2.0 Web Browser SSO Profile over the HTTP POST binding, identity provider to
      service provider only. That name is a label this lab invented for a subset this lab
      defined: it is not an OASIS profile identifier, it is registered nowhere, and nothing
      that must interoperate with a real deployment should be built from it.
    </p>
    <p>
      <strong>Nothing here touches a real identity provider or a real identity.</strong>
      No network request leaves the page. The identity provider, the service provider and
      the attacker are three modules in one browser tab. RSA-2048 key material is generated
      locally on every run by Web Crypto and is never stored or sent. The only two identities
      are fixtures on the reserved <code>.invalid</code> domain. This is not a production
      SAML stack and must not be used as one.
    </p>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Declared algorithm and structure subset">
      <table>
        <caption>
          The declared bounded subset. Every mismatch in a listed field is refused by
          a named rule; unlisted schema requirements are outside this lesson.
        </caption>
        <thead><tr><th scope="col">Field</th><th scope="col">Accepted</th><th scope="col">Source</th></tr></thead>
        <tbody>${subsetRows}</tbody>
      </table>
    </div>
    <p>
      One deviation from SAML Core 5.4.1 is deliberate: that section says processors SHOULD
      support <code>rsa-sha1</code>. SHA-1 is not collision resistant and is unfit for
      signatures, so this lab implements <code>rsa-sha256</code> from XML Signature 1.1
      instead and supports no SHA-1 algorithm at all.
    </p>
  </div>

  <div class="card">
    <h2 id="layers">Four questions a single boolean hides</h2>
    <p class="lede">
      XML Signature 1.1 section 3.2 splits core validation into reference validation and
      signature validation. A library does both and returns one value. These are the four
      separate questions, and this page answers each one separately on every run.
    </p>
    <ul>
      <li><strong>L1 — signature validation.</strong> Is <code>SignatureValue</code> a valid
      RSA-SHA256 signature over the canonical <code>SignedInfo</code>, under the key this
      service provider trusts?</li>
      <li><strong>L2 — node and reference binding.</strong> Which single element does the one
      <code>Reference</code> resolve to, is that resolution unambiguous, and
      <em>is that element the one the application is about to read?</em></li>
      <li><strong>L3 — SAML profile validation.</strong> Response correlation and status,
      audience, recipient, a required authentication statement, subject confirmation,
      <code>InResponseTo</code>, validity windows and single use — evaluated on the L2 element
      and local service-provider state. If an assertion
      carries several bearer confirmations, one complete confirmation tuple must pass; fields
      are never combined across candidates.</li>
      <li><strong>L4 — application authorization.</strong> Which principal, and which role?</li>
    </ul>
    <p>
      The dependency used here performs exclusive canonicalization, the enveloped-signature
      transform, reference resolution, digesting and RSA verification — that is L1 and the
      digest half of L2, and it does them better than hand-written code would. In this pinned
      version it also refuses duplicate IDs, which the suite verifies directly. What it returns
      is still a boolean. It does not tell the application <em>which</em> element it validated.
      That gap is the lesson.
    </p>
  </div>

  <div class="card">
    <h2 id="parties">The three parties</h2>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Parties and key material">
      <table>
        <thead><tr><th scope="col">Party</th><th scope="col">Identifier</th><th scope="col">Key material</th></tr></thead>
        <tbody>
          <tr><th scope="row">Identity provider</th><td class="mono">${esc(IDP_ENTITY_ID)}</td>
            <td class="mono" id="idpKey">not generated yet</td></tr>
          <tr><th scope="row">Service provider</th><td class="mono">${esc(SP_ENTITY_ID)}</td>
            <td>trusts one pinned public key; assertion consumer service
              <span class="mono">${esc(ACS_URL)}</span></td></tr>
          <tr><th scope="row">Attacker</th><td class="mono">no entity identifier</td>
            <td class="mono" id="attackerKey">not generated yet</td></tr>
        </tbody>
      </table>
    </div>
    <p class="status">
      The clock is frozen at <span class="mono">${esc(NOW_ISO)}</span>. Every fixture is dated
      against that instant, so a validity verdict is a property of the document rather than of
      the minute you pressed a button.
    </p>
  </div>

  <h2 id="run">Run the comparison</h2>
  <div class="btn-row">
    <button id="btnBaseline" type="button">1 · Honest signed response</button>
    <button id="btnWrapping" type="button">2 · Signature wrapping attack</button>
    <button id="btnControls" type="button">3 · Every negative control</button>
  </div>

  <section class="card" aria-labelledby="scenarioHeading">
    <h3 id="scenarioHeading">Scenario</h3>
    <p class="status" id="scenarioStatus" role="status" aria-live="polite">Nothing has been run yet.</p>
    <div id="scenarioBody"></div>
  </section>

  <section class="card" aria-labelledby="controlsHeading">
    <h3 id="controlsHeading">Negative controls</h3>
    <p class="status" id="controlsStatus" role="status" aria-live="polite">Nothing has been run yet.</p>
    <div id="controlsBody"></div>
  </section>

  <div class="card">
    <h2 id="omissions">What is deliberately not here</h2>
    <p class="lede">
      None of these is implemented, and this lab claims nothing about any of them.
    </p>
    <ul>
      <li><strong>Metadata exchange.</strong> The service provider's trust anchor is one
      pinned raw public key set in code, not a parsed, signed metadata document.</li>
      <li><strong>Identity provider discovery</strong>, and the scoping machinery around it.</li>
      <li><strong>Single Logout and session management.</strong> <code>SessionIndex</code> is
      carried in the fixtures; no session is established, enforced or terminated.</li>
      <li><strong>Name identifier management and the federation lifecycle</strong> —
      persistent pseudonyms, account linking, defederation.</li>
      <li><strong>Real trust-anchor administration.</strong> No X.509 chain building, no path
      validation, no revocation, and <code>ds:KeyInfo</code> is ignored entirely. Certificate
      chains are <a href="https://systemslibrarian.github.io/crypto-lab-pki-chain/">PKI
      Chain</a>'s subject, and this lab links to it rather than imitating it.</li>
      <li><strong>XML Encryption.</strong> No <code>EncryptedAssertion</code>. Note that SAML's
      own security considerations (6.1.2) point out encryption would not stop replay anyway.</li>
      <li><strong>Production XML-parser hardening.</strong> Parsing uses a library's defaults.
      This lab does not claim defence against entity expansion, external entities, or
      schema-validation and round-tripping differences between parsers — and that last class is
      itself a known source of wrapping variants. It is not a complete XML Schema or SAML profile
      validator; Core attributes outside the listed checks are generated, not comprehensively
      validated.</li>
      <li><strong>Full multi-assertion profile conformance.</strong> The attack documents are
      hostile inputs, not conforming identity-provider output. This bounded consumer does not
      use the profile's same-principal and every-relied-upon-assertion signature rules as its
      binding repair; a production consumer must enforce those too.</li>
      <li><strong>The other wrapping permutations.</strong> Somorovsky et al. enumerate twelve
      two-level permutations alone. This page executes one, plus related reference defects.</li>
      <li><strong>Other bindings and profiles</strong> — no HTTP Redirect binding with its
      query-string signatures, no Artifact binding, no SOAP or ECP, no SAML 1.1.</li>
    </ul>
    <h3>And specifically not claimed</h3>
    <ul>
      <li>That any named SAML library or deployment is vulnerable. The only consumer broken
      here is one this lab wrote in order to break it.</li>
      <li>That the repair shown defeats every wrapping permutation.</li>
      <li>That passing these checks would make a real service provider secure.</li>
    </ul>
  </div>

  <div class="card">
    <h2 id="sources">Sources</h2>
    <ul>
      <li>OASIS, <em>Assertions and Protocols for the OASIS Security Assertion Markup Language
      (SAML) V2.0</em>, OASIS Standard, 15 March 2005 — sections 2.5.1.2, 2.5.1.4, 5.1–5.3 and
      5.4.1–5.4.5.</li>
      <li>OASIS, <em>Profiles for the OASIS Security Assertion Markup Language (SAML) V2.0</em>,
      OASIS Standard, 15 March 2005 — sections 4.1.4.2, 4.1.4.3, 4.1.4.5 and 4.1.5.</li>
      <li>OASIS, <em>Bindings for the OASIS Security Assertion Markup Language (SAML) V2.0</em>,
      OASIS Standard, 15 March 2005 — section 3.5.</li>
      <li>OASIS, <em>Security and Privacy Considerations for the OASIS Security Assertion Markup
      Language (SAML) V2.0</em>, OASIS Standard, 15 March 2005 — sections 6.1.2 and 6.4.1–6.4.6.</li>
      <li>OASIS, <em>SAML Version 2.0 Errata 05</em>, OASIS Approved Errata, 01 May 2012 — item
      E26, which replaces the processing rules above.</li>
      <li>W3C, <em>XML Signature Syntax and Processing Version 1.1</em>, Recommendation
      11 April 2013 — sections 3.2, 3.2.1, 3.2.2 and 4.4.3.</li>
      <li>W3C, <em>Exclusive XML Canonicalization Version 1.0</em>, Recommendation
      18 July 2002.</li>
      <li>W3C, <em>XML Signature Best Practices</em>, Working Group Note 11 April 2013 —
      Best Practice 14, which the repaired consumer implements.</li>
      <li>J. Somorovsky, A. Mayer, J. Schwenk, M. Kampmann and M. Jensen, “On Breaking SAML:
      Be Whoever You Want to Be”, 21st USENIX Security Symposium, 2012 — sections 3.4, 4.3,
      7.5–7.6 and 8.</li>
      <li>M. McIntosh and P. Austel, “XML signature element wrapping attacks and
      countermeasures”, Workshop on Secure Web Services, 2005 — the origin of the attack class,
      cited for attribution. It was not obtained in full and no claim here rests on its text.</li>
    </ul>
  </div>
</main>

<footer>
  <div class="wrap">
    <p>
      Part of the <a href="https://crypto-lab.systemslibrarian.dev/">Crypto Lab</a> suite.
      Source: <a href="https://github.com/systemslibrarian/crypto-lab-saml-binding">crypto-lab-saml-binding</a>.
    </p>
  </div>
</footer>
`;

let parties: Parties | null = null;
let busy = false;

const BUTTONS = ['btnBaseline', 'btnWrapping', 'btnControls'];

function setBusy(value: boolean): void {
  busy = value;
  for (const id of BUTTONS) ($(id) as HTMLButtonElement).disabled = value;
}

async function ensureParties(): Promise<Parties> {
  if (!parties) {
    parties = await (await lesson()).newParties();
    $('idpKey').textContent = `RSA-2048, SPKI SHA-256 ${shortFingerprint(parties.idp.fingerprint)}`;
    $('attackerKey').textContent =
      `RSA-2048, SPKI SHA-256 ${shortFingerprint(parties.attacker.fingerprint)}`;
  }
  return parties;
}

function retireScenario(): void {
  $('scenarioBody').innerHTML = '';
  $('scenarioStatus').textContent = RETIRED;
}

function retireControls(): void {
  $('controlsBody').innerHTML = '';
  $('controlsStatus').textContent = RETIRED;
}

function verdict(passed: boolean, yes: string, no: string): string {
  return passed ? `<span class="ok">${esc(yes)}</span>` : `<span class="no">${esc(no)}</span>`;
}

function layerPanel(report: ScenarioReport): string {
  const recomputed = report.verification.recomputed;
  const structure = report.verification.structure;
  const binding = report.verification.verifiedElement !== null;
  const l1 = recomputed
    ? recomputed.signatureValid &&
      recomputed.digestMatches &&
      report.verification.libraryVerified
    : false;

  const l1Body = recomputed
    ? `<p>Reference digest recomputed here: <span class="mono">${esc(
        recomputed.recomputedDigest.slice(0, 24),
      )}…</span></p>
       <p>Digest claimed by the document: <span class="mono">${esc(
         recomputed.claimedDigest.slice(0, 24),
       )}…</span> — ${verdict(recomputed.digestMatches, 'match', 'mismatch')}</p>
       <p>RSA-SHA256 over ${esc(recomputed.canonicalSignedInfoLength)} canonical
          SignedInfo bytes: ${verdict(recomputed.signatureValid, 'valid', 'invalid')}</p>
       <p>A library asked the same question separately answered
          <span class="mono">${esc(report.verification.libraryVerified)}</span>.</p>`
    : `<p>Not evaluated: the signature is outside the declared subset, or its reference does
        not resolve to exactly one element, so no cryptography was attempted.</p>
       <p class="mono">${esc(report.verification.libraryError ?? '')}</p>`;

  const failures = report.verification.failures
    .map((f) => `<li><span class="mono">${esc(f.rule)}</span> — ${esc(f.detail)}</li>`)
    .join('');

  return `
    <div class="layer ${l1 ? 'pass' : recomputed ? 'fail' : 'skip'}">
      <h4>L1 — signature validation</h4>
      ${l1Body}
    </div>
    <div class="layer ${binding ? 'pass' : 'fail'}">
      <h4>L2 — node and reference binding</h4>
      <p>Reference URI: <span class="mono">${esc(structure.referenceUri ?? 'absent')}</span>,
         one of ${esc(structure.referenceCount)} reference(s), in one of
         ${esc(structure.signatureCount)} signature(s).</p>
      <p>Element the signature actually covers:
         <span class="mono">${esc(report.verification.verifiedElementId ?? 'not established')}</span></p>
      <p>Element the vulnerable consumer read:
         <span class="mono">${esc(report.vulnerable.selectedAssertionId ?? 'none')}</span></p>
      ${failures ? `<ul>${failures}</ul>` : '<p class="ok">No binding rule fired.</p>'}
    </div>`;
}

function consumerPanel(outcome: ConsumeOutcome, title: string, note: string): string {
  const rows = outcome.checks
    .map(
      (check) =>
        `<tr><th scope="row">${esc(check.label)}</th>` +
        `<td>${verdict(check.passed, 'pass', 'fail')}</td>` +
        `<td class="mono">${esc(check.expected)}</td>` +
        `<td class="mono">${esc(check.observed)}</td>` +
        `<td>${esc(check.source)}</td></tr>`,
    )
    .join('');
  const decision = outcome.authorized
    ? `<p class="${outcome.role === 'administrator' ? 'no' : 'ok'}">
         Authorized <span class="mono">${esc(outcome.subject)}</span> as
         <strong>${esc(outcome.role)}</strong>, granting: ${esc(outcome.rights.join('; '))}</p>`
    : `<p class="ok">Refused at <strong>${esc(outcome.failedLayer)}</strong> —
         ${esc(outcome.reason)}</p>`;
  return `
    <div class="card">
      <h3>${esc(title)}</h3>
      <p class="status">${esc(note)}</p>
      <p>Assertion selection: <span class="mono">${esc(outcome.selectionMethod)}</span></p>
      ${decision}
      ${
        rows
          ? `<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(title)} profile checks">
               <table>
                 <thead><tr><th scope="col">Profile rule</th><th scope="col">Result</th>
                 <th scope="col">Expected</th><th scope="col">Observed</th><th scope="col">Source</th></tr></thead>
                 <tbody>${rows}</tbody>
               </table>
             </div>`
          : '<p>No profile rule was reached.</p>'
      }
    </div>`;
}

function censusPanel(report: ScenarioReport): string {
  const rows = report.census
    .map(
      (entry) =>
        `<tr><td class="mono">${esc(entry.id ?? 'no ID')}</td>` +
        `<td class="mono">${esc(entry.subject || 'none')}</td>` +
        `<td>${esc(entry.depth)}</td>` +
        `<td>${
          entry.id === report.verification.verifiedElementId
            ? '<span class="ok">covered by the signature</span>'
            : entry.id === report.vulnerable.selectedAssertionId
              ? '<span class="no">read by the vulnerable consumer</span>'
              : '<span class="warnc">neither</span>'
        }</td></tr>`,
    )
    .join('');
  return `
    <div class="table-wrap" tabindex="0" role="region" aria-label="Assertions in the document">
      <table>
        <caption>Every saml:Assertion in the document, in document order. Depth 1 is a direct
          child of samlp:Response.</caption>
        <thead><tr><th scope="col">ID</th><th scope="col">Subject</th>
        <th scope="col">Depth</th><th scope="col">Role in this run</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function renderScenario(report: ScenarioReport): void {
  const divergence =
    report.vulnerable.authorized !== report.repaired.authorized ||
    report.vulnerable.subject !== report.repaired.subject;
  $('scenarioBody').innerHTML = `
    <p><strong>${esc(report.title)}</strong> — profile ${esc(report.profileId)}, identity
      provider key ${esc(report.idpFingerprint)}.</p>
    ${censusPanel(report)}
    ${layerPanel(report)}
    <div class="grid2">
      ${consumerPanel(
        report.vulnerable,
        'Vulnerable consumer',
        'Verifies with a library, then asks the document again which assertion to use. ' +
          'This is the deliberate anti-pattern.',
      )}
      ${consumerPanel(
        report.repaired,
        'Repaired consumer',
        'Verification returns the element. There is no second query to get wrong.',
      )}
    </div>
    <p class="status">${
      divergence
        ? 'The two consumers disagree on this document. The cryptography is identical for both.'
        : 'The two consumers agree on this document.'
    }</p>
    <h3>The document, as delivered</h3>
    <pre class="doc" tabindex="0" role="region" aria-label="The SAML response XML"
      id="documentXml">${esc(report.documentXml)}</pre>`;
  $('scenarioStatus').textContent =
    `${report.title}: vulnerable consumer ${
      report.vulnerable.authorized ? `authorized ${report.vulnerable.subject}` : 'refused'
    }; repaired consumer ${
      report.repaired.authorized ? `authorized ${report.repaired.subject}` : 'refused'
    }.`;
}

function renderControls(rows: ControlRow[]): void {
  const body = rows
    .map(
      (row) =>
        `<tr><th scope="row">${esc(row.name)}</th>` +
        `<td>${esc(row.family)}</td>` +
        `<td>${esc(row.expectation)}</td>` +
        `<td class="mono">${esc(row.vulnerableOutcome)}</td>` +
        `<td class="mono">${esc(row.repairedOutcome)}</td>` +
        `<td>${verdict(row.asExpected, 'as expected', 'NOT as expected')}</td>` +
        `<td>${esc(row.source)}</td></tr>`,
    )
    .join('');
  const unexpected = rows.filter((row) => !row.asExpected).length;
  $('controlsBody').innerHTML = `
    <div class="table-wrap" tabindex="0" role="region" aria-label="Negative controls">
      <table>
        <caption>Each control must fail, visibly, at its own layer and for its own reason.
          Signature-byte tampering and signature wrapping are different rows on purpose:
          the first breaks the cryptography and both consumers catch it, the second breaks
          nothing cryptographic and only one consumer catches it.</caption>
        <thead><tr><th scope="col">Control</th><th scope="col">Family</th>
        <th scope="col">Expected</th><th scope="col">Vulnerable consumer</th>
        <th scope="col">Repaired consumer</th><th scope="col">Verdict</th>
        <th scope="col">Source</th></tr></thead>
        <tbody id="controlsRows">${body}</tbody>
      </table>
    </div>`;
  $('controlsStatus').textContent =
    `${rows.length} controls run; ${rows.length - unexpected} behaved as this page predicted` +
    `${unexpected === 0 ? '.' : `; ${unexpected} did not.`}`;
}

async function run(
  label: string,
  statusId: string,
  body: () => Promise<void>,
  retire: () => void,
): Promise<void> {
  if (busy) return;
  setBusy(true);
  retire();
  $(statusId).textContent = `Running ${label}…`;
  try {
    await body();
  } catch (error) {
    $(statusId).textContent = `${label} failed: ${(error as Error).name}: ${(error as Error).message}`;
  } finally {
    setBusy(false);
  }
}

$('btnBaseline').addEventListener('click', () => {
  void run(
    'the honest baseline',
    'scenarioStatus',
    async () => renderScenario(await (await lesson()).runBaseline(await ensureParties())),
    retireControls,
  );
});

$('btnWrapping').addEventListener('click', () => {
  void run(
    'the wrapping attack',
    'scenarioStatus',
    async () => renderScenario(await (await lesson()).runWrapping(await ensureParties())),
    retireControls,
  );
});

$('btnControls').addEventListener('click', () => {
  void run(
    'every negative control',
    'controlsStatus',
    async () => renderControls(await (await lesson()).runControls(await ensureParties())),
    retireScenario,
  );
});
