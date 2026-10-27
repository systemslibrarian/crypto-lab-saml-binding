import { expect, test } from '@playwright/test';
import { boot, runControls, runScenario } from './gate';

/**
 * Independent claim checks.
 *
 * Every assertion here RECOMPUTES the thing the page claims, from the page's
 * own rendered evidence, rather than reading the sentence the page wrote about
 * it. A token scanner reads the rendered SAML bytes without any XML parser, and
 * the digests are decoded in the test. If the page's prose and its document
 * ever drifted apart, these fail.
 */

/**
 * Recompute the page's facts from the page's own displayed document.
 *
 * This deliberately uses NO XML parser at all - not the lab's, and not the
 * browser's. It walks the serialized bytes the page shows and tracks element
 * nesting directly, which makes it independent of every piece of machinery the
 * implementation uses, and leaves nothing that reinterprets DOM text as markup.
 * (CodeQL flagged the earlier version, which re-parsed the displayed text in
 * the browser with `DOMParser`, as `js/xss-through-dom`. The finding was fair,
 * and this is a better check as well as a safer one.)
 */
interface ScannedAssertion {
  id: string | null;
  subject: string;
  depth: number;
}

interface ScannedDocument {
  assertions: ScannedAssertion[];
  referenceUri: string | null;
  digestHex: string | null;
  signatureCount: number;
}

function attrOf(tag: string, name: string): string | null {
  const match = new RegExp(`\\b${name}="([^"]*)"`).exec(tag);
  return match ? match[1]! : null;
}

function scanDocument(xml: string): ScannedDocument {
  const token = /<(\/?)([A-Za-z_][\w.:-]*)((?:"[^"]*"|[^>"])*?)(\/?)>/g;
  const open: string[] = [];
  const assertionStack: ScannedAssertion[] = [];
  const assertions: ScannedAssertion[] = [];
  let referenceUri: string | null = null;
  let digestBase64: string | null = null;
  let signatureCount = 0;
  let capture: 'nameid' | 'digest' | null = null;
  let buffer = '';
  let cursor = 0;
  let match: RegExpExecArray | null;

  while ((match = token.exec(xml)) !== null) {
    if (capture) buffer += xml.slice(cursor, match.index);
    cursor = token.lastIndex;
    const [, closing, name, attributes, selfClosing] = match;
    const isClose = closing === '/';
    const isSelf = selfClosing === '/';

    if (!isClose) {
      if (name === 'saml:Assertion') {
        const assertion: ScannedAssertion = {
          id: attrOf(attributes ?? '', 'ID'),
          subject: '',
          depth: open.length,
        };
        assertions.push(assertion);
        if (!isSelf) assertionStack.push(assertion);
      }
      if (name === 'ds:Signature') signatureCount += 1;
      if (name === 'ds:Reference') referenceUri = attrOf(attributes ?? '', 'URI');
      if (name === 'saml:NameID' && !isSelf) {
        capture = 'nameid';
        buffer = '';
      }
      if (name === 'ds:DigestValue' && !isSelf) {
        capture = 'digest';
        buffer = '';
      }
      if (!isSelf) open.push(name!);
    } else {
      if (name === 'saml:NameID' && capture === 'nameid') {
        const current = assertionStack[assertionStack.length - 1];
        if (current && current.subject === '') current.subject = buffer.trim();
        capture = null;
      }
      if (name === 'ds:DigestValue' && capture === 'digest') {
        digestBase64 = buffer.trim();
        capture = null;
      }
      if (name === 'saml:Assertion') assertionStack.pop();
      open.pop();
    }
  }

  return {
    assertions,
    referenceUri,
    digestHex: digestBase64 ? Buffer.from(digestBase64, 'base64').toString('hex') : null,
    signatureCount,
  };
}

async function renderedAssertions(
  page: import('@playwright/test').Page,
): Promise<ScannedDocument> {
  const xml = (await page.locator('#documentXml').textContent()) ?? '';
  expect(xml.length, 'the page displayed no document').toBeGreaterThan(0);
  return scanDocument(xml);
}

test('the honest baseline authorizes the subject its own document names', async ({ page }) => {
  await boot(page);
  await runScenario(page, '#btnBaseline');

  const rendered = await renderedAssertions(page);
  expect(rendered.assertions).toHaveLength(1);
  expect(rendered.signatureCount).toBe(1);

  const subject = rendered.assertions[0]!.subject;
  const status = await page.locator('#scenarioStatus').textContent();
  expect(status).toContain(`vulnerable consumer authorized ${subject}`);
  expect(status).toContain(`repaired consumer authorized ${subject}`);

  // And the reference points at that same, only, assertion.
  expect(rendered.referenceUri).toBe(`#${rendered.assertions[0]!.id}`);
});

test('the wrapped document really carries two assertions, nested as the page says', async ({
  page,
}) => {
  await boot(page);
  await runScenario(page, '#btnWrapping');

  const rendered = await renderedAssertions(page);
  expect(rendered.assertions).toHaveLength(2);
  // Recomputed from the document: the attacker's is first and shallow, the
  // signed one is later and deeper.
  expect(rendered.assertions[0]!.depth).toBe(1);
  expect(rendered.assertions[1]!.depth).toBeGreaterThan(1);
  expect(rendered.assertions[0]!.subject).not.toBe(rendered.assertions[1]!.subject);

  // The census table must say exactly that, row for row.
  const censusCells = await page
    .locator('#scenarioBody table tbody tr')
    .first()
    .locator('td')
    .allTextContents();
  expect(censusCells[0]).toBe(rendered.assertions[0]!.id);
  expect(censusCells[1]).toBe(rendered.assertions[0]!.subject);
  expect(censusCells[2]).toBe('1');
});

test('the signature covers the deeper assertion, and the page says which', async ({ page }) => {
  await boot(page);
  await runScenario(page, '#btnWrapping');

  const rendered = await renderedAssertions(page);
  const signedId = rendered.assertions[1]!.id;
  // The reference in the rendered document, recomputed, is the deeper one.
  expect(rendered.referenceUri).toBe(`#${signedId}`);

  const bindingPanel = await page.locator('#scenarioBody .layer').nth(1).textContent();
  expect(bindingPanel).toContain(`#${signedId}`);
  // And the vulnerable consumer read the OTHER one.
  expect(bindingPanel).toContain(rendered.assertions[0]!.id!);
});

test('the digest the page displays is the digest in the document', async ({ page }) => {
  await boot(page);
  await runScenario(page, '#btnBaseline');

  const rendered = await renderedAssertions(page);
  expect(rendered.digestHex).not.toBeNull();

  const l1 = (await page.locator('#scenarioBody .layer').first().textContent()) ?? '';
  const claimed = /Digest claimed by the document:\s*([0-9a-f]+)/.exec(l1);
  const recomputed = /Reference digest recomputed here:\s*([0-9a-f]+)/.exec(l1);
  expect(claimed, `no claimed digest in: ${l1.slice(0, 200)}`).not.toBeNull();
  expect(recomputed).not.toBeNull();

  // Both displayed prefixes must be prefixes of the base64 DigestValue the
  // document actually carries, decoded here in the test.
  expect(rendered.digestHex!.startsWith(claimed![1]!)).toBe(true);
  expect(rendered.digestHex!.startsWith(recomputed![1]!)).toBe(true);
  expect(l1).toContain('match');
});

test('the vulnerable consumer authorizes the attacker and the repaired one refuses', async ({
  page,
}) => {
  await boot(page);
  await runScenario(page, '#btnWrapping');

  const rendered = await renderedAssertions(page);
  const attackerSubject = rendered.assertions[0]!.subject;

  const panels = page.locator('#scenarioBody .grid2 > .card');
  await expect(panels).toHaveCount(2);
  const vulnerable = (await panels.nth(0).textContent()) ?? '';
  const repaired = (await panels.nth(1).textContent()) ?? '';

  expect(vulnerable).toContain('Vulnerable consumer');
  expect(vulnerable).toContain(`Authorized ${attackerSubject}`);
  expect(vulnerable).toContain('administrator');

  expect(repaired).toContain('Repaired consumer');
  expect(repaired).toContain('Refused at');
  expect(repaired).toContain('L2 binding');
  expect(repaired).not.toContain(`Authorized ${attackerSubject}`);

  // Every implemented selected-assertion check passed for the vulnerable
  // consumer: those checks are not what repairs the binding defect.
  const vulnerableFails = await panels
    .nth(0)
    .locator('tbody tr td:nth-child(2)')
    .filter({ hasText: 'fail' })
    .count();
  expect(vulnerableFails).toBe(0);
});

test('every negative control behaves the way the page predicts', async ({ page }) => {
  await boot(page);
  await runControls(page);

  const rows = page.locator('#controlsRows tr');
  const count = await rows.count();
  expect(count).toBe(23);

  const names = await rows.locator('th').allTextContents();
  expect(names).toContain('The signed assertion sits under a non-SAML document root');
  expect(names).toContain('A valid assertion signature is placed under the Response');
  expect(names).toContain('Selected assertion has no authentication statement');
  expect(names).toContain('Conditions carries a malformed time value');
  expect(names).toContain('Response Destination is a different consumer URL');
  expect(names).toContain('Response InResponseTo does not match the pending request');

  const verdicts = await page.locator('#controlsRows tr td:nth-child(6)').allTextContents();
  expect(verdicts.filter((v) => v.trim() !== 'as expected')).toEqual([]);

  const status = await page.locator('#controlsStatus').textContent();
  // The count in the sentence is recomputed from the rendered rows.
  expect(status).toContain(`${count} controls run`);
  expect(status).toContain(`${count} behaved as this page predicted`);
});

test('signature tampering and signature wrapping are separate rows with separate layers', async ({
  page,
}) => {
  await boot(page);
  await runControls(page);

  const rowFor = async (name: string) => {
    const row = page.locator('#controlsRows tr').filter({ hasText: name }).first();
    return {
      family: (await row.locator('td').nth(0).textContent())?.trim(),
      vulnerable: (await row.locator('td').nth(2).textContent())?.trim(),
      repaired: (await row.locator('td').nth(3).textContent())?.trim(),
    };
  };

  const tamper = await rowFor('Signature bytes altered');
  const wrap = await rowFor('XML Signature Wrapping');

  expect(tamper.family).toBe('signature');
  expect(tamper.vulnerable).toContain('L1 signature');
  expect(tamper.repaired).toContain('L1 signature');

  expect(wrap.family).toBe('binding');
  expect(wrap.vulnerable).toMatch(/^authorized/);
  expect(wrap.repaired).toContain('L2 binding');
});

test('running one scenario retires the other panel', async ({ page }) => {
  await boot(page);
  await runScenario(page, '#btnBaseline');
  await expect(page.locator('#scenarioBody pre.doc')).toBeVisible();

  await runControls(page);
  await expect(page.locator('#scenarioStatus')).toContainText('Retired');
  await expect(page.locator('#scenarioBody')).toBeEmpty();

  await runScenario(page, '#btnWrapping');
  await expect(page.locator('#controlsStatus')).toContainText('Retired');
  await expect(page.locator('#controlsBody')).toBeEmpty();
});

test('key material is generated on this run and shown as such', async ({ page }) => {
  await boot(page);
  await expect(page.locator('#idpKey')).toHaveText('not generated yet');
  await runScenario(page, '#btnBaseline');

  const idp = (await page.locator('#idpKey').textContent()) ?? '';
  const attacker = (await page.locator('#attackerKey').textContent()) ?? '';
  expect(idp).toMatch(/^RSA-2048, SPKI SHA-256 [0-9a-f]{8}…[0-9a-f]{8}$/);
  expect(attacker).toMatch(/^RSA-2048, SPKI SHA-256 [0-9a-f]{8}…[0-9a-f]{8}$/);
  expect(idp).not.toBe(attacker);
});

test('the page keeps its profile name, its synthetic warning and its omissions visible', async ({
  page,
}) => {
  await boot(page);
  const body = (await page.locator('main').textContent()) ?? '';
  // HTML source wrapping inserts whitespace into textContent. Collapse it so
  // this test checks the learner-visible sentence rather than source layout.
  const normalizedBody = body.replace(/\s+/g, ' ');
  expect(normalizedBody).toContain('S12-WBSSO-POST-SYNTH/1');
  expect(normalizedBody).toContain('not an OASIS profile identifier');
  expect(normalizedBody).toContain('Nothing here touches a real identity provider');
  expect(normalizedBody).toContain('not a production');
  expect(normalizedBody).toContain('Metadata exchange');
  expect(normalizedBody).toContain('Single Logout');
  expect(normalizedBody).toContain('Production XML-parser hardening');
  expect(normalizedBody).toContain('not a complete XML Schema or SAML profile validator');
  expect(normalizedBody).toContain('Full multi-assertion profile conformance');
  expect(normalizedBody).toContain('only consumer broken');
  // And the declared subset is stated, not merely described.
  expect(normalizedBody).toContain('http://www.w3.org/2001/10/xml-exc-c14n#');
  expect(normalizedBody).toContain('rsa-sha256');
  expect(normalizedBody).toContain('required authentication statement');
  expect(normalizedBody).toContain('one complete confirmation tuple must pass');
  expect(normalizedBody).toContain('refuses duplicate IDs');
});
