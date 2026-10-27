import { expect, test } from '@playwright/test';
import { boot, runControls, runScenario } from './gate';

/**
 * Independent claim checks.
 *
 * Every assertion here RECOMPUTES the thing the page claims, from the page's
 * own rendered evidence, rather than reading the sentence the page wrote about
 * it. The rendered SAML document is parsed in the test with the browser's own
 * DOMParser - a different parser from the one the lab ships - and the digests
 * are decoded in the test. If the page's prose and its document ever drifted
 * apart, these fail.
 */

/** Parse the XML the page displays, in the browser, with the browser's parser. */
async function renderedAssertions(page: import('@playwright/test').Page) {
  return page.evaluate(() => {
    const SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
    const DS = 'http://www.w3.org/2000/09/xmldsig#';
    const xml = document.getElementById('documentXml')?.textContent ?? '';
    const doc = new DOMParser().parseFromString(xml, 'application/xml');
    const assertions = Array.from(doc.getElementsByTagNameNS(SAML, 'Assertion')).map(
      (assertion) => {
        let depth = 0;
        let node: Node | null = assertion.parentNode;
        while (node && node.nodeType === 1) {
          depth += 1;
          node = node.parentNode;
        }
        return {
          id: assertion.getAttribute('ID'),
          subject:
            assertion.getElementsByTagNameNS(SAML, 'NameID')[0]?.textContent?.trim() ?? '',
          depth,
        };
      },
    );
    const reference = doc.getElementsByTagNameNS(DS, 'Reference')[0];
    const digestValue = doc.getElementsByTagNameNS(DS, 'DigestValue')[0];
    const toHex = (b64: string) => {
      const binary = atob(b64.replace(/\s+/g, ''));
      let out = '';
      for (let i = 0; i < binary.length; i += 1) {
        out += binary.charCodeAt(i).toString(16).padStart(2, '0');
      }
      return out;
    };
    return {
      assertions,
      referenceUri: reference?.getAttribute('URI') ?? null,
      digestHex: digestValue ? toHex(digestValue.textContent ?? '') : null,
      parseError: doc.getElementsByTagName('parsererror').length > 0,
      signatureCount: doc.getElementsByTagNameNS(DS, 'Signature').length,
    };
  });
}

test('the honest baseline authorizes the subject its own document names', async ({ page }) => {
  await boot(page);
  await runScenario(page, '#btnBaseline');

  const rendered = await renderedAssertions(page);
  expect(rendered.parseError).toBe(false);
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
  expect(rendered.parseError).toBe(false);
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

  // Every profile rule passed for the vulnerable consumer: profile validation
  // is not what stops this, and the page must not suggest it is.
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
  expect(count).toBeGreaterThanOrEqual(17);

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
  expect(body).toContain('S12-WBSSO-POST-SYNTH/1');
  expect(body).toContain('not an OASIS profile identifier');
  expect(body).toContain('Nothing here touches a real identity provider');
  expect(body).toContain('not a production');
  expect(body).toContain('Metadata exchange');
  expect(body).toContain('Single Logout');
  expect(body).toContain('Production XML-parser hardening');
  expect(body).toContain('only consumer broken');
  // And the declared subset is stated, not merely described.
  expect(body).toContain('http://www.w3.org/2001/10/xml-exc-c14n#');
  expect(body).toContain('rsa-sha256');
});
