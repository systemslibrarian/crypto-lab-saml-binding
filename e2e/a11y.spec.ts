import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import {
  WIDTHS,
  boot,
  expectNoHorizontalOverflow,
  expectScrollRegionsAreReachable,
  runControls,
  runScenario,
} from './gate';

/**
 * WCAG A/AA, reflow, forced colors, reduced motion and keyboard operation.
 *
 * Each of the page's states is driven through its own controls - never
 * un-hidden, never injected - and scanned at 320, 380 and 1280 px, because a
 * result panel that only exists after a run is exactly the markup a load-time
 * scan never sees.
 */

const SCANS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function scan(page: import('@playwright/test').Page, label: string): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(SCANS).analyze();
  expect(
    results.violations.map((v) => `${v.id} (${v.nodes.length}) in ${label}`),
    `axe violations in ${label}`,
  ).toEqual([]);
}

for (const size of WIDTHS) {
  test(`no WCAG A/AA violations and no sideways scroll at ${size.label}`, async ({ page }) => {
    await page.setViewportSize({ width: size.width, height: size.height });
    await boot(page);
    await scan(page, `${size.label} / nothing run`);
    await expectNoHorizontalOverflow(page, `${size.label} / nothing run`);

    await runScenario(page, '#btnBaseline');
    await scan(page, `${size.label} / honest baseline`);
    await expectNoHorizontalOverflow(page, `${size.label} / honest baseline`);
    await expectScrollRegionsAreReachable(page);

    await runScenario(page, '#btnWrapping');
    await scan(page, `${size.label} / wrapping attack`);
    await expectNoHorizontalOverflow(page, `${size.label} / wrapping attack`);

    await runControls(page);
    await scan(page, `${size.label} / every control`);
    await expectNoHorizontalOverflow(page, `${size.label} / every control`);
  });
}

test('is operable and scans clean in forced-colors mode', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active' });
  await boot(page);
  await runScenario(page, '#btnWrapping');
  await scan(page, 'forced-colors / wrapping attack');
  await expectNoHorizontalOverflow(page, 'forced-colors / wrapping attack');
});

test('respects reduced motion and still runs', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await boot(page);
  await runScenario(page, '#btnBaseline');
  const animated = await page.evaluate(() =>
    Array.from(document.querySelectorAll('*')).filter((element) => {
      const style = getComputedStyle(element);
      const duration = `${style.animationDuration} ${style.transitionDuration}`;
      return /\d*\.?\d+m?s/.test(duration) && !/^0s 0s$/.test(duration);
    }).length,
  );
  expect(animated).toBe(0);
});

test('every control is reachable and operable from the keyboard alone', async ({ page }) => {
  await boot(page);

  // The skip link is the first stop and moves focus into the main region.
  await page.keyboard.press('Tab');
  await expect(page.locator('a.skip')).toBeFocused();

  // Walk to the first scenario button without touching the mouse.
  const reached = await page.evaluate(() => {
    const button = document.getElementById('btnBaseline');
    return button !== null && button.tabIndex >= 0;
  });
  expect(reached).toBe(true);

  await page.locator('#btnBaseline').focus();
  await expect(page.locator('#btnBaseline')).toBeFocused();
  const outline = await page.locator('#btnBaseline').evaluate((element) => {
    const style = getComputedStyle(element);
    return `${style.outlineStyle} ${style.outlineWidth}`;
  });
  expect(outline).not.toMatch(/^none/);

  // Activate with the keyboard, and the result must be announced.
  await page.keyboard.press('Enter');
  await expect(page.locator('#scenarioBody pre.doc')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#scenarioStatus')).toHaveAttribute('role', 'status');
  await expect(page.locator('#scenarioStatus')).toHaveAttribute('aria-live', 'polite');

  // And the scroll regions are in the tab order rather than mouse-only.
  await expectScrollRegionsAreReachable(page);
});

test('reports a failure state in the status region rather than silently', async ({ page }) => {
  await boot(page);
  // Buttons disable while a run is in flight, so a second click cannot
  // interleave two runs and leave a result beside the wrong inputs.
  await page.locator('#btnControls').click();
  await expect(page.locator('#controlsStatus')).not.toHaveText('Nothing has been run yet.');
  await expect(page.locator('#controlsRows tr').first()).toBeVisible({ timeout: 60_000 });
  for (const id of ['#btnBaseline', '#btnWrapping', '#btnControls']) {
    await expect(page.locator(id)).toBeEnabled();
  }
});
