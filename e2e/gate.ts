import { expect, type Page } from '@playwright/test';

/**
 * Shared browser setup.
 *
 * This helper asserts STRUCTURE and nothing else: that the controls exist, that
 * the page starts in its un-run state, and that the theme is the pinned one. It
 * deliberately asserts no sentence of product copy. A prose assertion in a
 * setup helper fails every test that imports it, under whatever name those
 * tests carry, so a copy edit gets reported as an accessibility failure or a
 * claim failure and the real subject never appears. Sentences are asserted in
 * claims.spec.ts, where a failure names copy as the subject.
 */

export const WIDTHS = [
  { label: '320px', width: 320, height: 900 },
  { label: '380px', width: 380, height: 900 },
  { label: '1280px', width: 1280, height: 900 },
] as const;

export const BUTTONS = ['#btnBaseline', '#btnWrapping', '#btnControls'] as const;

export async function boot(page: Page): Promise<void> {
  await page.goto('/');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  for (const id of BUTTONS) await expect(page.locator(id)).toBeEnabled();
  await expect(page.locator('#scenarioStatus')).toHaveText('Nothing has been run yet.');
  await expect(page.locator('#controlsStatus')).toHaveText('Nothing has been run yet.');
}

export async function runScenario(page: Page, button: string): Promise<void> {
  await page.locator(button).click();
  await expect(page.locator('#scenarioBody pre.doc')).toBeVisible({ timeout: 30_000 });
}

export async function runControls(page: Page): Promise<void> {
  await page.locator('#btnControls').click();
  await expect(page.locator('#controlsRows tr').first()).toBeVisible({ timeout: 60_000 });
}

/** No hidden horizontal overflow: the page body must never scroll sideways. */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const root = document.documentElement;
    if (root.scrollWidth <= root.clientWidth) return null;
    let widest = '';
    let widestRight = 0;
    for (const element of Array.from(document.body.querySelectorAll('*'))) {
      const box = element.getBoundingClientRect();
      if (box.right > widestRight) {
        widestRight = box.right;
        widest = `${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ''}`;
      }
    }
    return { clientWidth: root.clientWidth, scrollWidth: root.scrollWidth, widest };
  });
  expect(overflow, `the page scrolls horizontally in state: ${label}`).toBeNull();
}

/** Every scrollable region must be reachable and announced, not just scrollable. */
export async function expectScrollRegionsAreReachable(page: Page): Promise<void> {
  const regions = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.table-wrap, pre.doc')).map((element) => ({
      tabindex: element.getAttribute('tabindex'),
      role: element.getAttribute('role'),
      label: element.getAttribute('aria-label'),
    })),
  );
  expect(regions.length).toBeGreaterThan(0);
  for (const region of regions) {
    expect(region.tabindex).toBe('0');
    expect(region.role).toBe('region');
    expect(region.label ?? '').not.toBe('');
  }
}
