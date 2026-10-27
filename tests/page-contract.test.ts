import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * Contracts about the published page that no browser run would catch early.
 *
 * These read the sources as text on purpose: they are about what the repository
 * ships, which is a different question from what a rendered page happens to
 * show on one run.
 */

const main = readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8');
const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const css = readFileSync(new URL('../src/style.css', import.meta.url), 'utf8');
const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const profile = readFileSync(new URL('../src/saml/profile.ts', import.meta.url), 'utf8');

// Emoji ranges, plus the variation selector that turns a glyph into one.
const EMOJI =
  /[\u{1F000}-\u{1FAFF}\u{2190}-\u{21FF}\u{2300}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}]/u;

describe('no emojis anywhere a reader sees', () => {
  for (const [name, text] of [
    ['index.html', html],
    ['src/main.ts', main],
    ['src/style.css', css],
    ['README.md', readme],
  ] as const) {
    it(name, () => {
      const match = EMOJI.exec(text);
      expect(match?.[0] ?? null, `found ${match?.[0]} in ${name}`).toBeNull();
    });
  }
});

describe('one pinned theme, no toggle', () => {
  it('stamps data-theme on the root element before first paint', () => {
    expect(html).toMatch(/<html lang="en" data-theme="dark">/);
    expect(html).toMatch(/color-scheme: dark/);
  });

  it('never reads a stored or system theme preference', () => {
    for (const text of [html, main, css]) {
      expect(text).not.toMatch(/localStorage/);
      expect(text).not.toMatch(/prefers-color-scheme/);
    }
  });

  it('ships no theme control', () => {
    expect(`${html}${main}`).not.toMatch(/theme-toggle|themeToggle/);
  });
});

describe('the page states its own boundaries', () => {
  it('names the profile it implements, and renders that name', () => {
    expect(profile).toContain("PROFILE_ID = 'S12-WBSSO-POST-SYNTH/1'");
    expect(main).toContain('esc(PROFILE_ID)');
    // And says, in the same breath, that the name is this lab's own invention.
    expect(main).toMatch(/not an OASIS profile identifier/);
    expect(profile).toMatch(/not an OASIS profile identifier/);
  });

  it('says it is synthetic and not a production stack', () => {
    expect(main).toMatch(/Nothing here touches a real identity provider/);
    expect(main).toMatch(/not a production\s*\n?\s*SAML stack/);
  });

  it('lists every omission the design record promised', () => {
    for (const omission of [
      'Metadata exchange',
      'Identity provider discovery',
      'Single Logout',
      'Name identifier management',
      'Real trust-anchor administration',
      'XML Encryption',
      'Production XML-parser hardening',
      'wrapping permutations',
      'Other bindings and profiles',
    ]) {
      expect(main, `omission missing: ${omission}`).toContain(omission);
    }
  });

  it('refuses the over-broad claim about other implementations', () => {
    expect(main).toMatch(/only consumer broken\s*\n?\s*here is one this lab wrote/);
  });

  it('labels the vulnerable consumer as a deliberate anti-pattern', () => {
    expect(main).toMatch(/deliberate anti-pattern/);
  });
});

describe('accessibility affordances are in the shipped source', () => {
  it('offers a skip link into the main region', () => {
    expect(html).toContain('class="skip"');
    expect(main).toContain('id="main"');
  });

  it('gives every scrollable region a focusable, labelled container', () => {
    const regions = main.match(/class="table-wrap"[^>]*/g) ?? [];
    expect(regions.length).toBeGreaterThan(2);
    for (const region of regions) {
      expect(region).toContain('tabindex="0"');
      expect(region).toContain('role="region"');
      expect(region).toContain('aria-label');
    }
    expect(main).toMatch(/<pre class="doc" tabindex="0" role="region"/);
  });

  it('announces results through live regions rather than silently', () => {
    expect(main).toContain('id="scenarioStatus" role="status" aria-live="polite"');
    expect(main).toContain('id="controlsStatus" role="status" aria-live="polite"');
  });

  it('honours reduced motion and forced colors', () => {
    expect(css).toContain('@media (prefers-reduced-motion: reduce)');
    expect(css).toContain('@media (forced-colors: active)');
  });

  it('keeps a visible focus indicator', () => {
    expect(css).toContain(':focus-visible');
    expect(css).toMatch(/outline: 3px solid/);
  });
});

describe('stale output is retired rather than left standing', () => {
  it('clears the other panel before a scenario runs', () => {
    expect(main).toContain('const RETIRED =');
    expect(main).toMatch(/retireControls/);
    expect(main).toMatch(/retireScenario/);
  });
});
