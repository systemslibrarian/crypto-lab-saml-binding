import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    // The XML in this lab is parsed by @xmldom/xmldom in the page and in the
    // tests alike, so the suite needs no DOM environment of its own. A lesson
    // about which node was selected must not depend on which DOM parsed it.
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/saml/**'],
      reporter: ['text', 'html'],
    },
  },
});
