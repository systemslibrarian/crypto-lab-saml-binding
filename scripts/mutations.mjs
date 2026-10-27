#!/usr/bin/env node
/**
 * The clean-baseline source-mutation gate.
 *
 * A passing suite proves the tests run. It does not prove they would notice if
 * the thing they are about stopped working. This harness checks that directly:
 * it establishes a clean baseline, then for each named mutation it edits one
 * source line, runs ONE owning test file, and requires that file to FAIL.
 *
 * Four rules make the result mean something.
 *
 *   1. The baseline must pass first. A mutation that fails on both sides
 *      proves nothing, so the unmutated run is asserted before any mutation.
 *   2. Every mutation names its owning test. "Some test somewhere went red" is
 *      not evidence that the property is covered.
 *   3. No retries and no skips. A mutation that is caught only sometimes is not
 *      caught.
 *   4. Sources are restored byte for byte, and that is verified by hashing each
 *      file before and after rather than assumed from a successful write.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Each mutation keeps every binding referenced.
 *
 * `noUnusedLocals` and `noUnusedParameters` are on, so deleting an argument or
 * a variable turns the mutation into a BUILD failure rather than a test
 * failure, and a build failure must never be counted as a caught mutation. The
 * idioms below - `x ? y : y`, `cond && false`, `a !== a` - keep every name in
 * use while changing what the code decides.
 */
const MUTATIONS = [
  {
    name: 'the document root no longer has to be a SAML Response',
    file: 'src/saml/verify.ts',
    find: "  if (root.namespaceURI !== NS.samlp || root.localName !== 'Response') {",
    replace:
      "  if ((root.namespaceURI !== NS.samlp || root.localName !== 'Response') && false) {",
    owner: 'tests/binding.test.ts',
  },
  {
    name: 'the assertion signature no longer has to follow its Issuer',
    file: 'src/saml/verify.ts',
    find: '  if (issuerIndex < 0 || signatureIndex !== issuerIndex + 1) {',
    replace: '  if ((issuerIndex < 0 || signatureIndex !== issuerIndex + 1) && false) {',
    owner: 'tests/binding.test.ts',
  },
  {
    name: 'the verified node no longer has to be where the response delivers it',
    file: 'src/saml/verify.ts',
    find: '  if (!direct.some((candidate) => candidate === element)) {',
    replace: '  if (!direct.some((candidate) => candidate === element) && false) {',
    owner: 'tests/wrapping.test.ts',
  },
  {
    name: 'the repaired consumer stops binding to the verified element',
    file: 'src/saml/consumers.ts',
    find: '  const assertion = verification.verifiedElement;',
    replace:
      '  const assertion = assertionsInDocumentOrder(parseXml(xml))[0] ?? ' +
      'verification.verifiedElement;',
    owner: 'tests/wrapping.test.ts',
  },
  {
    name: 'two elements carrying one ID are no longer ambiguous',
    file: 'src/saml/verify.ts',
    find: '  if (matches.length > 1) {',
    replace: '  if (matches.length > 1 && false) {',
    owner: 'tests/binding.test.ts',
  },
  {
    name: 'a reference that resolves to nothing is tolerated',
    file: 'src/saml/verify.ts',
    find: '  if (matches.length === 0) {',
    replace: '  if (matches.length === 0 && false) {',
    owner: 'tests/binding.test.ts',
  },
  {
    name: 'the transform allow-list stops being a list',
    file: 'src/saml/verify.ts',
    find: '  if (!sameTransforms) {',
    replace: '  if (!sameTransforms && false) {',
    owner: 'tests/binding.test.ts',
  },
  {
    name: 'any URI shape is treated as a same-document reference',
    file: 'src/saml/verify.ts',
    find: "  if (!/^#[A-Za-z_][\\w.\\-]*$/.test(uri)) {",
    replace: "  if (!/^#?[A-Za-z_]?[\\w.\\-:/]*$/.test(uri)) {",
    owner: 'tests/binding.test.ts',
  },
  {
    name: 'the reference digest is reported as matching whatever it is',
    file: 'src/saml/verify.ts',
    find: '    digestMatches: hex(digest) === claimed,',
    replace: '    digestMatches: hex(digest) === hex(digest),',
    owner: 'tests/signature.test.ts',
  },
  {
    name: 'dependency disagreement is ignored',
    file: 'src/saml/verify.ts',
    find: '  if (!library.verified) {',
    replace: '  if (!library.verified && false) {',
    owner: 'tests/signature.test.ts',
  },
  {
    name: 'exclusive canonicalization is swapped for inclusive',
    file: 'src/saml/verify.ts',
    find: 'const EXCLUSIVE = () => new xmldsig.XmlCanonicalizer(false, true);',
    replace: 'const EXCLUSIVE = () => new xmldsig.XmlCanonicalizer(false, false);',
    owner: 'tests/canonicalization.test.ts',
  },
  {
    name: 'the audience restriction is no longer compared with this service provider',
    file: 'src/saml/checks.ts',
    find: '      childElements(restriction, NS.saml, \'Audience\').some((a) => textOf(a) === state.entityId),',
    replace: '      childElements(restriction, NS.saml, \'Audience\').some((a) => textOf(a) === textOf(a)),',
    owner: 'tests/profile.test.ts',
  },
  {
    name: 'the recipient is no longer compared with the consumer URL',
    file: 'src/saml/checks.ts',
    find: '    passed: recipient === state.acsUrl,',
    replace: '    passed: recipient === recipient,',
    owner: 'tests/profile.test.ts',
  },
  {
    name: 'InResponseTo is no longer compared with the pending request',
    file: 'src/saml/checks.ts',
    find: '    passed: expectedRequest === null ? inResponseTo === null : inResponseTo === expectedRequest,',
    replace: '    passed: expectedRequest === null ? inResponseTo === null : inResponseTo === inResponseTo,',
    owner: 'tests/profile.test.ts',
  },
  {
    name: 'Response InResponseTo is no longer compared with the pending request',
    file: 'src/saml/checks.ts',
    find:
      '  const responseMatchesRequest =\n' +
      '    expectedRequest === null ? inResponseTo === null : inResponseTo === expectedRequest;',
    replace:
      '  const responseMatchesRequest =\n' +
      '    expectedRequest === null ? inResponseTo === null : inResponseTo === inResponseTo;',
    owner: 'tests/replay.test.ts',
  },
  {
    name: 'a forbidden NotBefore on SubjectConfirmationData is allowed',
    file: 'src/saml/checks.ts',
    find: '    passed: confirmationNotBefore === null,',
    replace: '    passed: confirmationNotBefore === confirmationNotBefore,',
    owner: 'tests/profile.test.ts',
  },
  {
    name: 'a bearer assertion no longer needs an authentication statement',
    file: 'src/saml/checks.ts',
    find: '    passed: authnStatements.length > 0,',
    replace: '    passed: authnStatements.length >= 0,',
    owner: 'tests/profile.test.ts',
  },
  {
    name: 'only the first bearer confirmation is considered',
    file: 'src/saml/checks.ts',
    find: '    candidates.find((candidate) => candidate.accepted) ??',
    replace: '    candidates[0] ??',
    owner: 'tests/profile.test.ts',
  },
  {
    name: 'the validity window loses its upper bound',
    file: 'src/saml/checks.ts',
    find:
      '    (notOnOrAfterRaw === null ||\n' +
      '      (notOnOrAfter !== null && NOW_MS - skewMs < notOnOrAfter));',
    replace:
      '    (notOnOrAfterRaw === null ||\n' +
      '      (notOnOrAfter !== null && (NOW_MS - skewMs < notOnOrAfter || true)));',
    owner: 'tests/profile.test.ts',
  },
  {
    name: 'a malformed Conditions expiry is treated as an absent bound',
    file: 'src/saml/checks.ts',
    find:
      '    (notOnOrAfterRaw === null ||\n' +
      '      (notOnOrAfter !== null && NOW_MS - skewMs < notOnOrAfter));',
    replace:
      '    (notOnOrAfterRaw === null ||\n' +
      '      notOnOrAfter === null || NOW_MS - skewMs < notOnOrAfter);',
    owner: 'tests/profile.test.ts',
  },
  {
    name: 'the allowed clock skew swallows the boundary',
    file: 'src/saml/profile.ts',
    find: 'export const CLOCK_SKEW_SECONDS = 60;',
    replace: 'export const CLOCK_SKEW_SECONDS = 86400;',
    owner: 'tests/profile.test.ts',
  },
  {
    name: 'consumed assertion IDs are never recorded',
    file: 'src/saml/checks.ts',
    find: '    state.consumed.set(assertionId, expiry);',
    replace: '    void expiry;',
    owner: 'tests/replay.test.ts',
  },
  {
    name: 'a rejected assertion burns its ID anyway',
    file: 'src/saml/checks.ts',
    find: '  if (options.consume && !alreadyUsed && results.every((r) => r.passed)) {',
    replace: '  if (options.consume && !alreadyUsed) {',
    owner: 'tests/replay.test.ts',
  },
  {
    name: 'a bad Response envelope check still burns the assertion ID',
    file: 'src/saml/consumers.ts',
    find: '    ...runProfileChecks(assertion, state, { consume: responsePassed }),',
    replace:
      '    ...runProfileChecks(assertion, state, { consume: responsePassed ? true : true }),',
    owner: 'tests/replay.test.ts',
  },
  {
    name: 'the issuer is no longer compared with the trusted identity provider',
    file: 'src/saml/checks.ts',
    find: '    passed: issuer === state.trustedIssuer,',
    replace: '    passed: issuer === issuer,',
    owner: 'tests/profile.test.ts',
  },
  {
    name: 'the page stops retiring stale output',
    file: 'src/main.ts',
    find: "const RETIRED = 'Retired: a different scenario was run.",
    replace: "const STALE_RETIRED = 'Retired: a different scenario was run.",
    owner: 'tests/page-contract.test.ts',
  },
];

const sha = (text) => createHash('sha256').update(text).digest('hex');

function runVitest(files) {
  const result = spawnSync(
    'npx',
    ['vitest', 'run', ...files, '--reporter=dot'],
    { cwd: ROOT, encoding: 'utf8', stdio: 'pipe' },
  );
  return { code: result.status, output: `${result.stdout ?? ''}${result.stderr ?? ''}` };
}

const touched = [...new Set(MUTATIONS.map((m) => m.file))];
const original = new Map();
const originalHash = new Map();
for (const file of touched) {
  const text = readFileSync(join(ROOT, file), 'utf8');
  original.set(file, text);
  originalHash.set(file, sha(text));
}

function restoreAll() {
  for (const file of touched) writeFileSync(join(ROOT, file), original.get(file));
}

const owners = [...new Set(MUTATIONS.map((m) => m.owner))];
process.stdout.write('establishing the clean baseline over every owning test file\n');
const baseline = runVitest(owners);
if (baseline.code !== 0) {
  process.stdout.write(baseline.output);
  process.stdout.write('baseline FAILED: a mutation result would prove nothing\n');
  process.exit(1);
}
process.stdout.write('baseline: unmutated sources PASS\n');

let caught = 0;
for (const [index, mutation] of MUTATIONS.entries()) {
  const path = join(ROOT, mutation.file);
  const before = original.get(mutation.file);
  if (!before.includes(mutation.find)) {
    restoreAll();
    process.stdout.write(
      `mutation ${index + 1} did NOT APPLY: ${mutation.file} no longer contains its anchor\n` +
        `  anchor: ${mutation.find}\n` +
        'A mutation that fails to apply is indistinguishable from one nothing caught.\n',
    );
    process.exit(1);
  }
  const occurrences = before.split(mutation.find).length - 1;
  if (occurrences !== 1) {
    restoreAll();
    process.stdout.write(
      `mutation ${index + 1} anchor is not unique in ${mutation.file} (${occurrences} matches)\n`,
    );
    process.exit(1);
  }

  writeFileSync(path, before.replace(mutation.find, mutation.replace));
  const mutated = readFileSync(path, 'utf8');
  if (sha(mutated) === originalHash.get(mutation.file)) {
    restoreAll();
    process.stdout.write(`mutation ${index + 1} changed nothing on disk\n`);
    process.exit(1);
  }

  const run = runVitest([mutation.owner]);
  restoreAll();

  if (run.code === 0) {
    process.stdout.write(run.output);
    process.stdout.write(
      `mutation ${index + 1} SURVIVED: ${mutation.name}\n` +
        `  owning test ${mutation.owner} still passed\n`,
    );
    process.exit(1);
  }
  caught += 1;
  process.stdout.write(`caught ${caught}/${MUTATIONS.length}: ${mutation.name}\n`);
}

let restoredCleanly = true;
for (const file of touched) {
  if (sha(readFileSync(join(ROOT, file), 'utf8')) !== originalHash.get(file)) {
    restoredCleanly = false;
    process.stdout.write(`RESTORE FAILED: ${file} does not match its original bytes\n`);
  }
}
if (!restoredCleanly) process.exit(1);

process.stdout.write('re-running the clean baseline after restoration\n');
const after = runVitest(owners);
if (after.code !== 0) {
  process.stdout.write(after.output);
  process.stdout.write('the restored baseline FAILED\n');
  process.exit(1);
}

process.stdout.write(
  `all ${MUTATIONS.length} mutation(s) caught by their owning tests; ` +
    'sources restored byte for byte and the clean baseline passes again\n',
);
