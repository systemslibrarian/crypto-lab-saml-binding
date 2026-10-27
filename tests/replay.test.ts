import { beforeAll, describe, expect, it } from 'vitest';
import { honestSpec, type ResponseSpec } from '../src/saml/build.js';
import { issueSignedResponse, newParties, type Parties } from '../src/saml/lesson.js';
import { repairedConsume, vulnerableConsume } from '../src/saml/consumers.js';
import { freshState } from '../src/saml/checks.js';
import { ACS_URL, IDP_ENTITY_ID, SP_ENTITY_ID } from '../src/saml/profile.js';

/**
 * Single use.
 *
 * Profiles 4.1.4.5: "The service provider MUST ensure that bearer assertions
 * are not replayed, by maintaining the set of used ID values for the length of
 * time for which the assertion would be considered valid based on the
 * NotOnOrAfter attribute in the SubjectConfirmationData."
 *
 * The interesting cases are not the replay itself but the two ways a consumed
 * set goes wrong: recording an assertion that was REJECTED, which would let a
 * bad document poison a later good one, and failing to isolate one service
 * provider's state from another's.
 */

let parties: Parties;
const PENDING = honestSpec().inResponseTo;

function state() {
  return freshState(SP_ENTITY_ID, ACS_URL, IDP_ENTITY_ID, PENDING);
}

beforeAll(async () => {
  parties = await newParties();
}, 60_000);

describe('replay', () => {
  it('accepts the first delivery and refuses the second', async () => {
    const xml = await issueSignedResponse(parties, honestSpec());
    const sp = state();
    const first = await repairedConsume(xml, parties.idp.publicKey, sp);
    const second = await repairedConsume(xml, parties.idp.publicKey, sp);
    expect(first.authorized).toBe(true);
    expect(second.authorized).toBe(false);
    expect(second.failedLayer).toBe('L3 profile');
    expect(second.checks.find((row) => row.name === 'single-use')?.passed).toBe(false);
  }, 60_000);

  it('catches a replay in the vulnerable consumer too: this is not the wrapping defect', async () => {
    const xml = await issueSignedResponse(parties, honestSpec());
    const sp = state();
    await vulnerableConsume(xml, parties.idp.publicKey, sp);
    const second = await vulnerableConsume(xml, parties.idp.publicKey, sp);
    expect(second.authorized).toBe(false);
    expect(second.failedLayer).toBe('L3 profile');
  }, 60_000);

  it('accepts a second, differently identified assertion', async () => {
    const sp = state();
    const first = await issueSignedResponse(parties, honestSpec());
    const otherSpec = { ...honestSpec() } as ResponseSpec;
    otherSpec.assertionId = '_s12assertion000000000000000000002';
    const second = await issueSignedResponse(parties, otherSpec);
    expect((await repairedConsume(first, parties.idp.publicKey, sp)).authorized).toBe(true);
    expect((await repairedConsume(second, parties.idp.publicKey, sp)).authorized).toBe(true);
  }, 60_000);

  it('does not consume the ID of an assertion it rejected', async () => {
    // A rejected document must not be able to deny service to a later honest
    // one that happens to carry the same ID.
    const sp = state();
    const badSpec = { ...honestSpec(), audience: 'https://other.lab.invalid/saml2/sp' } as ResponseSpec;
    const bad = await issueSignedResponse(parties, badSpec);
    const rejected = await repairedConsume(bad, parties.idp.publicKey, sp);
    expect(rejected.authorized).toBe(false);
    expect(sp.consumed.size).toBe(0);

    const good = await issueSignedResponse(parties, honestSpec());
    const accepted = await repairedConsume(good, parties.idp.publicKey, sp);
    expect(accepted.authorized).toBe(true);
    expect(sp.consumed.size).toBe(1);
  }, 60_000);

  it('keeps one service provider’s consumed set out of another’s', async () => {
    const xml = await issueSignedResponse(parties, honestSpec());
    const a = state();
    const b = state();
    expect((await repairedConsume(xml, parties.idp.publicKey, a)).authorized).toBe(true);
    expect((await repairedConsume(xml, parties.idp.publicKey, b)).authorized).toBe(true);
  }, 60_000);
});
