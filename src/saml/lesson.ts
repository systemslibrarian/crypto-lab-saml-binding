/**
 * Orchestration: every figure the interface shows is produced here, by running
 * the protocol, on this run, with keys generated on this run.
 *
 * Nothing is cached between scenarios and nothing is precomputed. Changing an
 * input means re-running, which is why the interface retires a panel rather
 * than leaving a figure beside inputs that did not produce it.
 */
import { generateSigningKeys, shortFingerprint, type SigningKeys } from './keys.js';
import { buildResponse, honestSpec, type ResponseSpec } from './build.js';
import { signResponse } from './sign.js';
import { freshState, type ServiceProviderState } from './checks.js';
import {
  assertionCensus,
  repairedConsume,
  vulnerableConsume,
  type ConsumeOutcome,
} from './consumers.js';
import type { BoundVerification } from './verify.js';
import {
  addUnsupportedTransform,
  duplicateAssertionId,
  removeReferencedId,
  siblingAssertionFirst,
  tamperSignatureBytes,
  tamperSignedSubject,
  wrapInAdvice,
} from './attacks.js';
import { ACS_URL, ALICE, IDP_ENTITY_ID, MALLORY, PROFILE_ID, SP_ENTITY_ID } from './profile.js';

export interface Parties {
  idp: SigningKeys;
  attacker: SigningKeys;
}

export async function newParties(): Promise<Parties> {
  const [idp, attacker] = await Promise.all([generateSigningKeys(), generateSigningKeys()]);
  return { idp, attacker };
}

/**
 * The service provider's own state.
 *
 * `pendingRequestId` is what THIS service provider sent, so it comes from the
 * honest request and never from the document under test. Reading it out of the
 * document would make the InResponseTo check compare an attacker-supplied value
 * with itself, which passes always and checks nothing - a mistake this code
 * made once and the control table caught.
 */
function spState(pendingRequestId: string | null): ServiceProviderState {
  return freshState(SP_ENTITY_ID, ACS_URL, IDP_ENTITY_ID, pendingRequestId);
}

/** The AuthnRequest this service provider is waiting for in every solicited run. */
const PENDING_REQUEST_ID = honestSpec().inResponseTo;

export async function issueSignedResponse(
  parties: Parties,
  spec: ResponseSpec,
  signer: 'idp' | 'attacker' = 'idp',
): Promise<string> {
  const key = signer === 'idp' ? parties.idp.privateKey : parties.attacker.privateKey;
  return signResponse(buildResponse(spec), key, {
    referenceId: spec.assertionId,
    placeInside: 'referenced-element',
  });
}

export interface ScenarioReport {
  id: string;
  title: string;
  documentXml: string;
  census: { id: string | null; subject: string; depth: number }[];
  vulnerable: ConsumeOutcome;
  repaired: ConsumeOutcome;
  verification: BoundVerification;
  idpFingerprint: string;
  profileId: string;
}

async function scenario(
  id: string,
  title: string,
  xml: string,
  parties: Parties,
  pending: string | null,
): Promise<ScenarioReport> {
  // Separate service-provider state per consumer: a shared consumed-ID set
  // would make whichever consumer ran second look like it caught a replay.
  const vulnerable = await vulnerableConsume(xml, parties.idp.publicKey, spState(pending));
  const repaired = await repairedConsume(xml, parties.idp.publicKey, spState(pending));
  return {
    id,
    title,
    documentXml: xml,
    census: assertionCensus(xml),
    vulnerable,
    repaired,
    verification: repaired.verification,
    idpFingerprint: shortFingerprint(parties.idp.fingerprint),
    profileId: PROFILE_ID,
  };
}

/** 1 - the honest, signed response both consumers accept. */
export async function runBaseline(parties: Parties): Promise<ScenarioReport> {
  const spec = honestSpec();
  const xml = await issueSignedResponse(parties, spec);
  return scenario('baseline', 'Honest signed response', xml, parties, PENDING_REQUEST_ID);
}

/** 3 and 4 - the wrapped document, and what each consumer does with it. */
export async function runWrapping(parties: Parties): Promise<ScenarioReport> {
  const spec = honestSpec();
  const honest = await issueSignedResponse(parties, spec);
  const wrapped = wrapInAdvice(honest, spec, MALLORY.nameId);
  return scenario('wrapping', 'XML Signature Wrapping', wrapped, parties, PENDING_REQUEST_ID);
}

export interface ControlRow {
  name: string;
  family:
    | 'signature'
    | 'binding'
    | 'profile'
    | 'replay';
  expectation: string;
  vulnerableOutcome: string;
  repairedOutcome: string;
  /** The layer the repaired consumer stopped at, from the run. */
  repairedLayer: string;
  asExpected: boolean;
  source: string;
}

function describe(outcome: ConsumeOutcome): string {
  if (outcome.authorized) return `authorized ${outcome.subject} as ${outcome.role}`;
  return `refused at ${outcome.failedLayer}`;
}

/** 5 - every negative control, each failing at its own layer for its own reason. */
export async function runControls(parties: Parties): Promise<ControlRow[]> {
  const rows: ControlRow[] = [];
  const base = honestSpec();
  const honest = await issueSignedResponse(parties, base);

  async function row(
    name: string,
    family: ControlRow['family'],
    expectation: string,
    xml: string,
    pending: string | null,
    expectRepairedLayer: string,
    source: string,
    options?: { preconsume?: boolean },
  ): Promise<void> {
    const vulnerableState = spState(pending);
    const repairedState = spState(pending);
    if (options?.preconsume) {
      // Replay needs the service provider to have seen this assertion already.
      await vulnerableConsume(xml, parties.idp.publicKey, vulnerableState);
      await repairedConsume(xml, parties.idp.publicKey, repairedState);
    }
    const vulnerable = await vulnerableConsume(xml, parties.idp.publicKey, vulnerableState);
    const repaired = await repairedConsume(xml, parties.idp.publicKey, repairedState);
    const layer = repaired.authorized ? 'accepted' : String(repaired.failedLayer);
    rows.push({
      name,
      family,
      expectation,
      vulnerableOutcome: describe(vulnerable),
      repairedOutcome: describe(repaired),
      repairedLayer: layer,
      asExpected: layer === expectRepairedLayer,
      source,
    });
  }

  // --- L1, the cryptography. Both consumers must catch all of these. ---
  await row(
    'Signature bytes altered',
    'signature',
    'refused at L1 by both consumers: the cryptography itself fails',
    tamperSignatureBytes(honest),
    PENDING_REQUEST_ID,
    'L1 signature',
    'XMLDSIG 1.1 3.2.2',
  );
  await row(
    'Signed subject altered',
    'signature',
    'refused at L1 by both consumers: the reference digest no longer matches',
    tamperSignedSubject(honest, MALLORY.nameId),
    PENDING_REQUEST_ID,
    'L1 signature',
    'XMLDSIG 1.1 3.2.1',
  );
  await row(
    'Signed by an untrusted key',
    'signature',
    'refused at L1: valid RSA, wrong issuer',
    await issueSignedResponse(parties, base, 'attacker'),
    PENDING_REQUEST_ID,
    'L1 signature',
    'SAMLSec 6.4.3',
  );

  // --- L2, the binding. Only the repaired consumer sees these. ---
  await row(
    'XML Signature Wrapping',
    'binding',
    'signature valid, refused at L2: the verified node is not where the response delivers it',
    wrapInAdvice(honest, base, MALLORY.nameId),
    PENDING_REQUEST_ID,
    'L2 binding',
    'Somorovsky et al. 3.4; W3C XMLDSIG Best Practice 14',
  );
  await row(
    'An unsigned assertion placed first',
    'binding',
    'accepted at L4 - and for the right person: the repaired consumer reads the element ' +
      'verification returned, so the attacker\u2019s assertion is simply never consulted',
    siblingAssertionFirst(honest, base, MALLORY.nameId),
    PENDING_REQUEST_ID,
    'accepted',
    'Somorovsky et al. Figure 7; W3C XMLDSIG Best Practice 14',
  );
  await row(
    'Two elements carry one ID',
    'binding',
    'refused at L2 for a determinate reason: "the signed element" has no answer',
    duplicateAssertionId(honest, base, MALLORY.nameId),
    PENDING_REQUEST_ID,
    'L2 binding',
    'SAMLCore 5.4.2; XMLDSIG 1.1 4.4.3.3',
  );
  await row(
    'Reference resolves to nothing',
    'binding',
    'refused at L2 before any cryptography runs',
    removeReferencedId(honest, base),
    PENDING_REQUEST_ID,
    'L2 binding',
    'XMLDSIG 1.1 4.4.3.3',
  );
  await row(
    'A transform outside the declared subset',
    'binding',
    'refused at L2 before any cryptography runs',
    addUnsupportedTransform(honest),
    PENDING_REQUEST_ID,
    'L2 binding',
    'SAMLCore 5.4.4',
  );

  // --- L3, the profile. The documents are honestly signed and genuinely wrong. ---
  const profileCases: [string, string, Partial<ResponseSpec>, string][] = [
    [
      'Audience names another service provider',
      'refused at L3: the assertion is addressed elsewhere',
      { audience: 'https://other.lab.invalid/saml2/sp' },
      'SAMLCore 2.5.1.4; SAMLProf 4.1.4.2',
    ],
    [
      'Recipient is a different consumer URL',
      'refused at L3: delivered somewhere this assertion does not name',
      { recipient: 'https://other.lab.invalid/saml2/acs' },
      'SAMLProf 4.1.4.3; SAMLSec 6.4.2',
    ],
    [
      'Subject confirmation is not bearer',
      'refused at L3: this profile confirms bearer subjects only',
      { subjectConfirmationMethod: 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key' },
      'SAMLProf 4.1.4.2',
    ],
    [
      'SubjectConfirmationData carries NotBefore',
      'refused at L3: the profile forbids the attribute outright',
      { confirmationNotBeforeOffsetSeconds: -120 },
      'SAMLProf 4.1.4.2',
    ],
    [
      'InResponseTo does not match the pending request',
      'refused at L3: this answers a different request',
      { inResponseTo: '_s12authnrequest00000000000000999' },
      'SAMLProf 4.1.4.3',
    ],
    [
      'Assertion expired',
      'refused at L3: outside the Conditions window, beyond skew',
      { notOnOrAfterOffsetSeconds: -600, confirmationNotOnOrAfterOffsetSeconds: -600 },
      'SAMLCore 2.5.1.2; SAMLSec 6.4.1',
    ],
    [
      'Assertion not yet valid',
      'refused at L3: before the Conditions window, beyond skew',
      { notBeforeOffsetSeconds: 600 },
      'SAMLCore 2.5.1.2',
    ],
  ];

  for (const [name, expectation, overrides, source] of profileCases) {
    const spec = { ...honestSpec(), ...overrides } as ResponseSpec;
    // Each case gets a distinct assertion ID so one control cannot consume an
    // ID another control then reports as replayed.
    spec.assertionId = `${spec.assertionId.slice(0, -2)}${rows.length.toString().padStart(2, '0')}`;
    const xml = await issueSignedResponse(parties, spec);
    await row(name, 'profile', expectation, xml, PENDING_REQUEST_ID, 'L3 profile', source);
  }

  // An unsolicited response that still carries InResponseTo.
  const unsolicited = { ...honestSpec(), inResponseTo: null } as ResponseSpec;
  unsolicited.assertionId = `${unsolicited.assertionId.slice(0, -2)}90`;
  const unsolicitedXml = await issueSignedResponse(parties, {
    ...unsolicited,
    inResponseTo: '_s12authnrequest00000000000000001',
  });
  await row(
    'Unsolicited response carries InResponseTo',
    'profile',
    'refused at L3: SAMLProf 4.1.5 says the attribute MUST NOT be present',
    unsolicitedXml,
    null,
    'L3 profile',
    'SAMLProf 4.1.5',
  );

  // --- Replay. ---
  const replaySpec = { ...honestSpec() } as ResponseSpec;
  replaySpec.assertionId = `${replaySpec.assertionId.slice(0, -2)}91`;
  const replayXml = await issueSignedResponse(parties, replaySpec);
  await row(
    'The same assertion, delivered twice',
    'replay',
    'refused at L3 on the second delivery: single use',
    replayXml,
    PENDING_REQUEST_ID,
    'L3 profile',
    'SAMLProf 4.1.4.5; SAMLSec 6.4.5',
    { preconsume: true },
  );

  return rows;
}

export const PARTICIPANTS = { ALICE, MALLORY };
