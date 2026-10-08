/**
 * Fehler, der beim Paket 5 aufgefallen ist: Enthielt der x5c-Header den Anker
 * selbst, entfernte die Kettenbildung den Anker, und das Zertifikat davor
 * wurde nie auf Sperrung gefragt. Ein gesperrtes Blatt ging durch, wenn der
 * Aussteller den Anker an den x5c-Header anhängte.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import 'reflect-metadata';

import { createAccessCa, TEST_ENTITLEMENT_MAP } from '../onboarding/mock-pki.ts';
import { MockRevocationList } from '../onboarding/mock-revocation.ts';
import { enforceIssuerChainRevocation } from './issuer-revocation.ts';

async function setup() {
  const ca = await createAccessCa('Anker im x5c CA TEST');
  const leaf = await ca.issueWrpac({ subjectCn: 'Blatt (TEST)', entitlementOids: [Object.keys(TEST_ENTITLEMENT_MAP)[0] as string] });
  const revocation = new MockRevocationList();
  return { ca, leaf, revocation };
}

const rejectsRevoked = (e: unknown) => e instanceof Error && /gesperrt/.test(e.message);

describe('Sperrprüfung der Aussteller-Kette mit dem Anker im x5c', () => {
  it('gesperrtes Blatt ohne Anker im x5c -> abgelehnt (wie bisher)', async () => {
    const { ca, leaf, revocation } = await setup();
    revocation.revoke(leaf.certDer);
    await assert.rejects(enforceIssuerChainRevocation(revocation, [leaf.certDer], [ca.caCertDer]), rejectsRevoked);
  });

  it('gesperrtes Blatt mit angehängtem Anker im x5c -> abgelehnt', async () => {
    const { ca, leaf, revocation } = await setup();
    revocation.revoke(leaf.certDer);
    await assert.rejects(enforceIssuerChainRevocation(revocation, [leaf.certDer, ca.caCertDer], [ca.caCertDer]), rejectsRevoked);
  });

  it('nicht gesperrtes Blatt mit angehängtem Anker -> angenommen (Gegenprobe)', async () => {
    const { ca, leaf, revocation } = await setup();
    await enforceIssuerChainRevocation(revocation, [leaf.certDer, ca.caCertDer], [ca.caCertDer]);
  });

  it('der Anker selbst wird nie gefragt, auch wenn er in der Sperrliste stünde', async () => {
    const { ca, leaf, revocation } = await setup();
    revocation.revoke(ca.caCertDer);
    await enforceIssuerChainRevocation(revocation, [leaf.certDer, ca.caCertDer], [ca.caCertDer]);
    await enforceIssuerChainRevocation(revocation, [ca.caCertDer], [ca.caCertDer]);
  });
});
