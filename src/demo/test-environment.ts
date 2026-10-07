/**
 * TEST-Umgebung für die Flow-Demo: Trust List, Onboarding-Gate, OCSP und
 * Mandantenregistrierung. Nur TEST-Material im Arbeitsspeicher.
 *
 * Wichtig für die Ehrlichkeit der Demo: hier wird nichts gemockt, was im
 * Dienst ein echter Pfad ist.
 *
 * - Die TEST Trust List wird als signierte JWS von `TrustListServer`
 *   ausgeliefert und über `TrustListMonitor` mit `JwsTrustListSignatureVerifier`
 *   geprüft. Der Dienst bekommt `monitor.asIssuerTrustPolicy()`, also den
 *   echten `IssuerTrustPolicy`-Pfad.
 * - Das Onboarding-Gate ist das gehärtete `RelyingPartyOnboardingGate` mit
 *   TEST-WRPAC/WRPRC aus `mock-pki.ts`.
 * - Die Sperrprüfung ist der echte `OcspRevocationChecker` gegen den lokalen
 *   TEST-Responder aus `test-ocsp.ts`.
 *
 * Es entstehen ausschließlich kurzlebige TEST-Schlüssel im Arbeitsspeicher.
 * Nichts wird auf die Platte geschrieben oder geloggt, es wird nichts an
 * einen Server außerhalb der Loopback-Adresse gesendet.
 */
import { AuthorityInfoAccessExtension, X509Certificate, X509CertificateGenerator } from '@peculiar/x509';

import { generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { createAccessCa, createWrprcIssuer, createWrprcLeaf, signWrprc, TEST_ENTITLEMENT_MAP, type AccessCa, type WrprcIssuer } from '../onboarding/mock-pki.ts';
import { WRPRC_POLICY_OID } from '../onboarding/oid.ts';
import { OcspRevocationChecker } from '../onboarding/ocsp-revocation.ts';
import { TokenStatusListChecker } from '../service/credential-status.ts';
import { JwsTrustListSignatureVerifier, TrustListMonitor, sha256Hex, type IssuerTrustPolicy } from '../trustlist/monitor.ts';
import { TrustListServer, buildTrustListDocument, trustListEntry } from '../trustlist/mock-server.ts';
import { TestOcspResponder, type OcspStatus } from './test-ocsp.ts';
import { TestStatusListServer } from './test-status-list.ts';
import type { RegistrationMaterial } from '../service/tenant.ts';

export const DEMO_TENANT_ID = 'flow-demo';
export const DEMO_SUBJECT_CN = 'Beispiel GmbH (TEST)';
const REGISTRY_URI = 'https://TEST-registrar.example/api/v1';
const SERVICE_PROVIDER_URI = TEST_ENTITLEMENT_MAP['0.4.0.19475.1.1'];

/**
 * TEST-Ausstellerzertifikat mit OCSP-AIA auf den lokalen Responder.
 *
 * Abweichung von `generateTestKeyMaterial`: es kommt die AIA-Erweiterung
 * (id-ad-ocsp) dazu, weil die Demo den Sperrstatus über OCSP beziehen will.
 * Zertifikate erzeugt weiterhin @peculiar/x509, es ist kein eigener
 * Zertifikatsbau.
 */
export async function createTestIssuerWithAia(name: string, ocspUrl: string): Promise<TestKeyMaterial> {
  const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.randomUUID().replace(/-/g, ''),
    name: `CN=${name}, C=DE`,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    keys: keyPair,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [new AuthorityInfoAccessExtension({ ocsp: ocspUrl }, false)],
  });
  const certDerBytes = new Uint8Array(cert.rawData);
  const publicJwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicJwk,
    x5cBase64: Buffer.from(certDerBytes).toString('base64'),
    certDerBytes,
  };
}

async function buildRegistration(accessCa: AccessCa, wrprcIssuer: WrprcIssuer): Promise<RegistrationMaterial> {
  const wrpac = await accessCa.issueWrpac({
    subjectCn: DEMO_SUBJECT_CN,
    entitlementOids: [Object.keys(TEST_ENTITLEMENT_MAP)[0]],
  });
  const leaf = await createWrprcLeaf(wrprcIssuer, DEMO_SUBJECT_CN);
  const now = Math.floor(Date.now() / 1000);
  const wrprc = await signWrprc(
    {
      sub: 'demo-wrp-1',
      iat: now,
      exp: now + 3600,
      registry_uri: REGISTRY_URI,
      entitlements: [SERVICE_PROVIDER_URI],
      policy_id: [WRPRC_POLICY_OID],
    },
    leaf.key.privateKey,
    [leaf.certDer, wrprcIssuer.certDer],
  );
  return { wrpacChain: wrpac.chain, wrprc };
}

export interface DemoTestEnvironment {
  /** TEST-Aussteller auf der Trust List, OCSP `good`. */
  issuer: TestKeyMaterial;
  /** TEST-Aussteller auf der Trust List, OCSP `revoked`. */
  revokedIssuer: TestKeyMaterial;
  /** TEST-Aussteller, der bewusst nicht auf der Trust List steht. */
  untrustedIssuer: TestKeyMaterial;
  /** TEST-Inhaberschlüssel der Mock-Wallet (Key-Binding). */
  holder: TestKeyMaterial;
  registration: RegistrationMaterial;
  /** Access-CA-Anker (DER) für das Onboarding-Gate. */
  accessCaAnchors: Uint8Array[];
  /** WRPRC-Issuer-Anker (DER) für das Onboarding-Gate. */
  wrprcIssuerAnchors: Uint8Array[];
  issuerTrust: IssuerTrustPolicy;
  ocspChecker: OcspRevocationChecker;
  /** Lokaler TEST-Status-List-Server mit VALID/INVALID/SUSPENDED. */
  statusListServer: TestStatusListServer;
  /** URI der TEST-Liste; kein Demo-Szenario aktiviert sie automatisch. */
  statusListUri: string;
  /** Echter Checker für spätere TEST-Szenarien, nicht automatisch verdrahtet. */
  credentialStatus: TokenStatusListChecker;
  close(): Promise<void>;
}

/**
 * Baut die komplette TEST-Umgebung. `revokedIssuerStatus` steuert, ob der
 * Sperrfall im Gutfall steckt; für die Demo-Szenarien wird `revoked` gesetzt.
 */
export interface BuildDemoTestEnvironmentOptions {
  /** Sperrstatus des `revokedIssuer`; die Demo-Szenarien setzen `revoked`. */
  revokedIssuerStatus?: OcspStatus;
}

/**
 * Baut die komplette TEST-Umgebung. Reihenfolge ist wichtig: der OCSP-Responder
 * startet zuerst, weil die Ausstellerzertifikate seine URL mit dem Port in die
 * AIA-Erweiterung schreiben müssen.
 */
export async function buildDemoTestEnvironment(options: BuildDemoTestEnvironmentOptions): Promise<DemoTestEnvironment> {
  const authority = await generateTestKeyMaterial('Demo Trust-List-Authority TEST');
  const accessCa = await createAccessCa('Demo Access CA TEST ONLY');
  const wrprcIssuer = await createWrprcIssuer('Demo WRPRC Issuer TEST ONLY');
  const registration = await buildRegistration(accessCa, wrprcIssuer);
  const holder = await generateTestKeyMaterial('Demo Wallet Holder TEST');

  const responder = new TestOcspResponder({ issuers: [] });
  const ocspBaseUrl = await responder.start();

  const revokedStatus = options.revokedIssuerStatus ?? 'revoked';
  const issuer = await createTestIssuerWithAia('Demo Wallet Issuer TEST', `${ocspBaseUrl}/ocsp`);
  const revokedIssuer = await createTestIssuerWithAia('Demo Wallet Issuer Revoked TEST', `${ocspBaseUrl}/ocsp`);
  const untrustedIssuer = await createTestIssuerWithAia('Demo Wallet Issuer Untrusted TEST', `${ocspBaseUrl}/ocsp`);

  responder.addIssuer({ material: issuer, cert: new X509Certificate(new Uint8Array(issuer.certDerBytes)), status: 'good' });
  responder.addIssuer({ material: revokedIssuer, cert: new X509Certificate(new Uint8Array(revokedIssuer.certDerBytes)), status: revokedStatus });
  responder.addIssuer({ material: untrustedIssuer, cert: new X509Certificate(new Uint8Array(untrustedIssuer.certDerBytes)), status: 'good' });

  const ocspChecker = new OcspRevocationChecker({ allowInsecureHttp: true, timeoutMs: 2_000 });
  const statusListServer = new TestStatusListServer();
  const statusListUri = await statusListServer.start(issuer);
  const credentialStatus = new TokenStatusListChecker({
    trustedSigners: () => [issuer.certDerBytes],
    allowInsecureHttp: true,
    timeoutMs: 2_000,
  });

  // Trust List: der Aussteller mit gutem Status und der gesperrte stehen
  // darauf, der nicht vertrauenswürdige bewusst nicht.
  const trustServer = new TrustListServer({ authorityKey: authority });
  const nowSeconds = Math.floor(Date.now() / 1000);
  const trustUri = await trustServer.start(
    buildTrustListDocument({
      id: 'demo-trustlist',
      issuer: 'Demo Trust-List-Authority 1',
      issuedAt: nowSeconds - 60,
      nextUpdate: nowSeconds + 3600,
      version: '1',
      entries: [
        trustListEntry({ providerName: 'Demo Wallet Issuer', subjectCommonName: 'Demo Wallet Issuer TEST', anchorFingerprintHex: sha256Hex(issuer.certDerBytes) }),
        trustListEntry({ providerName: 'Demo Wallet Issuer Revoked', subjectCommonName: 'Demo Wallet Issuer Revoked TEST', anchorFingerprintHex: sha256Hex(revokedIssuer.certDerBytes) }),
      ],
    }),
  );
  const monitor = new TrustListMonitor({
    uri: `${trustUri}/trustlist`,
    fetcher: async (uri) => {
      const res = await fetch(uri);
      return { status: res.status, body: await res.text() };
    },
    verifier: new JwsTrustListSignatureVerifier(authority.publicJwk),
  });
  await monitor.refresh();

  return {
    issuer,
    revokedIssuer,
    untrustedIssuer,
    holder,
    registration,
    accessCaAnchors: [accessCa.caCertDer],
    wrprcIssuerAnchors: [wrprcIssuer.certDer],
    issuerTrust: monitor.asIssuerTrustPolicy(),
    ocspChecker,
    statusListServer,
    statusListUri,
    credentialStatus,
    close: async () => {
      await statusListServer.close();
      await responder.close();
      await trustServer.close();
    },
  };
}
