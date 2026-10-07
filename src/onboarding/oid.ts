/**
 * OID- und Namens-Konstanten für das EUDI-Wallet-Relying-Party-Regime
 * (Baustein B, Prototyp). Werte folgen den ETSI-WRPA-Arcs
 * `0.4.0.19475.*` (eudiwrp) bzw. dem ETSI-URI-Vokabular
 * `https://uri.etsi.org/19475/Entitlement/<Name>`.
 *
 * Die konkrete Numerierung der zehn Entitlement-Achsen folgt Annex A der
 * ETSI TS 119 475 V1.2.1 (2026-03): A.1 definiert den Basis-Arc
 * `0.4.0.19475.1`, A.2.1–A.2.10 die Referenznummern .1–.10 (OID) mit den
 * zugehörigen URIs `https://uri.etsi.org/19475/Entitlement/<Name>`.
 */
export const ETSI_EUDIWRP_ARC = '0.4.0.19475';

/** Entitlement-OID-Arc (Werte kartieren auf KR-Anhang-A.2-URIs). */
export const ID_ETSI_WRPA_ENTITLEMENT_ARC = `${ETSI_EUDIWRP_ARC}.1`;

/** ETSI-EUDIWRP-Policy-Identifiers (TS 119 411-8 §5.3). */
export const ID_ETSI_WRPA_POLICY_IDENTIFIERS_ARC = `${ETSI_EUDIWRP_ARC}.3`;

/** WRPRC-Policy-OID (TS 119 475, `wrprcPolicyOID`). */
export const WRPRC_POLICY_OID = `${ID_ETSI_WRPA_POLICY_IDENTIFIERS_ARC}.1`;

export const OID_ANY_EXTENDED_KEY_USAGE = '2.5.29.37.0';
export const OID_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';

export const ENTITLEMENTS_NS = 'https://uri.etsi.org/19475/Entitlement/';

/**
 * Die zehn auf EU-Ebene definierten Entitlements mit OID, URI und
 * Normfundstelle — ETSI TS 119 475 V1.2.1 (2026-03), Anhang A.2.1–A.2.10.
 *
 * Dies ist die **einzige** normative Zuordnungstabelle im Code. OID, URI und
 * Abschnitt stehen bewusst in einem Eintrag, damit die beiden zuvor getrennt
 * geführten Listen (`ENTITLEMENT_URIS` und die vier Einträge große TEST-Karte in
 * `mock-pki.ts`) nicht mehr auseinanderlaufen können: genau diese Lücke war der
 * Grund, warum das Onboarding-Gate außerhalb des Entwicklungsschalters jede
 * Entitlement-OID mit `entitlement_unknown` ablehnte.
 *
 * **Keine Berechtigungsquelle.** Die Tabelle löst OIDs zu *Namen* auf. Welche
 * Entitlements ein WRP tatsächlich hält, steht laut ETSI TS 119 475 V1.2.1
 * (2026-03), Klausel 4.2 im WRPRC und im nationalen Register — nicht in diesem
 * Code. Siehe [interne Notiz, nicht veröffentlicht], Abschnitte 4 und 5.
 */
export const NORMATIVE_ENTITLEMENTS: readonly {
  readonly oid: string;
  readonly uri: string;
  readonly clause: string;
}[] = [
  { oid: `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.1`, uri: `${ENTITLEMENTS_NS}Service_Provider`, clause: 'A.2.1' },
  { oid: `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.2`, uri: `${ENTITLEMENTS_NS}QEAA_Provider`, clause: 'A.2.2' },
  { oid: `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.3`, uri: `${ENTITLEMENTS_NS}Non_Q_EAA_Provider`, clause: 'A.2.3' },
  { oid: `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.4`, uri: `${ENTITLEMENTS_NS}PUB_EAA_Provider`, clause: 'A.2.4' },
  { oid: `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.5`, uri: `${ENTITLEMENTS_NS}PID_Provider`, clause: 'A.2.5' },
  { oid: `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.6`, uri: `${ENTITLEMENTS_NS}QCert_for_ESeal_Provider`, clause: 'A.2.6' },
  { oid: `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.7`, uri: `${ENTITLEMENTS_NS}QCert_for_ESig_Provider`, clause: 'A.2.7' },
  { oid: `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.8`, uri: `${ENTITLEMENTS_NS}rQSealCDs_Provider`, clause: 'A.2.8' },
  { oid: `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.9`, uri: `${ENTITLEMENTS_NS}rQSigCDs_Provider`, clause: 'A.2.9' },
  { oid: `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.10`, uri: `${ENTITLEMENTS_NS}ESig_ESeal_Creation_Provider`, clause: 'A.2.10' },
];

/** Bekanntes Entitlement-URI-Vokabular (ETSI, KR-Anhang A.2), aus der Tabelle abgeleitet. */
export const ENTITLEMENT_URIS: readonly string[] = NORMATIVE_ENTITLEMENTS.map((e) => e.uri);

/**
 * Normative OID -> URI, eingefroren. Basis jeder Produktionskarte, siehe
 * `src/onboarding/entitlement-source.ts`.
 */
export const NORMATIVE_ENTITLEMENT_MAP: Readonly<Record<string, string>> = Object.freeze(
  Object.fromEntries(NORMATIVE_ENTITLEMENTS.map((e) => [e.oid, e.uri])),
);

export function isEntitlementUri(value: string): boolean {
  return ENTITLEMENT_URIS.includes(value);
}

export function isOidUnder(oid: string, arc: string): boolean {
  return oid === arc || oid.startsWith(`${arc}.`);
}