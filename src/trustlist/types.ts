/**
 * Trust-List-Monitoring (Baustein A, Prototyp).
 *
 * Eigene, klar als TEST gekennzeichnete Dokument-/Signaturform:
 * Trust Listen werden als JWS (typ `trust-list+jwt.test`) mit einem fest
 * gepinnten TEST-Trust-List-Authority-Schlüssel signiert und per lokalen
 * Mock-HTTP-Server ausgeliefert. Die Produktionsform (ETSI TS 119 612 XML
 * mit XML-DSig / LoTE nach ETSI TS 119 602) wird über die Schnittstelle
 * `TrustListSignatureVerifier` angeschlossen, aber im Prototyp nicht
 * nachgebaut (siehe docs/erweiterung-status.md).
 */
export interface TrustListEntry {
  /** Bezeichner des Trust-Service-Anbieters (Kurzname, keine PII). */
  providerName: string;
  /** ISO-3166-1-alpha-2 (zwei Zeichen). */
  country: string;
  /** Dienst-Typ gemäß ETSI-Vokabular, z. B. `https://uri.etsi.org/TrstSvc/eSig/QES_Prov`. */
  serviceType: string;
  /** SHA-256-Fingerabdruck des als Anker geltenden Zertifikats (DER), hex, klein. */
  trustAnchorX509Sha256: string;
  /** Subject-Common-Name des Ankerzertifikats. */
  subjectCommonName: string;
  /** Gültigkeit des Ankereintrags in Sekunden (Unix). */
  validFrom: number;
  validTo: number;
}

export interface TrustListDocument {
  /** Bezeichner der Liste (TEST-URN). */
  id: string;
  /** Herausgeber der Liste (Identifikator, keine PII). */
  issuer: string;
  /** Ausgabezeitpunkt in Sekunden (Unix). */
  issuedAt: number;
  /** Frühester nächster Abruf in Sekunden (Unix). */
  nextUpdate: number;
  version: string;
  entries: TrustListEntry[];
}

export type TrustAnchorChangeKind = 'added' | 'removed' | 'updated';

export interface TrustAnchorChange {
  change: TrustAnchorChangeKind;
  providerName: string;
  subjectCommonName: string;
  fingerprintHex: string;
  serviceType: string;
  at: string;
}