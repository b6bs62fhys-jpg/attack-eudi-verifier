/**
 * Onboarding-Gate (Baustein B, Prototyp): Authorization der anfragenden
 * Relying Party am Verifier-Dienst.
 *
 * Ein Mandant ist nur dann „registriert“, wenn er echtes TEST-Material hat:
 * eine WRPAC-Kette, die zu einem konfigurierten Access-CA-Anker schließt und
 * mindestens ein bekanntes Entitlement trägt, und einen gültigen WRPRC
 * (Signatur, x5c-Kette zu WRPRC-Issuer-Anker, Claims, Fenster exp &le; iat + 12
 * Monate). Der gelieferte `registration_ref` (RPRC_19a) wird gegen die
 * verifizierte WRPRC geprüft (registry_uri + client_id/sub); ohne expliziten
 * Wert wird ein Default aus dem Material abgeleitet. Alle Prüfungen laufen nur
 * im Speicher, nur TEST-Material.
 */
import type { TenantStore } from '../service/tenant.ts';
import { ErrRegistrationRefMismatch, ErrTenantNotRegistered, ErrTenantRegistrationInvalid, OnboardingError } from './errors.ts';
import { ENTITLEMENT_URIS } from './oid.ts';
import type { RegistrationRef } from './registration-ref.ts';
import { loadWrpac, validateWrpacChain, type EntitlementMap, type Wrpac } from './wrpac.ts';
import { verifyWrprc, type WrprcRead } from './wrprc.ts';
import { assertRevocationAllowed, STRICT_MODE, type RevocationChecker, type RuntimeMode } from './revocation.ts';

export interface VerifiedTenantRegistration {
  wrpac: Wrpac;
  wrprc: WrprcRead;
}

/** Sicht des Dienstes auf das Onboarding-Gate (schmale Schnittstelle). */
export interface OnboardingGatePolicy {
  verifyTenant(tenantId: string): Promise<VerifiedTenantRegistration>;
  deriveRegistrationRef(registration: VerifiedTenantRegistration): RegistrationRef;
  assertRegistrationRefMatches(ref: RegistrationRef, registration: VerifiedTenantRegistration): void;
}

export interface RelyingPartyOnboardingGateOptions {
  tenants: Pick<TenantStore, 'byId'>;
  /** Access-CA-Anker (DER), auf die die WRPAC-Kette schließen muss. */
  accessCaAnchors: Uint8Array[];
  /** WRPRC-Issuer-Anker (DER), auf die die WRPRC-x5c-Kette schließen muss. */
  wrprcIssuerAnchors: Uint8Array[];
  /** Entitlement-OID -> URI (siehe mock-pki.ts TEST_ENTITLEMENT_MAP). */
  entitlementMap: EntitlementMap;
  /** Zulässige WRPRC-Entitlement-URIs; Default: komplette ETSI-Liste. */
  allowedEntitlements?: readonly string[];
  /**
   * Sperrprüfung (siehe revocation.ts). Pflichtfeld: kein stiller Rückfall
   * mehr auf NO_REVOCATION. Wer noch keine echte OCSP/CRL-Anbindung hat,
   * implementiert das Interface später.
   */
  revocation: RevocationChecker;
  /** Zeitgrenze je Sperrprüfung (ms). */
  revocationTimeoutMs?: number;
  /**
   * Laufzeitmodus aus der zentralen Konfiguration. Ohne Angabe gilt der
   * strenge Modus. NO_REVOCATION ist nur mit Entwicklungsschalter erlaubt,
   * sonst bricht der Aufbau mit ConfigError ab.
   */
  mode?: RuntimeMode;
  /** Uhr für die Prüfung der Gültigkeitszeiträume (injizierbar), Standard: jetzt. */
  now?: () => Date;
  /** Erlaubte Uhrabweichung in Sekunden, Standard 60. */
  clockSkewSeconds?: number;
}

export class RelyingPartyOnboardingGate implements OnboardingGatePolicy {
  private readonly tenants: Pick<TenantStore, 'byId'>;
  private readonly accessCaAnchors: Uint8Array[];
  private readonly wrprcIssuerAnchors: Uint8Array[];
  private readonly entitlementMap: EntitlementMap;
  private readonly allowedEntitlements: readonly string[];
  private readonly revocation: RevocationChecker;
  private readonly revocationTimeoutMs?: number;
  private readonly now: () => Date;
  private readonly clockSkewSeconds?: number;

  constructor(options: RelyingPartyOnboardingGateOptions) {
    this.tenants = options.tenants;
    this.accessCaAnchors = options.accessCaAnchors;
    this.wrprcIssuerAnchors = options.wrprcIssuerAnchors;
    this.entitlementMap = options.entitlementMap;
    this.allowedEntitlements = options.allowedEntitlements ?? ENTITLEMENT_URIS;
    assertRevocationAllowed(options.revocation, options.mode ?? STRICT_MODE);
    this.revocation = options.revocation;
    this.revocationTimeoutMs = options.revocationTimeoutMs;
    this.now = options.now ?? (() => new Date());
    this.clockSkewSeconds = options.clockSkewSeconds;
  }

  /** echtes TEST-Registrierungsmaterial des Mandanten oder `undefined`. */
  materialFor(tenantId: string): { wrpacChain: Uint8Array[]; wrprcRaw: string } | undefined {
    const tenant = this.tenants.byId(tenantId);
    const material = tenant?.registration;
    if (!material || material.wrpacChain.length === 0 || material.wrprc.length === 0) return undefined;
    return { wrpacChain: material.wrpacChain, wrprcRaw: material.wrprc };
  }

  async verifyTenant(tenantId: string): Promise<VerifiedTenantRegistration> {
    const material = this.materialFor(tenantId);
    if (!material) throw new ErrTenantNotRegistered();
    try {
      const now = this.now();
      const wrpac = await loadWrpac(material.wrpacChain[0], { entitlementMap: this.entitlementMap });
      if (wrpac.entitlements.length === 0) throw new Error('kein entitlement auf der karte');
      await validateWrpacChain(material.wrpacChain[0], {
        accessCaAnchors: this.accessCaAnchors,
        revocation: this.revocation,
        revocationTimeoutMs: this.revocationTimeoutMs,
        now,
        clockSkewSeconds: this.clockSkewSeconds,
      });
      const wrprc = await verifyWrprc(material.wrprcRaw, {
        wrprcIssuerAnchors: this.wrprcIssuerAnchors,
        allowedEntitlements: this.allowedEntitlements,
        revocation: this.revocation,
        revocationTimeoutMs: this.revocationTimeoutMs,
        now: Math.floor(now.getTime() / 1000),
        clockSkewSeconds: this.clockSkewSeconds,
      });
      return { wrpac, wrprc };
    } catch (e) {
      if (e instanceof ErrTenantNotRegistered) throw e;
      throw new ErrTenantRegistrationInvalid(e instanceof Error ? e.message : String(e), e instanceof OnboardingError ? e.code : 'unspecified');
    }
  }

  deriveRegistrationRef(registration: VerifiedTenantRegistration): RegistrationRef {
    return {
      clientName: registration.wrpac.subjectCommonName,
      clientId: registration.wrprc.sub,
      registryUri: registration.wrprc.registryUri,
      // Prototyp-Ersatz: ohne Registrar-Abfrage ist der intendierte Verwendungszweck
      // der WRPRC das gewährte Entitlement (ETSI-URI).
      intendedUseId: registration.wrprc.entitlements[0],
    };
  }

  assertRegistrationRefMatches(ref: RegistrationRef, registration: VerifiedTenantRegistration): void {
    if (ref.registryUri !== registration.wrprc.registryUri || ref.clientId !== registration.wrprc.sub) {
      throw new ErrRegistrationRefMismatch();
    }
  }
}