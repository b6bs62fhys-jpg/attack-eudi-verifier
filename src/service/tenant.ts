/**
 * Mandantenmodell (Prototyp). Mandanten (Kunden) werden separat angelegt, jede
 * Konfiguration gehört einem Mandanten, API-Schlüssel werden nur als SHA-256-Hash
 * gespeichert. Platzhalter für Zugriffs- und Registrierungszertifikat sind reine
 * TEST-Markierungen, keine Schlüssel – echte Zertifikate kommen später vom
 * Sandbox-Registrar.
 *
 * Seit Baustein B kann ein Mandant zusätzlich echtes TEST-Registrierungsmaterial
 * tragen (WRPAC-Kette + WRPRC, nur im Arbeitsspeicher). Mandanten ohne dieses
 * Material gelten als nicht registriert und werden am Dienst abgelehnt, sobald
 * das Onboarding-Gate aktiviert ist.
 */
import { createHash } from 'node:crypto';

import { resolveRequestProfile, type RequestProfile } from './profile.ts';

export interface RegistrationMaterial {
  /** WRPAC-Kette (Blatt zuerst, dann CA) nach Baustein B – nur TEST, im Speicher. */
  wrpacChain: Uint8Array[];
  /** Signierter WRPRC (JWT) des Mandanten – nur TEST, im Speicher. */
  wrprc: string;
}

export interface TenantConfig {
  id: string;
  name: string;
  /** SHA-256-Hex des API-Schlüssels – der Klartext wird nie gespeichert. */
  apiKeyHash: string;
  requestProfile: RequestProfile;
  /** Nur TEST-Platzhalter, kein Zertifikat und kein Schlüssel. */
  accessCertificateTest: string;
  /** Nur TEST-Platzhalter, kein Zertifikat und kein Schlüssel. */
  registrationCertificateTest: string;
  /** TEST-Registrierungsmaterial (WRPAC-Kette + WRPRC) – optional, siehe oben. */
  registration?: RegistrationMaterial;
  /** Gültigkeitsdauer einer Prüfsitzung in Sekunden. */
  requestTtlSeconds: number;
}

export interface NewTenantInput {
  id: string;
  name: string;
  apiKey: string;
  requestTtlSeconds?: number;
  requestProfile?: string | Record<string, unknown>;
  /** TEST-Registrierungsmaterial (WRPAC-Kette + WRPRC) für das Onboarding-Gate. */
  registration?: RegistrationMaterial;
}

export function hashApiKey(apiKey: string): string {
  return createHash('sha256').update(apiKey).digest('hex');
}

export class TenantStore {
  private readonly tenants = new Map<string, TenantConfig>();

  add(input: NewTenantInput): TenantConfig {
    const id = input.id.trim();
    if (!id || input.name.trim().length === 0) throw new Error('tenant id und name sind Pflicht');
    if (!input.apiKey || input.apiKey.length < 8) throw new Error('API-Schlüssel muss mindestens 8 Zeichen lang sein');
    if (this.tenants.has(id)) throw new Error(`Mandant existiert bereits: ${id}`);
    let requestProfile: RequestProfile;
    try {
      requestProfile = resolveRequestProfile(input.requestProfile ?? 'pid_basis');
    } catch (e) {
      throw new Error(`Mandant "${id}": ${e instanceof Error ? e.message : String(e)}`, { cause: e });
    }
    const config: TenantConfig = {
      id,
      name: input.name.trim(),
      apiKeyHash: hashApiKey(input.apiKey),
      requestProfile,
      accessCertificateTest: `TEST-ZugriffsZertifikat-Platzhalter-${id}`,
      registrationCertificateTest: `TEST-RegistrierungsZertifikat-Platzhalter-${id}`,
      registration: input.registration,
      requestTtlSeconds: input.requestTtlSeconds ?? 300,
    };
    this.tenants.set(id, config);
    return config;
  }

  byApiKey(apiKey: string): TenantConfig | undefined {
    const hash = hashApiKey(apiKey);
    for (const tenant of this.tenants.values()) {
      if (tenant.apiKeyHash === hash) return tenant;
    }
    return undefined;
  }

  byId(id: string): TenantConfig | undefined {
    return this.tenants.get(id);
  }

  list(): readonly TenantConfig[] {
    return [...this.tenants.values()];
  }
}
