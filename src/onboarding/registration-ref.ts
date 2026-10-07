/**
 * RegistrationRef (RPRC_19a): der Registrierungsnachweis eines Relying Party,
 * der in jeden Authorization Request des onboardschalteten WP eingebettet wird.
 *
 * Felder (JSON): `client_name`, `client_id`, `registry_uri`, `intended_use_id`.
 * Nur Struktur/Validierung MEINER Implementierung; Standards: EUDI-ARF.
 */
import { ErrRegistrationRef } from './errors.ts';

export const REGISTRATION_REF_CLAIM = 'registration_ref';
export const MAX_CLIENT_NAME_LENGTH = 256;
export const MAX_CLIENT_ID_LENGTH = 256;
export const MAX_INTENDED_USE_ID_LENGTH = 128;

export interface RegistrationRef {
  clientName: string;
  clientId: string;
  registryUri: string;
  intendedUseId: string;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

export function isHttpUri(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch {
    return false;
  }
}

export function validateRegistrationRefRaw(value: unknown): RegistrationRef {
  if (typeof value !== 'object' || value === null) throw new ErrRegistrationRef();
  const raw = value as Record<string, unknown>;
  const clientName = raw.client_name ?? raw.clientName;
  const clientId = raw.client_id ?? raw.clientId;
  const registryUri = raw.registry_uri ?? raw.registryUri;
  const intendedUseId = raw.intended_use_id ?? raw.intendedUseId;

  if (!isNonEmptyString(clientName)) throw new ErrRegistrationRef();
  if (clientName.length > MAX_CLIENT_NAME_LENGTH) throw new ErrRegistrationRef();
  if (!isNonEmptyString(clientId)) throw new ErrRegistrationRef();
  if (clientId.length > MAX_CLIENT_ID_LENGTH) throw new ErrRegistrationRef();
  if (!isNonEmptyString(registryUri) || !isHttpUri(registryUri)) throw new ErrRegistrationRef();
  if (!isNonEmptyString(intendedUseId)) throw new ErrRegistrationRef();
  if (intendedUseId.length > MAX_INTENDED_USE_ID_LENGTH) throw new ErrRegistrationRef();

  return { clientName, clientId, registryUri, intendedUseId };
}

export function toRegistrationRefClaim(ref: RegistrationRef): Record<string, unknown> {
  return {
    [REGISTRATION_REF_CLAIM]: {
      client_name: ref.clientName,
      client_id: ref.clientId,
      registry_uri: ref.registryUri,
      intended_use_id: ref.intendedUseId,
    },
  };
}