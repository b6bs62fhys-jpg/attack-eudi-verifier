/**
 * Gemeinsame TEST-Einstellungen für Dienst-Tests. Entspricht einem Start mit
 * ATTACK_DEV_MODE=true außerhalb von Produktion: nur dann ist das Abschalten
 * der Credential-Statusprüfung und der Aussteller-Sperrprüfung erlaubt.
 * Nicht für den Dienststart verwenden.
 */
import { NO_CREDENTIAL_STATUS } from './credential-status.ts';
import { NO_REVOCATION } from '../onboarding/revocation.ts';
import type { VerifierServiceOptions } from './service.ts';

export const DEV_MODE = Object.freeze({ devMode: true, isProduction: false });

export const DEV_TEST_OPTIONS: VerifierServiceOptions = Object.freeze({
  mode: DEV_MODE,
  credentialStatus: NO_CREDENTIAL_STATUS,
  issuerRevocation: NO_REVOCATION,
});
