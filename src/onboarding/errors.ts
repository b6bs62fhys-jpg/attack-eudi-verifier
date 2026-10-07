/**
 * Fehlersentinels für das RP-Onboarding (Baustein B, Prototyp).
 *
 * Fail closed: bei jedem unbekannten/ungültigen Zustand wird abgelehnt.
 * Fehlermeldungen enthalten keine Attributwerte, keine Schlüssel und keine
 * personenbezogenen Daten (inkl. Registry-URIs / IDs fremder Systeme).
 */
export class OnboardingError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'OnboardingError';
    this.code = code;
  }
}

export const ErrMalformed = class ErrMalformed extends OnboardingError {
  constructor() {
    super('wrprc_malformed', 'token ist nicht lesbar');
  }
};

export const ErrWrprcType = class ErrWrprcType extends OnboardingError {
  constructor() {
    super('wrprc_type_invalid', 'token-typ ist nicht rc-wrp+jwt');
  }
};

export const ErrWrprcHeader = class ErrWrprcHeader extends OnboardingError {
  constructor() {
    super('wrprc_header_invalid', 'x5c-kette fehlt oder ist ungueltig');
  }
};

export const ErrWrprcSignature = class ErrWrprcSignature extends OnboardingError {
  constructor() {
    super('wrprc_signature_invalid', 'signatur kann nicht verifiziert werden');
  }
};

export const ErrWrprcUnsupportedSigningAlgorithm = class ErrWrprcUnsupportedSigningAlgorithm extends OnboardingError {
  constructor() {
    super('wrprc_unsupported_alg', 'signaturalgorithmus wird nicht unterstuetzt');
  }
};

export const ErrWrprcClaims = class ErrWrprcClaims extends OnboardingError {
  constructor() {
    super('wrprc_claims_missing', 'erforderliche claims fehlen');
  }
};

export const ErrWrprcNotYetValid = class ErrWrprcNotYetValid extends OnboardingError {
  constructor() {
    super('wrprc_not_yet_valid', 'token ist noch nicht gueltig');
  }
};

export const ErrWrprcExpired = class ErrWrprcExpired extends OnboardingError {
  constructor() {
    super('wrprc_expired', 'token ist abgelaufen');
  }
};

export const ErrWrprcValidity = class ErrWrprcValidity extends OnboardingError {
  constructor() {
    super('wrprc_validity_window_invalid', 'gueltigkeitsfenster ueberschreitet das Maximum');
  }
};

export const ErrWrprcPolicyId = class ErrWrprcPolicyId extends OnboardingError {
  constructor() {
    super('wrprc_policy_id_missing', 'policy_id enthaelt nicht die WRPRC-Policy');
  }
};

export const ErrWrprcEntitlement = class ErrWrprcEntitlement extends OnboardingError {
  constructor() {
    super('wrprc_entitlement_missing', 'kein berechtigtes entitlement vorhanden');
  }
};

export const ErrUnknownEntitlement = class ErrUnknownEntitlement extends OnboardingError {
  constructor() {
    super('entitlement_unknown', 'entitlement-oid ist nicht auf der konfigurierten karte');
  }
};

export const ErrWrpacPolicy = class ErrWrpacPolicy extends OnboardingError {
  constructor() {
    super('wrpac_policy_missing', 'zugriffszertifikat traegt keine EUDIWRP-Policy');
  }
};

export const ErrWrpacContactSan = class ErrWrpacContactSan extends OnboardingError {
  constructor() {
    super('wrpac_contact_san_missing', 'zugriffszertifikat hat keine kontakt-san');
  }
};

export const ErrWrpacKeyUsage = class ErrWrpacKeyUsage extends OnboardingError {
  constructor() {
    super('wrpac_key_usage_invalid', 'zugriffszertifikat hat nicht digitalSignature');
  }
};

export const ErrWrpacExtKeyUsage = class ErrWrpacExtKeyUsage extends OnboardingError {
  constructor() {
    super('wrpac_ext_key_usage_invalid', 'zugriffszertifikat hat keine zulaessige eku');
  }
};

export const ErrTrustPath = class ErrTrustPath extends OnboardingError {
  constructor() {
    super('trust_path_not_found', 'kein vertrauenspfad zu einem anker');
  }
};

export const ErrRevokedCertificate = class ErrRevokedCertificate extends OnboardingError {
  constructor() {
    super('certificate_revoked', 'zertifikat ist gesperrt (revocation)');
  }
};

export const ErrCertificateExpired = class ErrCertificateExpired extends OnboardingError {
  constructor() {
    super('certificate_expired', 'zertifikat ist abgelaufen (notAfter ueberschritten)');
  }
};

export const ErrCertificateNotYetValid = class ErrCertificateNotYetValid extends OnboardingError {
  constructor() {
    super('certificate_not_yet_valid', 'zertifikat ist noch nicht gueltig (notBefore in der zukunft)');
  }
};

export const ErrSuspendedCertificate = class ErrSuspendedCertificate extends OnboardingError {
  constructor() {
    super('certificate_suspended', 'zertifikat ist ausgesetzt (certificateHold)');
  }
};

export const ErrRevocationUnavailable = class ErrRevocationUnavailable extends OnboardingError {
  constructor() {
    super('revocation_unavailable', 'sperrquelle ist nicht erreichbar');
  }
};

export const ErrRevocationTimeout = class ErrRevocationTimeout extends OnboardingError {
  constructor() {
    super('revocation_timeout', 'sperrquelle antwortet nicht innerhalb der zeitgrenze');
  }
};

export const ErrRevocationListTooLarge = class ErrRevocationListTooLarge extends OnboardingError {
  constructor() {
    super('revocation_list_too_large', 'sperrliste ueberschreitet die groessengrenze');
  }
};

export const ErrRevocationListSignature = class ErrRevocationListSignature extends OnboardingError {
  constructor() {
    super('revocation_list_signature_invalid', 'signatur der sperrliste ist ungueltig');
  }
};

export const ErrRevocationListMalformed = class ErrRevocationListMalformed extends OnboardingError {
  constructor() {
    super('revocation_list_malformed', 'sperrliste hat ein ungueltiges format');
  }
};

export const ErrRevocationListExpired = class ErrRevocationListExpired extends OnboardingError {
  constructor() {
    super('revocation_list_expired', 'sperrliste ist abgelaufen oder noch nicht gueltig');
  }
};

export const ErrRevocationStatusUnknown = class ErrRevocationStatusUnknown extends OnboardingError {
  constructor() {
    super('revocation_status_unknown', 'sperrstatus ist unbekannt');
  }
};

export const ErrRevocationSourceMissing = class ErrRevocationSourceMissing extends OnboardingError {
  constructor() {
    super('revocation_source_missing', 'zertifikat nennt keine nutzbare sperrquelle');
  }
};

export const ErrRegistrationRef = class ErrRegistrationRef extends OnboardingError {
  constructor() {
    super('registration_ref_invalid', 'registration reference ist ungueltig');
  }
};

export const ErrRegistrationRefMismatch = class ErrRegistrationRefMismatch extends OnboardingError {
  constructor() {
    super('registration_ref_mismatch', 'registration reference passt nicht zur WRPRC-Registrierung des Mandanten');
  }
};

export const ErrTenantNotRegistered = class ErrTenantNotRegistered extends OnboardingError {
  constructor() {
    super('tenant_not_registered', 'mandant ist nicht registriert');
  }
};

export const ErrTenantRegistrationInvalid = class ErrTenantRegistrationInvalid extends OnboardingError {
  /** Fester Code der inneren Ursache (z. B. certificate_revoked), nur für Audit/Betrieb. */
  readonly reason: string;
  constructor(detail = '', reason = 'unspecified') {
    super('tenant_registration_invalid', detail || 'registrierungsmaterial des mandanten ist ungueltig');
    this.reason = reason;
  }
};

export const ErrRegistrarStatus = class ErrRegistrarStatus extends OnboardingError {
  constructor() {
    super('registrar_status_invalid', 'registrar antwortet mit unerwartetem status');
  }
};

export const ErrRegistrarUnavailable = class ErrRegistrarUnavailable extends OnboardingError {
  constructor() {
    super('registrar_unavailable', 'registrar ist nicht erreichbar');
  }
};

export const ErrRegistrarTimeout = class ErrRegistrarTimeout extends OnboardingError {
  constructor() {
    super('registrar_timeout', 'registrar antwortet nicht innerhalb des timeouts');
  }
};

export const ErrRegistrarSignature = class ErrRegistrarSignature extends OnboardingError {
  constructor() {
    super('registrar_signature_invalid', 'registrar antwort ist nicht gegen den gepinnten schluessel');
  }
};

export const ErrRegistrarStale = class ErrRegistrarStale extends OnboardingError {
  constructor() {
    super('registrar_stale_response', 'registrar antwort ist nicht mehr aktuell');
  }
};

export const ErrRegistrarResponseMalformed = class ErrRegistrarResponseMalformed extends OnboardingError {
  constructor() {
    super('registrar_response_malformed', 'registrar antwort ist ungueltig');
  }
};

export const ErrWrpNotFound = class ErrWrpNotFound extends OnboardingError {
  constructor() {
    super('registrar_wrp_not_found', 'wrp ist nicht registriert');
  }
};

export const ErrIntendedUseNotFound = class ErrIntendedUseNotFound extends OnboardingError {
  constructor() {
    super('registrar_intended_use_not_found', 'intended use ist nicht registriert');
  }
};

export const ErrIntendedUseNotActive = class ErrIntendedUseNotActive extends OnboardingError {
  constructor() {
    super('registrar_intended_use_not_active', 'intended use ist nicht aktiv');
  }
};