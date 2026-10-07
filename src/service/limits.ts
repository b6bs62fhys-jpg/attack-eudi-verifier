/**
 * Eingabegrenzen und feste Fehlercodes des Dienstes (Haertung 6).
 *
 * Nach außen gehen ausschließlich feste Codes aus docs/fehlercodes.md, nie
 * Rohmeldungen aus Bibliotheken, Stacktraces oder interne Pfade.
 */
import {
  ExpiredCredentialError,
  HaipValidationError,
  InvalidSignatureError,
  MalformedCredentialError,
  NonceValidationError,
  OpenID4VPError,
  UnsupportedFormatError,
} from '@openeudi/openid4vp';

/** Größte zulässige Anfrage (Bytes) auf allen Endpunkten. */
export const MAX_BODY_BYTES = 64 * 1024;
/** Größte zulässige Präsentation (SD-JWT inkl. Disclosures und KB-JWT, Zeichen). */
export const MAX_VP_TOKEN_CHARS = 32 * 1024;
/** Größte zulässige JWE-Antwort (direct_post.jwt, Zeichen). */
export const MAX_JWE_CHARS = 48 * 1024;
/** Höchstzahl Disclosures je SD-JWT. */
export const MAX_DISCLOSURES = 64;
/** Höchstlänge von `state`. */
export const MAX_STATE_CHARS = 128;
/** Höchstzahl angefragter Claims je Prüfanfrage. */
export const MAX_CLAIMS = 32;
const CLAIM_NAME = /^[A-Za-z0-9_.-]{1,64}$/;
const VCT = /^[\x21-\x7e]{1,256}$/;

/** Ungültige Eingabe mit festem Code (HTTP 400). */
export class ServiceInputError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = 'ServiceInputError';
    this.code = code;
  }
}

export function validateClaims(claims: unknown): string[] {
  if (!Array.isArray(claims) || claims.length === 0 || claims.length > MAX_CLAIMS) throw new ServiceInputError('claims_invalid');
  if (!claims.every((c) => typeof c === 'string' && CLAIM_NAME.test(c))) throw new ServiceInputError('claims_invalid');
  return claims as string[];
}

export function validateVct(vct: unknown): string {
  if (typeof vct !== 'string' || !VCT.test(vct)) throw new ServiceInputError('vct_invalid');
  return vct;
}

/**
 * Prüft Form und Größe einer Präsentation vor jeder weiteren Verarbeitung.
 * Liefert einen Fehlercode oder `undefined`.
 */
export function vpTokenLimitError(state: unknown, vpToken: unknown): string | undefined {
  if (typeof state !== 'string' || state.length === 0 || state.length > MAX_STATE_CHARS) return 'state_invalid';
  if (typeof vpToken !== 'object' || vpToken === null || Array.isArray(vpToken)) return 'vp_token_invalid';
  const entries = Object.entries(vpToken as Record<string, unknown>);
  if (entries.length !== 1) return 'vp_token_invalid';
  const presentations = entries[0][1];
  if (!Array.isArray(presentations) || presentations.length !== 1) return 'vp_token_invalid';
  const token = presentations[0];
  if (typeof token !== 'string' || token.length === 0) return 'vp_token_invalid';
  if (token.length > MAX_VP_TOKEN_CHARS) return 'vp_token_too_long';
  // SD-JWT: <issuer-jwt>~<disclosure>~...~<kb-jwt>; leere Teile zählen nicht.
  const disclosures = token.split('~').slice(1, -1).filter((part) => part.length > 0);
  if (disclosures.length > MAX_DISCLOSURES) return 'too_many_disclosures';
  return undefined;
}

const LIBRARY_CODES: Record<string, string> = {
  trust_anchor_not_found: 'issuer_trust_anchor_not_found',
  chain_invalid: 'issuer_chain_invalid',
  certificate_revoked: 'issuer_certificate_revoked',
  revocation_check_failed: 'issuer_revocation_check_failed',
  multi_credential_unsupported: 'multi_credential_unsupported',
};

/** Übersetzt Ausnahmen der Prüfbibliothek in feste Codes (keine Rohmeldung). */
export function presentationErrorCode(e: unknown): string {
  if (e instanceof InvalidSignatureError) return 'credential_signature_invalid';
  if (e instanceof ExpiredCredentialError) return 'credential_expired';
  if (e instanceof NonceValidationError) return 'nonce_invalid';
  if (e instanceof UnsupportedFormatError) return 'credential_format_unsupported';
  if (e instanceof MalformedCredentialError) return 'credential_malformed';
  if (e instanceof HaipValidationError) return 'query_invalid';
  if (e instanceof OpenID4VPError && LIBRARY_CODES[e.code]) return LIBRARY_CODES[e.code];
  return 'presentation_invalid';
}
