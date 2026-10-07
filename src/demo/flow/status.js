export const USER_MESSAGES = {
  waiting: 'Warten auf die Präsentation der Wallet …',
  completed: 'Die Prüfung ist erfolgreich abgeschlossen.',
  rejected: 'Die Prüfung wurde abgelehnt.',
  expired: 'Die Prüfanfrage ist abgelaufen. Bitte starten Sie eine neue Prüfung.',
  failed: 'Die Prüfung ist fehlgeschlagen. Bitte versuchen Sie es erneut.',
  unknown: 'Die Prüfanfrage wurde nicht gefunden. Bitte starten Sie eine neue Prüfung.',
};

/**
 * Ursache einer Ablehnung in lesbarer Form. Bewusst ohne technisches Detail:
 * gezeigt wird, was der Besitzer der Prüfanfrage wissen darf, nicht wie der
 * Nachweis aufgebaut ist. Der zugehoerige Code wird getrennt davon angezeigt.
 */
export const REJECTION_REASONS = {
  issuer_trust_anchor_not_found: 'Der Aussteller steht nicht auf der Trust List.',
  issuer_certificate_revoked: 'Das Ausstellerzertifikat ist gesperrt.',
  session_expired: 'Die Prüfanfrage war abgelaufen, bevor die Wallet geantwortet hat.',
  session_reused: 'Die Prüfanfrage wurde bereits einmal beantwortet.',
  state_mismatch: 'Die Antwort passt nicht zu der gestellten Anfrage.',
  unknown_session: 'Zu dieser Prüfanfrage gibt es keine Sitzung mehr.',
  unknown_state: 'Der Verifier kennt diese Prüfanfrage nicht mehr.',
  presentation_invalid: 'Die Wallet-Präsentation wurde abgelehnt. Der Verifier nennt hier bewusst keinen Detailgrund, damit nichts über den Aufbau des Nachweises nach außen dringt.',
  credential_expired: 'Der Nachweis in der Wallet ist abgelaufen.',
  nonce_mismatch: 'Die Antwort der Wallet gehört zu einer anderen Anfrage.',
  disclosure_invalid: 'Eine Offenlegung im Nachweis passt nicht zum Nachweis.',
  presentation_expired: 'Die Präsentation ist abgelaufen.',
  tenant_registration_invalid: 'Die Registrierung des Mandanten ist unvollständig.',
};

export function rejectionReason(code) {
  if (typeof code !== 'string' || code === '') return null;
  return REJECTION_REASONS[code] ?? null;
}

export function safeReturnUrl(raw) {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  if (raw.includes('\\') || raw.includes('\n') || raw.includes('\r')) return null;
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.includes('://')) return null;
  const firstSlash = raw.indexOf('/', 1);
  const schemeInPath = (firstSlash === -1 ? raw : raw.slice(0, firstSlash)).includes(':');
  return schemeInPath ? null : raw;
}

export function createFlowState() {
  return { status: 'waiting', claims: null, at: null, error: null, message: USER_MESSAGES.waiting };
}

export function applyPollResponse(prev, statusCode, body) {
  if (statusCode === 404 || body === null || typeof body !== 'object') {
    return { status: 'failed', claims: null, at: null, error: null, message: USER_MESSAGES.unknown };
  }
  switch (body.status) {
    case 'pending':
      return { status: 'waiting', claims: null, at: null, error: null, message: USER_MESSAGES.waiting };
    case 'completed': {
      const result = body.result && typeof body.result === 'object' ? body.result : null;
      const claims = result && typeof result.claims === 'object' && result.claims !== null ? result.claims : null;
      const at = typeof result?.at === 'string' ? result.at : null;
      // Abgelehnt ist abgeschlossen mit `valid: false`. Ohne diesen Zweig
      // wuerde die Oberflaeche eine Ablehnung als Erfolg mit leeren Claims
      // anzeigen.
      if (result && result.valid === false) {
        const code = typeof result.error === 'string' ? result.error : '';
        const reason = rejectionReason(code);
        return {
          status: 'rejected',
          claims: null,
          at,
          error: code,
          message: reason ?? USER_MESSAGES.rejected,
        };
      }
      return { status: 'completed', claims, at, error: null, message: USER_MESSAGES.completed };
    }
    case 'expired':
      return { status: 'expired', claims: null, at: null, error: null, message: USER_MESSAGES.expired };
    default:
      return { status: 'failed', claims: null, at: null, error: null, message: USER_MESSAGES.failed };
  }
}
