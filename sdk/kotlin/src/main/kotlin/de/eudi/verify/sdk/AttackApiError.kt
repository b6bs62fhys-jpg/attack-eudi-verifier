package de.eudi.verify.sdk

/**
 * Fehler eines API-Aufrufs mit HTTP-Status und, wenn der Dienst einen
 * dokumentierten Code liefert, mit diesem Code.
 *
 * Der Code stammt aus dem Feld `error` der Fehlerantwort. Die vollstaendige
 * Liste steht in `openapi.yaml` und in `docs/fehlercodes.md`. Interne
 * Serverfehler werden nicht durchgereicht, der Dienst antwortet auf 500 mit
 * `internal_error`.
 */
public class AttackApiError(
    public val status: Int,
    public val code: String?,
) : RuntimeException(code ?: "http_$status")
