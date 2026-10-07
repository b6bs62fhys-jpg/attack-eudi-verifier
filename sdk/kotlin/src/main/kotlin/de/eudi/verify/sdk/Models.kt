package de.eudi.verify.sdk

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Modelle der Attack Verifier API.
 *
 * Die Felder entsprechen `openapi.yaml` im Repository-Wurzelverzeichnis. Die
 * Serialisierungsnamen sind die JSON-Feldnamen der API, nicht die
 * Kotlin-Namen: `registration_ref` und `issuerCountry` bleiben deshalb so
 * benannt, wie der Dienst sie erwartet.
 */

/** Eingabe einer Pruefanfrage. Leere Eingabe nutzt das Profil des Mandanten. */
@Serializable
public data class CreateRequestInput(
    val claims: List<String>? = null,
    val vct: String? = null,
    @SerialName("registration_ref") val registrationRef: RegistrationRef? = null,
)

/** Referenz auf eine WRPAC-Registrierung des Mandanten. */
@Serializable
public data class RegistrationRef(
    @SerialName("client_name") val clientName: String,
    @SerialName("client_id") val clientId: String,
    @SerialName("registry_uri") val registryUri: String,
    @SerialName("intended_use_id") val intendedUseId: String,
)

/** Ergebnis einer angelegten Pruefanfrage. */
@Serializable
public data class CreateRequestOutput(
    val sessionId: String,
    val state: String,
    val expiresAt: Long,
    val requestObject: String,
    val responseUri: String,
    val requestObjectUri: String,
)

/** Antwort von `GET /live` und `GET /health`. */
@Serializable
public data class LivenessResponse(
    val ok: Boolean,
    val status: String,
    val app: String? = null,
)

/** Antwort von `GET /ready`. `not_ready` ist eine gueltige Antwort, kein Fehler. */
@Serializable
public data class ReadinessResponse(
    val ok: Boolean,
    val status: String,
    val checks: Map<String, String> = emptyMap(),
)

/** Klartext-Umhüllung einer Wallet-Praesentation fuer `POST /direct_post`. */
@Serializable
public data class DirectPostEnvelope(
    @SerialName("vp_token") val vpToken: Map<String, List<JsonElement>>,
    val state: String,
) {
    /** Leere Envelope, um `state` nachtraeglich zu setzen. */
    public constructor(state: String) : this(emptyMap(), state)

    public companion object {
        /**
         * Huelle fuer den haeufigsten Fall: rohe SD-JWTs unter einem
         * Credential-Namen, erreichbar auch aus Java.
         */
        @JvmStatic
        public fun ofSdJwts(state: String, credentialId: String, vararg sdJwts: String): DirectPostEnvelope =
            DirectPostEnvelope(mapOf(credentialId to sdJwts.map { JsonPrimitive(it) }), state)
    }
}

/** Verschluesselte Antwort einer Wallet fuer `POST /direct_post` (direct_post.jwt). */
@Serializable
public data class DirectPostJwe(val response: String)

/** Antwort von `POST /direct_post`. `valid` ist das Pruefergebnis. */
@Serializable
public data class PresentationResponse(
    val ok: Boolean,
    val valid: Boolean,
    val error: String? = null,
)

/** Fertiges Pruefergebnis einer Praesentation. */
@Serializable
public data class VerificationResult(
    val at: String,
    val valid: Boolean,
    val claims: JsonObject = JsonObject(emptyMap()),
    val issuerCountry: String,
    val error: String,
)

/** Zustand einer Pruefanfrage. */
@Serializable
public enum class ResultState {
    @SerialName("pending")
    PENDING,

    @SerialName("completed")
    COMPLETED,

    @SerialName("expired")
    EXPIRED,

    @SerialName("not_found")
    NOT_FOUND,
}

/** Antwort von `GET /v1/verification-requests/{id}`. */
@Serializable
public data class ResultStatus(
    val status: ResultState,
    val result: VerificationResult? = null,
)
