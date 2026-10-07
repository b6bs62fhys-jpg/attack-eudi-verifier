package de.eudi.verify.sdk

import java.io.IOException
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * Typisierter Client fuer die Attack Verifier API.
 *
 * Der Client ist zustandslos und fuer parallele Nutzung ausgelegt. Der
 * Mandantenschluessel wird nur an die mandantenbezogenen Routen gesendet und
 * gehoert auf den Server; er darf nicht in Browser- oder Mobilcode stehen.
 *
 * ```
 * val attack = AttackClient("http://127.0.0.1:8080", apiKey = System.getenv("ATTACK_API_KEY"))
 * val request = attack.createPresentationRequest(CreateRequestInput(claims = listOf("age_over_18")))
 * val status = attack.getResult(request.sessionId)
 * ```
 *
 * @param baseUrl Basisadresse des Dienstes, zum Beispiel `http://127.0.0.1:8080`.
 * @param apiKey Mandantenschluessel fuer die mandantenbezogenen Routen.
 * @param httpClient eigener HTTP-Client, zum Beispiel mit Proxy oder TLS-Vorgaben.
 * @param json JSON-Formatierung; unbekannte Felder werden toleriert.
 * @param requestTimeout Zeitgrenze fuer einen einzelnen Aufruf.
 */
public class AttackClient @JvmOverloads constructor(
    baseUrl: String,
    private val apiKey: String? = null,
    private val httpClient: HttpClient = defaultHttpClient(),
    private val json: Json = defaultJson(),
    private val requestTimeout: Duration = Duration.ofSeconds(10),
) {
    private val baseUrl: String = baseUrl.trimEnd('/')

    /** `GET /live`: Prozess laeuft, unabhaengig von externen Abhaengigkeiten. */
    public fun getLiveness(): LivenessResponse = getJson("/live", authenticated = false, type = LivenessResponse.serializer())

    /** `GET /health`: Dienst laeuft. */
    public fun getHealth(): LivenessResponse = getJson("/health", authenticated = false, type = LivenessResponse.serializer())

    /**
     * `GET /ready`: Abhaengigkeiten des Dienstes.
     *
     * HTTP 503 ist eine gueltige Antwort und kein Fehler: sie wird wie 200
     * ausgewertet, damit die Pruefergebnisse in `checks` auswertbar bleiben.
     */
    public fun getReadiness(): ReadinessResponse {
        val response = send("/ready", "GET", null, authenticated = false)
        if (response.statusCode() == 200 || response.statusCode() == 503) {
            return json.decodeFromString(ReadinessResponse.serializer(), response.body())
        }
        throw errorFrom(response)
    }

    /** `GET /metrics`: Prometheus-Textformat 0.0.4, keine Quantile. */
    public fun getMetrics(): String = sendChecked("/metrics", "GET", null, authenticated = false).body()

    /**
     * `POST /v1/verification-requests`: legt eine Pruefanfrage an.
     *
     * Eine leere Eingabe verwendet das Anfrageprofil des Mandanten.
     */
    public fun createPresentationRequest(
        input: CreateRequestInput = CreateRequestInput(),
    ): CreateRequestOutput = sendJson(
        "/v1/verification-requests",
        "POST",
        json.encodeToString(CreateRequestInput.serializer(), input),
        authenticated = true,
        type = CreateRequestOutput.serializer(),
    )

    /** `GET /v1/verification-requests/{id}/request-object`: signiertes Request Object. */
    public fun getRequestObject(sessionId: String): String =
        sendChecked("/v1/verification-requests/${encodePathSegment(sessionId)}/request-object", "GET", null, authenticated = false).body()

    /** `POST /direct_post`: nimmt eine Klartext-Praesentation der Wallet an. */
    public fun submitPresentation(envelope: DirectPostEnvelope): PresentationResponse = sendWalletJson(
        "/direct_post",
        json.encodeToString(DirectPostEnvelope.serializer(), envelope),
        PresentationResponse.serializer(),
    )

    /** `POST /direct_post`: nimmt eine verschluesselte Antwort der Wallet an. */
    public fun submitPresentation(jwe: DirectPostJwe): PresentationResponse = sendWalletJson(
        "/direct_post",
        json.encodeToString(DirectPostJwe.serializer(), jwe),
        PresentationResponse.serializer(),
    )

    /**
     * `GET /v1/verification-requests/{id}`: Status oder fertiges Ergebnis.
     *
     * Ein fertiges Ergebnis wird genau einmal ausgeliefert. Danach antwortet
     * die Route wie bei einer unbekannten Sitzung.
     */
    public fun getResult(sessionId: String): ResultStatus = getJson(
        "/v1/verification-requests/${encodePathSegment(sessionId)}",
        authenticated = true,
        type = ResultStatus.serializer(),
    )

    /** `DELETE /v1/verification-requests/{id}`: loescht die Sitzung. */
    public fun deleteSession(sessionId: String) {
        sendChecked("/v1/verification-requests/${encodePathSegment(sessionId)}", "DELETE", null, authenticated = true)
    }

    private fun <T> getJson(path: String, authenticated: Boolean, type: kotlinx.serialization.KSerializer<T>): T {
        val response = sendChecked(path, "GET", null, authenticated)
        return json.decodeFromString(type, response.body())
    }

    private fun <T> sendJson(
        path: String,
        method: String,
        body: String,
        authenticated: Boolean,
        type: kotlinx.serialization.KSerializer<T>,
    ): T {
        val response = sendChecked(path, method, body, authenticated)
        return json.decodeFromString(type, response.body())
    }

    /** Wie [send], wertet aber jeden Status ausserhalb 2xx als [AttackApiError]. */
    private fun sendChecked(path: String, method: String, body: String?, authenticated: Boolean): HttpResponse<String> {
        val response = send(path, method, body, authenticated)
        if (response.statusCode() !in 200..299) throw errorFrom(response)
        return response
    }

    /**
     * Wie [sendJson], wertet aber eine **abgelehnte Praesentation** nicht als
     * Fehler.
     *
     * `/direct_post` ist die oeffentliche Wallet-Route. Eine nicht angenommene
     * Praesentation traegt HTTP 422 und im Body den konkreten Grund
     * (`unknown_state`, `state_invalid`, `vp_token_invalid`, Replay). Das ist
     * ein Ergebnis, kein Fehler: der Aufrufer muss daraus den Ablehnungsgrund
     * lesen koennen.
     *
     * Vorher wurde hier jede Antwort ausserhalb 2xx als [AttackApiError]
     * geworfen, wodurch ein Aufrufer eine Ausnahme bekommen haette statt des
     * Präsentationsergebnisses. Die TypeScript- und Python-Clients liefern
     * die Antwort in diesem Fall zurueck; diese Abweichung war eine Falle,
     * gerade weil 422 der dokumentierte Normalfall einer Ablehnung ist.
     *
     * 401 und 413 werfen weiterhin, denn beide sind keine Ablehnung einer
     * Praesentation, sondern ein Fehler der Anfrage.
     */
    private fun <T> sendWalletJson(
        path: String,
        body: String,
        type: kotlinx.serialization.KSerializer<T>,
    ): T {
        val response = send(path, "POST", body, authenticated = false)
        if (response.statusCode() == REJECTED_PRESENTATION) {
            return json.decodeFromString(type, response.body())
        }
        if (response.statusCode() !in 200..299) throw errorFrom(response)
        return json.decodeFromString(type, response.body())
    }

    private fun send(path: String, method: String, body: String?, authenticated: Boolean): HttpResponse<String> {
        val builder = HttpRequest.newBuilder(URI.create("$baseUrl$path")).timeout(requestTimeout)
        if (authenticated && apiKey != null) {
            builder.header("authorization", "Bearer $apiKey")
        }
        if (body != null) {
            builder.header("content-type", "application/json")
            builder.method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
        } else if (method != "GET") {
            builder.method(method, HttpRequest.BodyPublishers.noBody())
        }
        return try {
            httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
        } catch (e: IOException) {
            throw AttackTransportError("Aufruf $method $path fehlgeschlagen: ${e.message}", e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw AttackTransportError("Aufruf $method $path unterbrochen", e)
        }
    }

    private fun errorFrom(response: HttpResponse<String>): AttackApiError =
        AttackApiError(response.statusCode(), readErrorCode(response.body()))

    private fun readErrorCode(body: String): String? = try {
        val element = json.parseToJsonElement(body) as? JsonObject
        element?.get("error")?.let { value ->
            (value as? kotlinx.serialization.json.JsonPrimitive)?.content
        }
    } catch (_: Exception) {
        null
    }

    private fun encodePathSegment(value: String): String =
        URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")

    public companion object {
        /**
         * HTTP 422: die Praesentation kam an, wurde aber nicht angenommen. Der
         * Ablehnungsgrund steht im Body, deshalb ist das kein Fehlerfall und
         * [submitPresentation] liefert das Ergebnis statt einer Ausnahme.
         *
         * 401 bleibt exklusiv fuer den API-Schluessel, 413 fuer die
         * Groessengrenze; beide werden weiterhin als [AttackApiError] geworfen.
         */
        internal const val REJECTED_PRESENTATION: Int = 422

        /** Standardclient: HTTP/1.1, keine Weiterleitung, 10 s Connect-Timeout. */
        public fun defaultHttpClient(): HttpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10))
            .build()

        /** Unbekannte Felder werden ignoriert, `null` wird nicht gesendet. */
        public fun defaultJson(): Json = Json {
            ignoreUnknownKeys = true
            explicitNulls = false
        }
    }
}

/** Der Dienst war nicht erreichbar; das ist kein API-Fehler mit Fehlercode. */
public class AttackTransportError(
    message: String,
    cause: Throwable,
) : RuntimeException(message, cause)
