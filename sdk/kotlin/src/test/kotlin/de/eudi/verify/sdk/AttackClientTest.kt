package de.eudi.verify.sdk

import java.time.Duration
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AttackClientTest {
    private lateinit var server: FakeVerifier
    private val apiKey = "test-api-key-tenant-A"

    @BeforeTest
    fun startServer() {
        server = FakeVerifier()
    }

    @AfterTest
    fun stopServer() {
        server.close()
    }

    private fun client(withApiKey: Boolean = true) = AttackClient(
        baseUrl = server.baseUrl,
        apiKey = if (withApiKey) apiKey else null,
        requestTimeout = Duration.ofSeconds(5),
    )

    // --- Betriebsrouten -----------------------------------------------------

    @Test
    fun `health liefert Status und App`() {
        server.handler = { FakeResponse(200, """{"ok":true,"status":"live","app":"attack-service"}""") }

        val health = client().getHealth()

        assertTrue(health.ok)
        assertEquals("live", health.status)
        assertEquals("attack-service", health.app)
        assertEquals("/health", server.requests.single().path)
        assertNull(server.requests.single().header("authorization"))
    }

    @Test
    fun `liveness nutzt die Live-Route und sendet keinen Authorization-Header`() {
        server.handler = { FakeResponse(200, """{"ok":true,"status":"live","app":"attack-service"}""") }

        assertTrue(client().getLiveness().ok)

        assertEquals("/live", server.requests.single().path)
        assertNull(server.requests.single().header("authorization"))
    }

    @Test
    fun `readiness wertet 503 als gueltige Antwort aus und wirft nicht`() {
        server.handler = {
            FakeResponse(
                503,
                """{"ok":false,"status":"not_ready","checks":{"config":"ok","ocsp":"failed"}}""",
            )
        }

        val readiness = client().getReadiness()

        assertFalse(readiness.ok)
        assertEquals("not_ready", readiness.status)
        assertEquals("failed", readiness.checks.getValue("ocsp"))
    }

    @Test
    fun `readiness liefert checks im Ready-Fall`() {
        server.handler = {
            FakeResponse(200, """{"ok":true,"status":"ready","checks":{"config":"ok","onboarding":"degraded"}}""")
        }

        val readiness = client().getReadiness()

        assertTrue(readiness.ok)
        assertEquals("degraded", readiness.checks.getValue("onboarding"))
    }

    @Test
    fun `readiness mit unerwartetem Status wirft ApiFehler`() {
        server.handler = { FakeResponse(500, """{"error":"internal_error"}""") }

        val error = assertFailsWith<AttackApiError> { client().getReadiness() }

        assertEquals(500, error.status)
        assertEquals("internal_error", error.code)
    }

    @Test
    fun `metrics liefert das Prometheus-Textformat unveraendert`() {
        val prometheus = "# HELP attack_http_requests_total Requests\nattack_http_requests_total{method=\"GET\"} 3\n"
        server.handler = { FakeResponse(200, prometheus, contentType = "text/plain; version=0.0.4") }

        assertEquals(prometheus, client().getMetrics())
    }

    // --- Mandantenrouten ----------------------------------------------------

    @Test
    fun `createPresentationRequest sendet Bearer und Mantantenprofil`() {
        server.handler = {
            FakeResponse(
                201,
                """{"sessionId":"s1","state":"st1","expiresAt":1700000000,""" +
                    """"requestObject":"eyJ...","responseUri":"https://v.example/direct_post",""" +
                    """"requestObjectUri":"https://v.example/ro"}""",
            )
        }

        val created = client().createPresentationRequest(CreateRequestInput(claims = listOf("age_over_18")))

        assertEquals("s1", created.sessionId)
        assertEquals(1700000000L, created.expiresAt)

        val request = server.requests.single()
        assertEquals("POST", request.method)
        assertEquals("/v1/verification-requests", request.path)
        assertEquals("Bearer $apiKey", request.header("authorization"))
        assertEquals("application/json", request.header("content-type"))
        assertEquals("""{"claims":["age_over_18"]}""", request.body)
    }

    @Test
    fun `createPresentationRequest ohne Eingabe sendet leeres Objekt`() {
        server.handler = {
            FakeResponse(
                201,
                """{"sessionId":"s1","state":"st1","expiresAt":1,"requestObject":"ro",""" +
                    """"responseUri":"https://v/direct_post","requestObjectUri":"https://v/ro"}""",
            )
        }

        client().createPresentationRequest()

        assertEquals("{}", server.requests.single().body)
    }

    @Test
    fun `registration_ref wird mit dem API-Feldnamen serialisiert`() {
        server.handler = {
            FakeResponse(
                201,
                """{"sessionId":"s1","state":"st1","expiresAt":1,"requestObject":"ro",""" +
                    """"responseUri":"https://v/direct_post","requestObjectUri":"https://v/ro"}""",
            )
        }

        client().createPresentationRequest(
            CreateRequestInput(
                registrationRef = RegistrationRef(
                    clientName = "Attack GmbH",
                    clientId = "attack-gmbh",
                    registryUri = "https://registry.example/attack",
                    intendedUseId = "pid-basic",
                ),
            ),
        )

        val body = server.requests.single().body
        assertContains(body, "\"registration_ref\"")
        assertContains(body, "\"client_name\":\"Attack GmbH\"")
        assertContains(body, "\"registry_uri\":\"https://registry.example/attack\"")
        assertFalse(body.contains("registrationRef"), "Feld darf nicht im Klartext-Key stehen: $body")
    }

    @Test
    fun `ohne apiKey wird kein Authorization-Header gesendet`() {
        server.handler = {
            FakeResponse(
                201,
                """{"sessionId":"s1","state":"st1","expiresAt":1,"requestObject":"ro",""" +
                    """"responseUri":"https://v/direct_post","requestObjectUri":"https://v/ro"}""",
            )
        }

        // Der echte Dienst antwortet ohne Schluessel mit 401; der Testserver
        // antwortet 201, damit hier nur die Header-Frage geprueft wird.
        client(withApiKey = false).createPresentationRequest()

        assertNull(server.requests.single().header("authorization"))
    }

    @Test
    fun `getRequestObject liefert den JWT als Text`() {
        server.handler = { FakeResponse(200, "eyJhbGciOiJFUzI1NiJ9.e30.sig", contentType = "application/oauth-authz-req+jwt") }

        assertEquals("eyJhbGciOiJFUzI1NiJ9.e30.sig", client().getRequestObject("s1"))
        assertEquals("/v1/verification-requests/s1/request-object", server.requests.single().path)
    }

    @Test
    fun `Sitzungs-ID mit Schraegstrich wird kodiert und nicht als Pfad missbraucht`() {
        server.handler = { FakeResponse(404, """{"error":"not_found"}""") }

        assertFailsWith<AttackApiError> { client().getRequestObject("a/../b") }

        // Der Pfad muss auf der Leitung kodiert bleiben. Der Testserver zeigt
        // zusaetzlich die dekodierte Sicht, die ein Zwischenlayer sehen wuerde.
        assertEquals("/v1/verification-requests/a%2F..%2Fb/request-object", server.requests.single().rawPath)
    }

    @Test
    fun `getResult liest ein abgeschlossenes Ergebnis`() {
        server.handler = {
            FakeResponse(
                200,
                """{"status":"completed","result":{"at":"2026-09-27T10:00:00Z","valid":true,""" +
                    """"claims":{"given_name":"Ada"},"issuerCountry":"DE","error":""}}""",
            )
        }

        val status = client().getResult("s1")

        assertEquals(ResultState.COMPLETED, status.status)
        assertEquals("DE", status.result?.issuerCountry)
        assertEquals(JsonPrimitive("Ada"), status.result?.claims?.get("given_name"))
        assertEquals("Bearer $apiKey", server.requests.single().header("authorization"))
    }

    @Test
    fun `getResult liest pending ohne Ergebnis`() {
        server.handler = { FakeResponse(200, """{"status":"pending"}""") }

        val status = client().getResult("s1")

        assertEquals(ResultState.PENDING, status.status)
        assertNull(status.result)
    }

    @Test
    fun `unbekannter Fehlercode des StatusEnum wird als Fehler gemeldet`() {
        server.handler = { FakeResponse(200, """{"status":"quatsche"}""") }

        assertFailsWith<Exception> { client().getResult("s1") }
    }

    @Test
    fun `deleteSession akzeptiert 204 ohne Body`() {
        server.handler = { FakeResponse(204) }

        client().deleteSession("s1")

        val request = server.requests.single()
        assertEquals("DELETE", request.method)
        assertEquals("/v1/verification-requests/s1", request.path)
    }

    // --- Wallet-Route -------------------------------------------------------

    @Test
    fun `submitPresentation sendet die Klartext-Envelope`() {
        server.handler = { FakeResponse(200, """{"ok":true,"valid":true}""") }

        val envelope = DirectPostEnvelope(
            vpToken = mapOf("pid" to listOf(JsonPrimitive("eyJ...~WyJzYWx0IiwibmFtZSIsIkFkYSJd~"))),
            state = "st1",
        )
        val response = client().submitPresentation(envelope)

        assertTrue(response.valid)

        val request = server.requests.single()
        assertEquals("/direct_post", request.path)
        assertNull(request.header("authorization"), "die Wallet-Route ist oeffentlich")
        assertContains(request.body, "\"vp_token\"")
        assertContains(request.body, "\"state\":\"st1\"")
    }

    @Test
    fun `submitPresentation sendet das JWE als response-Feld`() {
        server.handler = { FakeResponse(200, """{"ok":true,"valid":false,"error":"jwe_decrypt_failed"}""") }

        val response = client().submitPresentation(DirectPostJwe("compact.jwe"))

        assertFalse(response.valid)
        assertEquals("jwe_decrypt_failed", response.error)
        assertEquals("""{"response":"compact.jwe"}""", server.requests.single().body)
    }

    @Test
    fun `unbekanntes Feld in der Antwort wird toleriert`() {
        server.handler = {
            FakeResponse(200, """{"ok":true,"valid":true,"error":"","neu":{"a":1}}""")
        }

        assertTrue(client().submitPresentation(DirectPostJwe("jwe")).valid)
    }

    // --- Abgelehnte Praesentation: 422 ist ein Ergebnis, kein Fehler -----------

    @Test
    fun `422 liefert das Praesentationsergebnis statt einer Ausnahme`() {
        // /direct_post ist oeffentlich, es gab dort nichts zu authentifizieren.
        // Eine abgelehnte Praesentation traegt 422 und den konkreten Grund im
        // Body. Der Aufrufer muss daraus lesen koennen, also wirft der Client
        // hier nicht.
        server.handler = {
            FakeResponse(422, """{"ok":false,"valid":false,"error":"unknown_state"}""")
        }

        val response = client().submitPresentation(DirectPostJwe("compact.jwe"))

        assertFalse(response.ok)
        assertFalse(response.valid)
        assertEquals("unknown_state", response.error)
    }

    @Test
    fun `422 gilt fuer beide Praesentationsformen und fuer jeden Ablehnungsgrund`() {
        for (grund in listOf("unknown_state", "state_invalid", "vp_token_invalid", "session_reused")) {
            server.handler = { FakeResponse(422, """{"ok":false,"valid":false,"error":"$grund"}""") }
            assertEquals(grund, client().submitPresentation(DirectPostJwe("jwe")).error, "JWE $grund")
            assertEquals(grund, client().submitPresentation(DirectPostEnvelope(emptyMap(), "s")).error, "Klartext $grund")
        }
    }

    @Test
    fun `401 und 413 bleiben bei submitPresentation Fehler`() {
        // Gegenprobe: 422 ist der einzige Status, der eine Ablehnung traegt.
        // Fehler der Anfrage selbst muessen weiterhin eine Ausnahme loesen.
        server.handler = { FakeResponse(401, """{"error":"unauthorized"}""") }
        assertFailsWith<AttackApiError> { client().submitPresentation(DirectPostJwe("jwe")) }

        server.handler = { FakeResponse(413, """{"error":"payload_too_large"}""") }
        val error = assertFailsWith<AttackApiError> { client().submitPresentation(DirectPostJwe("jwe")) }
        assertEquals(413, error.status)
    }

    @Test
    fun `die Wallet-Route sendet weiterhin keinen Authorization-Header`() {
        server.handler = { FakeResponse(422, """{"ok":false,"valid":false,"error":"unknown_state"}""") }
        client().submitPresentation(DirectPostJwe("jwe"))
        assertNull(server.requests.single().header("authorization"))
    }

    // --- Fehler -------------------------------------------------------------

    @Test
    fun `401 liefert Status und Code unauthorized`() {
        server.handler = { FakeResponse(401, """{"error":"unauthorized"}""") }

        val error = assertFailsWith<AttackApiError> { client().getResult("s1") }

        assertEquals(401, error.status)
        assertEquals("unauthorized", error.code)
        assertEquals("unauthorized", error.message)
    }

    @Test
    fun `429 liefert rate_limited und reicht die Header durch den Fehler nicht weiter`() {
        server.handler = {
            FakeResponse(
                429,
                """{"error":"rate_limited"}""",
                headers = mapOf(
                    "x-ratelimit-limit" to "60",
                    "x-ratelimit-remaining" to "0",
                    "retry-after" to "42",
                ),
            )
        }

        val error = assertFailsWith<AttackApiError> { client().createPresentationRequest() }

        assertEquals(429, error.status)
        assertEquals("rate_limited", error.code)
    }

    @Test
    fun `413 liefert payload_too_large`() {
        server.handler = { FakeResponse(413, """{"error":"payload_too_large"}""") }

        val error = assertFailsWith<AttackApiError> { client().submitPresentation(DirectPostJwe("jwe")) }

        assertEquals("payload_too_large", error.code)
    }

    @Test
    fun `Fehlerkoerper ohne Fehlercode ergibt null als Code`() {
        server.handler = { FakeResponse(502, "<html>Bad Gateway</html>", contentType = "text/html") }

        val error = assertFailsWith<AttackApiError> { client().getHealth() }

        assertEquals(502, error.status)
        assertNull(error.code)
        assertEquals("http_502", error.message)
    }

    @Test
    fun `Antwort mit 200 und kaputtem JSON wird als Fehler gemeldet, nicht verschluckt`() {
        server.handler = { FakeResponse(200, "kein json") }

        assertFailsWith<Exception> { client().getHealth() }
    }

    @Test
    fun `nicht erreichbarer Dienst ergibt Transportfehler`() {
        val offline = AttackClient("http://127.0.0.1:1", requestTimeout = Duration.ofMillis(500))

        val error = assertFailsWith<AttackTransportError> { offline.getHealth() }

        assertContains(error.message!!, "GET /health")
    }

    @Test
    fun `Basisadresse mit Trailing Slash fuehrt nicht zu doppeltem Slash`() {
        server.handler = { FakeResponse(200, """{"ok":true,"status":"live"}""") }
        val client = AttackClient(server.baseUrl + "/", requestTimeout = Duration.ofSeconds(5))

        client.getHealth()

        assertEquals("/health", server.requests.single().path)
    }

    @Test
    fun `verschachtelte vp_token-Struktur bleibt unveraendert erhalten`() {
        server.handler = { FakeResponse(200, """{"ok":true,"valid":true}""") }
        val inner = JsonObject(mapOf("proof" to JsonObject(mapOf("type" to JsonPrimitive("jwt")))))
        val envelope = DirectPostEnvelope(mapOf("pid" to listOf(inner, JsonPrimitive("roher-sd-jwt"))), "st1")

        client().submitPresentation(envelope)

        val body = server.requests.single().body
        assertContains(body, """{"proof":{"type":"jwt"}}""")
        assertContains(body, """"roher-sd-jwt"""")
    }
}
