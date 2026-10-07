package de.eudi.verify.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Nachweis, dass der Kotlin-Client aus reinem Java heraus benutzbar ist.
 *
 * Der Test ist absichtlich in Java geschrieben: er schlaegt fehl, wenn der
 * Client etwas anbietet, das Java nicht aufrufen kann, zum Beispiel eine
 * Kotlin-Default-Implementierung, ein {@code value class} oder eine
 * Suspend-Funktion.
 */
class JavaInteropTest {

    private HttpServer server;
    private String baseUrl;
    private final List<String> authHeaders = new CopyOnWriteArrayList<>();
    private final List<String> bodies = new CopyOnWriteArrayList<>();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            bodies.add(body);
            authHeaders.add(String.valueOf(exchange.getRequestHeaders().getFirst("authorization")));

            String path = exchange.getRequestURI().getPath();
            String payload;
            int status;
            if (path.equals("/v1/verification-requests") && "POST".equals(exchange.getRequestMethod())) {
                status = 201;
                payload = "{\"sessionId\":\"java-1\",\"state\":\"st1\",\"expiresAt\":1700000000,"
                        + "\"requestObject\":\"eyJ...\",\"responseUri\":\"https://v/direct_post\","
                        + "\"requestObjectUri\":\"https://v/ro\"}";
            } else if (path.equals("/direct_post")) {
                status = 200;
                payload = "{\"ok\":true,\"valid\":true}";
            } else {
                status = 401;
                payload = "{\"error\":\"unauthorized\"}";
            }

            byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("content-type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void createRequestFromPlainJava() {
        AttackClient client = new AttackClient(baseUrl, "test-api-key-tenant-A");

        CreateRequestOutput created = client.createPresentationRequest(
                new CreateRequestInput(List.of("age_over_18"), null, null));

        assertEquals("java-1", created.getSessionId());
        assertEquals(1700000000L, created.getExpiresAt());
        assertNotNull(created.getRequestObjectUri());
        assertTrue(authHeaders.contains("Bearer test-api-key-tenant-A"), "Bearer-Header fehlt");
    }

    @Test
    void submitPresentationFromPlainJavaWithJsonElement() {
        AttackClient client = new AttackClient(baseUrl, null);

        // Roher SD-JWT ueber die statische Fabrik, verschachteltes Objekt ueber AttackJson.
        DirectPostEnvelope raw = DirectPostEnvelope.ofSdJwts("st1", "pid", "roher-sd-jwt");
        DirectPostEnvelope nested = new DirectPostEnvelope(
                Map.of("pid", List.of(AttackJson.parseObject("{\"proof\":{\"type\":\"jwt\"}}"),
                        AttackJson.string("zweiter-sd-jwt"))),
                "st1");

        assertTrue(client.submitPresentation(raw).getValid());
        assertTrue(client.submitPresentation(nested).getValid());

        assertTrue(bodies.stream().anyMatch(body -> body.contains("roher-sd-jwt")), "vp_token fehlt: " + bodies);
        assertTrue(bodies.stream().anyMatch(body -> body.contains("\"proof\"")), "Objekt fehlt: " + bodies);
    }

    @Test
    void apiErrorExposesStatusAndCodeToJava() {
        AttackClient client = new AttackClient(baseUrl, "falscher-schluessel");

        AttackApiError error = assertThrows(AttackApiError.class, () -> client.getResult("gibtsnicht"));

        assertEquals(401, error.getStatus());
        assertEquals("unauthorized", error.getCode());
    }

    @Test
    void healthIsCallableWithoutApiKey() {
        AttackClient client = new AttackClient(baseUrl, null);

        // /health ist oeffentlich; der Testserver antwortet darauf mit 401,
        // damit sichtbar bleibt, dass der Client den Aufruf ueberhaupt sendet.
        assertThrows(AttackApiError.class, client::getHealth);

        assertTrue(authHeaders.contains("null"), "es darf kein Authorization-Header gesendet werden");
    }
}
