package de.eudi.verify.sdk

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.util.concurrent.CopyOnWriteArrayList

/** Aufgezeichneter Request des Testservers. */
internal data class RecordedRequest(
    val method: String,
    val path: String,
    val rawPath: String,
    val headers: Map<String, String>,
    val body: String,
) {
    fun header(name: String): String? = headers[name.lowercase()]
}

internal data class FakeResponse(
    val status: Int,
    val body: String = "",
    val contentType: String? = "application/json",
    val headers: Map<String, String> = emptyMap(),
)

/**
 * Echter HTTP-Testserver auf 127.0.0.1 mit ephemerem Port.
 *
 * Bewusst kein Mock des HTTP-Clients: die Tests gehen damit über
 * `java.net.http.HttpClient` und die echte Serialisierung, also über den
 * gleichen Weg wie ein Aufrufer.
 */
internal class FakeVerifier : AutoCloseable {
    private val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
    private val recorded = CopyOnWriteArrayList<RecordedRequest>()

    @Volatile
    var handler: (RecordedRequest) -> FakeResponse = { FakeResponse(404, """{"error":"not_found"}""") }

    val requests: List<RecordedRequest> get() = recorded.toList()

    val baseUrl: String get() = "http://127.0.0.1:${server.address.port}"

    init {
        server.createContext("/") { exchange: HttpExchange ->
            val body = exchange.requestBody.readBytes().toString(StandardCharsets.UTF_8)
            val request = RecordedRequest(
                method = exchange.requestMethod,
                path = exchange.requestURI.path,
                rawPath = exchange.requestURI.rawPath,
                headers = exchange.requestHeaders.entries.associate { (key, values) ->
                    key.lowercase() to values.joinToString(", ")
                },
                body = body,
            )
            recorded.add(request)
            val response = runCatching { handler(request) }.getOrElse { throwable ->
                FakeResponse(500, """{"error":"internal_error"}""").also {
                    System.err.println("Fehler im Test-Handler: $throwable")
                }
            }
            val bytes = response.body.toByteArray(StandardCharsets.UTF_8)
            response.headers.forEach { (key, value) -> exchange.responseHeaders.add(key, value) }
            if (response.contentType != null) {
                exchange.responseHeaders.add("content-type", response.contentType)
            }
            exchange.sendResponseHeaders(response.status, if (bytes.isEmpty()) -1L else bytes.size.toLong())
            if (bytes.isNotEmpty()) {
                exchange.responseBody.use { it.write(bytes) }
            }
        }
        server.start()
    }

    override fun close() {
        server.stop(0)
    }
}
