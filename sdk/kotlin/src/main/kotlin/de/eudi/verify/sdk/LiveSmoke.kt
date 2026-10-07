package de.eudi.verify.sdk

import java.time.Duration

/**
 * Rauchtest gegen einen laufenden Dienst.
 *
 * Aufruf:
 * ```
 * ATTACK_URL=http://127.0.0.1:8099 ATTACK_API_KEY=test-api-key-tenant-A \
 *   gradle -q runSmoke
 * ```
 *
 * Der Test ist bewusst kein JUnit-Test: er braucht einen laufenden Dienst und
 * gehoert deshalb nicht in `gradle test`.
 */
public object LiveSmoke {
    @JvmStatic
    public fun main(args: Array<String>) {
        val baseUrl = System.getenv("ATTACK_URL") ?: "http://127.0.0.1:8080"
        val apiKey = System.getenv("ATTACK_API_KEY")
        val client = AttackClient(baseUrl, apiKey, requestTimeout = Duration.ofSeconds(10))

        val liveness = client.getLiveness()
        println("live: ok=${liveness.ok} status=${liveness.status} app=${liveness.app}")

        val readiness = client.getReadiness()
        println("ready: ok=${readiness.ok} status=${readiness.status} checks=${readiness.checks}")

        val metrics = client.getMetrics()
        val requestCounter = metrics.lineSequence().firstOrNull { it.startsWith("attack_http_requests_total") }
        println("metrics: ${metrics.lines().size} Zeilen, z. B. $requestCounter")

        if (apiKey != null) {
            val created = client.createPresentationRequest(CreateRequestInput(claims = listOf("given_name")))
            println("create: session=${created.sessionId} state=${created.state} expiresAt=${created.expiresAt}")

            val requestObject = client.getRequestObject(created.sessionId)
            println("request-object: ${requestObject.length} Zeichen, JWT=${requestObject.count { it == '.' } + 1} Teile")

            val status = client.getResult(created.sessionId)
            println("result: status=${status.status}")

            val deleted = runCatching { client.deleteSession(created.sessionId) }
            println("delete: ${if (deleted.isSuccess) "ok" else "fehlgeschlagen: ${deleted.exceptionOrNull()?.message}"}")
        } else {
            println("uebersprungen: Mandantenrouten, weil ATTACK_API_KEY nicht gesetzt ist")
        }
    }
}
