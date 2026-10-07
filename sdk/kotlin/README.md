# `eudi-verify-sdk-kotlin`

Typisierter JVM-Client für die Attack EUDI Verifier API. Das Paket ist ein
repository-lokaler SDK-Kandidat und noch nicht veröffentlicht. Es ist das
Gegenstück zu [`sdk/typescript`](../typescript) und [`sdk/python`](../python)
und wird aus derselben Quelle [`openapi.yaml`](../../openapi.yaml) im
Repository-Wurzelverzeichnis abgeleitet.

## Voraussetzungen

| Werkzeug | Version | Zweck |
|---|---|---|
| JDK | 21 | Bauen und Testen |
| Gradle | 8.x oder 9.x | Build |
| Kotlin | 2.4.20 | über den Gradle-Plugin, nicht lokal nötig |

Getestet mit Temurin/OpenJDK 21.0.12 und Gradle 9.7.1. Für den Build wird
`JAVA_HOME` auf ein JDK 21 gesetzt:

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
cd sdk/kotlin
gradle test
```

Es ist bewusst **kein** Gradle-Wrapper eingecheckt. Ein Wrapper würde eine
Binaerdatei (`gradle-wrapper.jar`) ins Repository bringen; da der Build ohnehin
eine installierte Gradle-Version braucht, steht die Anforderung hier oben.

## Installation

Noch nicht veroeffentlicht. Einbau als Verzeichnis:

```kotlin
dependencies {
    implementation(project(":sdk:kotlin"))
}
```

## Betriebsrouten

`/live`, `/health`, `/ready` und `/metrics` sind oeffentlich und werden nicht
rate-limitiert. `getReadiness()` wirft bei HTTP 403/503 **nicht**, weil
`not_ready` eine gueltige Antwort ist und die Pruefergebnisse in `checks`
auswertbar bleiben:

```kotlin
val readiness = attack.getReadiness()
if (!readiness.ok) {
    readiness.checks.forEach { (name, status) -> println("$name: $status") }
}
```

`getMetrics()` liefert das Prometheus-Textformat 0.0.4 als String. Der Dienst
exportiert nur Counter und Summen, deshalb sind daraus **keine Quantile wie
p95 berechenbar**. Wer Latenzverteilung braucht, misst sie beim Aufrufer.

## Mandantenrouten

Der API-Schluessel gehoert auf den Server. Er darf nicht in Browser- oder
Mobilcode stehen, weil er den Mandanten vollstaendig vertritt:

```kotlin
val attack = AttackClient(
    baseUrl = System.getenv("ATTACK_URL") ?: "http://127.0.0.1:8080",
    apiKey = System.getenv("ATTACK_API_KEY"),
)

// Leere Eingabe nutzt das Anfrageprofil des Mandanten.
val request = attack.createPresentationRequest(CreateRequestInput(claims = listOf("age_over_18")))
println("${request.requestObjectUri} ${request.responseUri}")

val status = attack.getResult(request.sessionId)
if (status.status == ResultState.COMPLETED) {
    println(status.result?.claims)
}
```

Ein fertiges Ergebnis wird genau einmal ausgeliefert. Danach ist die Sitzung
nicht mehr von einer unbekannten Sitzung zu unterscheiden.

## Wallet-Praesentation

Ohne JWE wird die Praesentation im Klartext angenommen:

```kotlin
val response = attack.submitPresentation(DirectPostEnvelope.ofSdJwts(state, "pid", sdJwt))
if (!response.ok) println("nicht verarbeitbar: ${response.error}")
else if (!response.valid) println("fachlich abgelehnt: ${response.error}")
```

`submitPresentation` wirft fuer eine **abgelehnte** Praesentation nicht, sondern
liefert das Ergebnis. `/direct_post` ist die oeffentliche Wallet-Route, daher ist
zu beachten: **der HTTP-Status sagt nur, ob der Dienst die Praesentation
verarbeiten konnte, nicht ob sie gueltig ist.**

| `ok` | `valid` | HTTP | Bedeutung |
|---|---|---|---|
| `false` | `false` | 422 | nicht verarbeitbar: unbekannte Sitzung, Formfehler, Replay, JWE-Problem |
| `true` | `false` | 200 | verarbeitet und inhaltlich abgelehnt, z. B. `certificate_expired` |
| `true` | `true` | 200 | gueltig |

Zu pruefen ist zuerst `response.ok`, dann `response.valid`, dann
`response.error`. HTTP 401 bleibt exklusiv fuer den API-Schluessel und 413
fuer die Groessengrenze; beide loesen weiterhin `AttackApiError` aus.

```kotlin
val response = attack.submitPresentation(DirectPostEnvelope.ofSdJwts(state, "pid", sdJwt))
if (!response.ok) {
    println("nicht verarbeitbar: ${response.error}") // unknown_state, state_invalid, …
} else if (!response.valid) {
    println("fachlich abgelehnt: ${response.error}") // 200, verarbeitet und abgelehnt
}
```

**Nur `valid` zu pruefen genuegt nicht**, denn bei 422 ist `valid` ebenfalls
`false`.

Mit `direct_post.jwt` wird die Antwort der Wallet als Compact JWE geschickt:

```kotlin
val response = attack.submitPresentation(DirectPostJwe(compactJwe))
```

Verschachtelte `vp_token`-Strukturen lassen sich mit `AttackJson` bauen, weil
`JsonPrimitive` in Kotlin eine Top-Level-Funktion ist und aus Java nur
umstaendlich erreichbar waere:

```kotlin
val envelope = DirectPostEnvelope(
    vpToken = mapOf("pid" to listOf(AttackJson.parseObject("""{"proof":{"type":"jwt"}}"""))),
    state = state,
)
```

## Fehler

`AttackApiError` traegt den HTTP-Status und – wenn der Dienst einen Code
liefert – den stabilen Code aus dem Feld `error`:

| Situation | Ausnahme |
|---|---|
| 4xx/5xx mit Fehlercode | `AttackApiError` mit `status` und `code` |
| Dienst nicht erreichbar | `AttackTransportError` |
| `GET /ready` mit 503 | **keine** Ausnahme, siehe oben |

Die vollstaendige Codeliste steht in `openapi.yaml` und `docs/fehlercodes.md`.
Ein Fehlerkoerper ohne `error`-Feld ergibt `code == null`, kein erfundener Code.

## Java

Der Client ist aus reinem Java benutzbar; das ist in
[`JavaInteropTest`](src/test/java/de/eudi/verify/sdk/JavaInteropTest.java)
nachgewiesen, einem JUnit-Test, der absichtlich in Java geschrieben ist:

```java
AttackClient client = new AttackClient(baseUrl, apiKey);
CreateRequestOutput created = client.createPresentationRequest(
        new CreateRequestInput(List.of("age_over_18"), null, null));
DirectPostEnvelope envelope = DirectPostEnvelope.ofSdJwts(state, "pid", sdJwt);
PresentationResponse response = client.submitPresentation(envelope);
```

## Tests

```bash
gradle test
```

31 Tests: 27 in Kotlin gegen einen echten HTTP-Testserver auf `127.0.0.1`
(kein Mock des HTTP-Clients, also mit echter Serialisierung und echter
 Kodierung von Pfaden) und 4 in Java fuer die Interoperabilitaet.

Ein Rauchtest gegen einen laufenden Dienst gehoert nicht in `gradle test`,
sondern in das eigene Task:

```bash
ATTACK_URL=http://127.0.0.1:8099 ATTACK_API_KEY=test-api-key-tenant-A gradle -q runSmoke
```

## Bekannte Grenzen

- Nicht veroeffentlicht, keine semantische Versionierung, kein Changelog.
- Kein Retry, keine backoff-Bibliothek, kein OpenTelemetry.
- `getRequestObject` und `getMetrics` geben den Koerper als Text zurueck; ein
  Content-Type-Missmatch wird nicht als Fehler erkannt.
- Kein Interoperabilitaetslauf gegen eine echte Wallet. Der Protokollteil
  (`direct_post`) ist gegen einen Testserver geprueft, nicht gegen eine
  HAIP-Wallet.
