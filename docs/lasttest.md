# Lasttest der Haupt-API

Stand: 27.09.2026 · Branch `launch-readiness-2026-09-27` · Messung auf einem
Entwickler-Laptop (macOS, Apple Silicon), Protokoll HTTP/1.1, ein Prozess.

## Was gemessen wurde und was nicht

Der Test ist kein Ersatz für eine Kapazitätsplanung. Er beantwortet zwei
Fragen: Bleibt die Latenz unter Last im Rahmen, und bleibt der Dienst unter
Last stabil und fehlerfrei. Die Durchsatzzahl ist eine Untergrenze, weil
Lastgenerator und Dienst auf derselben Maschine laufen (siehe unten).

## SLO-Vorschlag

Die Werte sind ein Vorschlag, keine abgestimmte Zielvereinbarung. Sie sind aus
der Messung abgeleitet und lassen bewusst großen Spielraum, damit sie auf
langsamer Hardware nicht falsch alarmieren. Anpassbar über `--slo-*`, siehe
`npm run loadtest -- --help`.

| SLO | Wert | Begründung |
|---|---|---|
| p95 Latenz | ≤ 50 ms | Gemessen 6–35 ms über den gesamten Lastbereich. Zehnfache Reserve. |
| p99 Latenz | ≤ 100 ms | Gemessen 11–42 ms. |
| Unerwartete Antworten | ≤ 1 % | 429 zählen nicht als Fehler, sie sind dokumentiertes Verhalten. |
| Durchsatz Betriebsrouten | ≥ 100 req/s | Gemessen über 15.000 req/s. Die Grenze ist der Generator, nicht der Dienst. |

Warum 429 nicht als Fehler zählt: Das Ratenlimit ist beabsichtigt, in
`docs/fehlercodes.md` dokumentiert und getestet. Es als Fehler zu werten hieße,
das gewollte Verhalten zu bestrafen.

## Ergebnis

Hauptlauf: 50 Verbindungen, 30 s je Betriebsroute, 50 Anfragen je Fachroute.

| Szenario | Art | Anfragen | p50 | p95 | p99 | max | Status |
|---|---|---|---|---|---|---|---|
| Betriebsrouten | Dauerlast, limitfrei | 1.751.003 | 2,6 ms | 6,3 ms | 11,4 ms | 136,6 ms | 200 |
| create | Burst, unter Limit | 50 | 48,6 ms | 48,8 ms | 49,4 ms | 49,4 ms | 201 |
| read | Burst, unter Limit | 50 | 3,8 ms | 8,2 ms | 8,3 ms | 8,3 ms | 200 |
| request-object | Burst, unter Limit | 50 | 1,6 ms | 1,9 ms | 1,9 ms | 1,9 ms | 200 |
| direct-post | Burst, unter Limit | 50 | 4,3 ms | 7,3 ms | 7,4 ms | 7,4 ms | 400 |

Keine unerwarteten Antworten in 1.751.153 Anfragen. Der Dienst blieb danach
`/ready` und bewegte sich über die Laufzeit im normalen Rahmen (78–86 MB RSS,
kein Wachstum erkennbar).

### Skalierung der Betriebsrouten

| Verbindungen | Anfragen | Durchsatz | p50 | p95 | p99 |
|---|---|---|---|---|---|
| 50 | 1.751.003 | 14.590 req/s | 2,6 ms | 6,3 ms | 11,4 ms |
| 100 | 534.525 | 16.691 req/s | 5,2 ms | 8,6 ms | 12,7 ms |
| 200 | 471.959 | 14.729 req/s | 12,7 ms | 20,1 ms | 27,6 ms |
| 400 | 523.263 | 16.325 req/s | 23,4 ms | 34,6 ms | 41,7 ms |

Der Durchsatz sättigt ab 100 Verbindungen bei rund 15.000 bis 17.000 req/s,
während die Latenz linear mitwächst. Das ist das erwartete Bild für eine
Warteschlange, nicht für einen Dienst, der einbricht.

## Die eigentliche Grenze liegt im Rate-Limit, nicht in der Hardware

Das ist der wichtigste Befund dieser Messung.

Die Betriebsrouten sind vom Ratenlimit ausgenommen
(`src/service/app.ts`, `shouldRateLimit`). Für die Fachrouten gilt ein festes
Fenster von 60 Anfragen je Mandant und 120 je IP-Adresse in 60 Sekunden
(`src/service/rate-limit.ts`). Nachgerechnet und verifiziert: 65 aufeinander
folgende `POST /v1/verification-requests` mit einem Mandanten liefern
**60 × 201 und 5 × 429**, die 429-Antwort mit `x-ratelimit-limit: 60`,
`x-ratelimit-remaining: 0` und `retry-after: 56`.

Daraus folgt: Mit der Voreinstellung kann der Dienst dauerhaft **eine Anfrage
je Sekunde und Mandant** annehmen. Für alles darüber gibt es keine
Kapazitätsaussage, weil der Dienst vorher mit 429 antwortet. Jede Aussage
über „Tragfähigkeit“ der Fachrouten wäre mit den Voreinstellungen eine
Fiktion.

Seit dem 27.09.2026 ist dieser Wert keine feste Eigenschaft mehr, sondern über
`ATTACK_RATE_LIMIT_TENANT_PER_WINDOW` und `ATTACK_RATE_LIMIT_WINDOW_SECONDS`
einstellbar; die Voreinstellung ist unverändert 60 je 60 Sekunden. Die
Messung oben gilt also für die **Voreinstellung**, nicht für eine eingestellte
Konfiguration. Wer den Wert erhöht, muss neu messen: die Latenzzahlen
entstehen bei `POST /v1/verification-requests` aus je einer ECDH-Schlüsselerzeugung
und Signatur, beides CPU-gebunden und nicht durch das Ratenlimit begrenzt.

Der Limiter zählt prozesslokal und im Arbeitsspeicher. Bei mehreren Instanzen
ist die wirksame Grenze das Produkt aus Einzelgrenze und Instanzzahl; eine
gemeinsame Ablage fehlt (`docs/eidas-arf-konformitaet.md` führt das als nicht
nachgewiesen).

## create ist der teure Pfad

`POST /v1/verification-requests` liegt mit rund 49 ms um eine Größenordnung
über allen anderen Routen. Der Grund ist plausibel: je Sitzung wird ein
ECDH-Schlüsselpaar erzeugt und das Request Object signiert, also
asymmetrische Kryptografie pro Anfrage. Das ist kein Fehler, aber es heißt:
Die Kosten des Dienstes hängen an der Sitzungserzeugung, nicht am
Ausliefern von Daten. Wer die Latenz optimieren will, muss dort anfangen.

## Wo die gemessene Zahl zu hoch ist

Die 15.000 bis 17.000 req/s sind **nicht** die Leistung des Dienstes. Ein
parallel laufender Test zeigte, dass der Lastgenerator dabei rund 150 % einer
CPU nutzt, während der Dienst bei etwa 50 % steht. Vier Generatorprozesse
parallel kamen zusammen auf rund 20.000 req/s, jeder einzelne nur auf rund
5.000.

Der Lastgenerator ist also der Engpass. Belastbar ist die Aussage: Der Dienst
hat bei 50 % CPU-Auslastung eine p95 von 6 ms erreicht und dabei mehr als 1,7
Millionen Anfragen ohne einen einzigen unerwarteten Fehler beantwortet. Wie
viel er bei voller CPU leistet, wurde nicht gemessen und lässt sich mit einem
Generator auf derselben Maschine auch nicht messen. Dafür bräuchte es
mehrere Maschinen oder `autocannon` mit mehreren Worker-Prozessen.

## Reproduktion

```bash
# Dienst im Dev-Modus starten (Testmaterial und Test-Mandanten)
ATTACK_DEV_MODE=true ATTACK_ALLOW_SELF_SIGNED=true npm run service

# In einem zweiten Terminal
npm run loadtest -- --api-key test-api-key-tenant-A \
  --duration 30000 --concurrency 50 --max-per-route 50 \
  --json docs/lasttest-ergebnis.json
```

Der Harness ist bewusst kein Vitest-Test (`tools/loadtest-main-api.ts`): ein
Lasttest dauert, und ein Latenzverstoß soll die Unit-Suite nicht rot machen.
Er hat einen eigenen Exit-Code und lässt sich in eine CI-Stufe hängen, sobald
eine Referenzmaschine festgelegt ist.

## Nächste Schritte

1. Entscheiden, welches Mandanten- und IP-Limit der Produktivbetrieb braucht,
   und die Voreinstellung konfigurierbar machen, statt sie im Code zu
   verdrahten.
2. Referenzmaschine festlegen, sonst ist jeder Vergleich zwischen zwei Läufen
   wertlos.
3. `direct_post` mit echten Wallet-JWE-Headern messen. Der Burst hier prüft
   nur den Parsing- und Validierungspfad; die Signaturprüfung ist nicht
   enthalten, weil sie eine echte Präsentation braucht.
4. Sitzungserzeugung separat messen, wenn die Latenz im Zielbereich liegt.
