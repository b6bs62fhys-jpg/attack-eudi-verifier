# Betrieb

Diese Datei sammelt das, was für den Betrieb belegbar ist. Jede Aussage nennt
ihre Quelle. Was nicht aus Code oder vorhandener Dokumentation belegbar ist,
steht als Lücke in Abschnitt 6 und nicht hier.

Die Pflichtvariablen und der Startbefehl sind aus `docs/deployment.md`
übernommen, nicht neu erfunden.

## 1. Start

### Produktionsstart

Aus `docs/deployment.md:10-19`. Das Image enthält nur Produktionsabhängigkeiten,
den Anwendungsquelltext und den Nicht-Root-Benutzer `node`; es läuft auf
Node.js 22 mit TypeScript-Type-Stripping (`docs/deployment.md:3-6`).

```bash
docker build -t attack-verifier:local .
docker run --rm -p 8080:8080 \
  -e NODE_ENV=production \
  -e ATTACK_VERIFIER_KEY_PEM=/run/secrets/verifier-key.pem \
  -e ATTACK_VERIFIER_CERT_CHAIN_PEM=/run/secrets/verifier-chain.pem \
  -e ATTACK_ISSUER_TRUST_ANCHORS_PEM=/run/secrets/issuer-anchors.pem \
  -v "$PWD/secrets:/run/secrets:ro" \
  attack-verifier:local
```

**Pflicht im Produktionsbetrieb** (`docs/deployment.md:27-32`):

- `NODE_ENV=production`
- `ATTACK_VERIFIER_KEY_PEM` — eingebundenes PEM, PKCS#8-Verifier-Private-Key
- `ATTACK_VERIFIER_CERT_CHAIN_PEM` — eingebundene Verifier-Zertifikatskette, Blatt zuerst
- `ATTACK_ISSUER_TRUST_ANCHORS_PEM` — eingebundene Aussteller-Vertrauensanker

**Pflicht, sobald das Onboarding-Gate aktiviert ist**
(`docs/deployment.md:34-37`):

- `ATTACK_ONBOARDING_ACCESS_CA_PEM` — Access-CA-Anker
- `ATTACK_ONBOARDING_WRPRC_ISSUER_PEM` — WRPRC-Aussteller-Anker

Der Dienst fällt zu, wenn Produktionsidentität oder Aussteller-Anker fehlen
(`docs/deployment.md:21-23`).

### Startverhalten bei fehlender Verifier-Identität

Der Einstiegspunkt `src/service/run.ts:32-38` fängt **jeden** Fehler aus dem
Bootstrap ab, gibt eine Meldung aus und beendet mit Exit-Code 1. Es gibt kein
Pfad, auf dem ein Konfigurationsfehler den Dienst starten lässt.

| Situation | Meldung | Quelle |
|---|---|---|
| beide Variablen fehlen | `Keine Verifier-Identität konfiguriert und kein Test-Rückfall erlaubt (Produktionsmodus). …` | `src/service/verifier-identity.ts:140` |
| genau eine Variable fehlt | `ATTACK_VERIFIER_<NAME>: nicht gesetzt. ATTACK_VERIFIER_KEY_PEM und ATTACK_VERIFIER_CERT_CHAIN_PEM müssen zusammen gesetzt sein (beide oder keine). Start abgebrochen.` | `src/service/verifier-identity.ts:76-85` |
| `NODE_ENV=production` und `ATTACK_DEV_MODE=true` | `NODE_ENV=production und ATTACK_DEV_MODE=true widersprechen sich. …` | `src/config.ts:121-126` |
| `ATTACK_ALLOW_SELF_SIGNED=true` in Produktion | `ATTACK_ALLOW_SELF_SIGNED=true ist in NODE_ENV=production verboten. …` | `src/config.ts:128-134` |
| `ATTACK_ALLOW_SELF_SIGNED=true` ohne `ATTACK_DEV_MODE=true` | `ATTACK_ALLOW_SELF_SIGNED=true ist nur zusammen mit ATTACK_DEV_MODE=true erlaubt. …` | `src/config.ts:138-143` |
| `PORT` nicht ganzzahlig oder außerhalb 1–65535 | `PORT muss eine ganze Zahl zwischen 1 und 65535 sein. Start abgebrochen.` | `src/config.ts:149-151` |
| `ATTACK_RESULT_TTL_SECONDS` außerhalb 1–3600 | `ATTACK_RESULT_TTL_SECONDS muss eine ganze Zahl zwischen 1 und 3600 sein. Start abgebrochen.` | `src/config.ts:161-163` |

`startupFailureMessage` (`src/config.ts:226-230`) gibt bei einem `ConfigError`
dessen Meldung unverändert aus, bei jedem anderen Fehler nur
`Start abgebrochen: unerwarteter Fehler beim Start (<Typ>).` — **ohne
Stacktrace und ohne Schlüsselinhalt**. Fünf Stellen werfen noch einen einfachen
`Error` statt eines `ConfigError` und zeigen deshalb die generische Meldung;
siehe [interne Notiz, nicht veröffentlicht], Punkt 14.

### Entwicklung

Aus dem `package.json`, Skript `demo`:

```bash
npm run demo
```

Das setzt `ATTACK_DEV_MODE=true ATTACK_ALLOW_SELF_SIGNED=true
NODE_ENV=development` und startet den Flow-Demo-Server. Für den Dienst selbst
mit Testmaterial:

```bash
npm run service
```

`ATTACK_DEV_MODE=true` allein reicht nicht für die Flow-Demo: sie verlangt
zusätzlich `ATTACK_ALLOW_SELF_SIGNED=true`
(`src/demo/flow-server.ts:209-213`).

## 2. Konfiguration

Alle Variablen aus `src/config.ts`, per `grep ENV_ATTACK` erhoben. Keine
zusätzlichen, keine ausgelassenen.

| Name | Pflicht | Standard | Wertebereich | Bedeutung |
|---|---|---|---|---|
| `NODE_ENV` | im Produktionsbetrieb ja | `development` | `development` / `production` | Schaltet die strenge Betriebsweise. `production` verbietet die Entwicklungsschalter (`src/config.ts:116-134`). |
| `PORT` | nein | `8080` (`loadConfig`, `src/config.ts:114`) | ganze Zahl 1–65535 | Port des HTTP-Servers. |
| `ATTACK_HOST` | nein | `127.0.0.1` (`src/config.ts:155`) | beliebige Adresse | Bindeadresse. |
| `ATTACK_DEV_MODE` | nein | nicht gesetzt | `true` / sonst etwas | Entwicklungsschalter. Aktiviert TEST-Identität, TEST-Anker und Test-Mandanten. In Produktion verboten. |
| `ATTACK_ALLOW_SELF_SIGNED` | nein | nicht gesetzt | `true` / sonst etwas | Erlaubt selbstsignierte Verifier-Zertifikate. Nur zusammen mit `ATTACK_DEV_MODE=true`, nie in Produktion (`src/config.ts:138-143`). |
| `ATTACK_VERIFIER_KEY_PEM` | ja, paarweise | — | Pfad zu einer lesbaren PEM | Privater Schlüssel, PKCS#8, ECDSA P-256. |
| `ATTACK_VERIFIER_CERT_CHAIN_PEM` | ja, paarweise | — | Pfad zu einer lesbaren PEM | Verifier-Zertifikatskette, Blatt zuerst. |
| `ATTACK_ISSUER_TRUST_ANCHORS_PEM` | ja im Produktionsbetrieb | — | Pfad zu einer lesbaren PEM | Aussteller-Vertrauensanker. Fehlt sie, startet der Dienst nicht. |
| `ATTACK_CLOCK_SKEW_SECONDS` | nein | `DEFAULT_CLOCK_SKEW_SECONDS_CONFIG` | 0 bis `CLOCK_SKEW_SECONDS_MAX` = 300 | Erlaubte Uhrabweichung bei der Zertifikatsprüfung (`src/config.ts:47, 170`). |
| `ATTACK_RESULT_TTL_SECONDS` | nein | `60` (`src/config.ts:50`) | ganze Zahl 1–3600 | Lebensdauer des Ergebnisses, bevor es aus dem RAM fällt. |
| `ATTACK_RATE_LIMIT_PUBLIC_PER_WINDOW` | nein | `120` (`src/config.ts:57`) | ganze Zahl | Ratenlimit der öffentlichen Routen je IP im Fenster. Gilt für `/direct_post` und das Request-Object, **nicht** für die Betriebsrouten (`src/config.ts:52-55`). |
| `ATTACK_RATE_LIMIT_TENANT_PER_WINDOW` | nein | `60` (`src/config.ts:64`) | ganze Zahl | Ratenlimit der mandantenpflichtigen Routen je API-Schlüssel im Fenster. |
| `ATTACK_RATE_LIMIT_WINDOW_SECONDS` | nein | `60` (`src/config.ts:67`) | 1 bis 3600 | Länge des Ratenfensters. |

`ATTACK_ONBOARDING_ACCESS_CA_PEM` und `ATTACK_ONBOARDING_WRPRC_ISSUER_PEM`
stehen in `docs/deployment.md:34-37`, werden aber in `src/config.ts` nicht über
ein `ENV_ATTACK_*`-Konstante deklariert; die Verdrahtung liegt in
`src/onboarding/onboarding-wiring.ts`.

## 3. Rate Limits

Quellen: `src/config.ts:51-70` und `src/service/rate-limit.ts`.

| Aspekt | Wert |
|---|---|
| öffentliche Routen, je IP im Fenster | 120 (konfigurierbar) |
| mandantenpflichtige Routen, je API-Schlüssel im Fenster | 60 (konfigurierbar) |
| Fensterlänge | 60 Sekunden (konfigurierbar, 1–3600) |
| öffentlich wirksam für | `/direct_post`, `/v1/verification-requests/:id/request-object` |
| ausgenommen | die Betriebsrouten `/live`, `/health`, `/ready`, `/metrics` |

Der Kommentar in `src/config.ts:58-62` nennt 60 je 60 Sekunden „die eigentliche
Obergrenze des Dienstes" und rechnet dauerhaft rund eine Anfrage je Sekunde und
Mandant. Das ist die beabsichtigte Auslegung, keine gemessene Grenze.

Was bei Überschreitung passiert, steht in `docs/fehlercodes.md` unter dem Code
`rate_limited` und in `openapi.yaml` als Antwort `429`.

## 4. Monitoring

Alle vier Routen sind `access: 'public'` und brauchen keinen API-Schlüssel
(`src/service/app.ts:186-215`).

| Route | Zweck laut Code | Antwort |
|---|---|---|
| `GET /live` | reiner Lebenszeichen-Endpunkt: `sendJson(res, 200, { ok: true, status: 'live', app })` | 200 mit `{ "ok": true, "status": "live", "app": … }` |
| `GET /health` | **identisch zu `/live`** — Zeile 196 liefert denselben Ausdruck wie Zeile 189 | 200, byteweise derselbe Body |
| `GET /ready` | einzige Route, die Abhängigkeiten prüft: `deps.readiness()` und meldet `checks` je Abhängigkeit | 200 mit `status: ready` oder 503 mit `status: not_ready` und `checks` |
| `GET /metrics` | Prometheus-Ausgabe | 200, `content-type: text/plain; version=0.0.4` |

`/live` und `/health` sind bewusst identisch (`src/service/app.ts:189` und
`:196`). Beide sagen **nur**, dass der Prozess läuft. Sie sagen nichts über
Abhängigkeiten. **Nur `/ready` prüft Abhängigkeiten** — dort landet auch
`onboarding: failed`, solange kein Gate-Material konfiguriert ist.

`/ready` mit 503 ist eine gültige Antwort auf die Frage, nicht ein Fehler: die
SDKs liefern dafür einen Wert statt einer Ausnahme (`sdk/typescript/README.md`,
Abschnitt „Readiness").

## 5. Fehlercodes

Die vollständige Liste mit Bedeutung steht in `docs/fehlercodes.md`, die
Response-Schemas in `openapi.yaml`. Hier wird nichts wiederholt.

Für den Betrieb wichtig sind nur zwei Zuordnungen:

- **401** bedeutet ausschließlich fehlenden oder unbekannten API-Schlüssel
  (`docs/fehlercodes.md:59`).
- **422 auf `/direct_post`** bedeutet, dass die Präsentation **nicht verarbeitet**
  werden konnte, nicht, dass sie abgelehnt wurde. Eine verarbeitete und inhaltlich
  abgelehnte Präsentation trägt 200 mit `valid: false` und dem Grund im Feld
  `error`. Die Herleitung steht in `src/service/app.ts:250-256`; siehe
  `docs/fehlercodes.md`, Abschnitt „Präsentation (`POST /direct_post`)".

## 6. Vorgehen bei Störungen

Belegbar ist Folgendes; der Rest ist in diesem Repository nicht festgelegt und
wird hier als Lücke benannt statt ergänzt.

### Start bricht ab

1. Die Meldung nennt die Ursache. Die Zuordnung steht in Abschnitt 1 dieser
   Datei. Ein Stacktrace fehlt absichtlich (`src/config.ts:223-225`).
2. Fehlt nur eine der beiden Verifier-Variablen, nennt die Meldung sie beim
   Namen. Das ist das Verhalten aus Paket F.
3. Bleibt die Meldung `unerwarteter Fehler beim Start (Error).`, liegt einer der
   in [interne Notiz, nicht veröffentlicht], Punkt 14, genannten Fälle vor: unlesbare
   oder unbrauchbare PEM-Datei. Der Fehlertext wird bewusst nicht ausgegeben.

### `/ready` meldet 503

`checks` im Body benennt die Abhängigkeit. `onboarding: failed` bedeutet fehlendes
Gate-Material (`ATTACK_ONBOARDING_ACCESS_CA_PEM`,
`ATTACK_ONBOARDING_WRPRC_ISSUER_PEM`) und ist ein bekannter, nicht behobener
Zustand.

### Geheimnisse und Schlüssel

`docs/sicherheit.md:31-40` beschreibt die Suche nach Geheimnissen im Repository
mit dem dort genannten `git ls-files`-Befehl. Schlüsselmaterial wird als
eingebundene PEM über `/run/secrets` gegeben, nie als Umgebungswert
(`docs/deployment.md:14-17`).

### Reproduzierbare Prüfbefehle

`docs/sicherheit.md:289-299` nennt die Befehle, mit denen sich der Zustand
prüfen lässt. Die dort genannte Testzahl ist der aktuelle Stand.

### Als Lücke benannt

- **Kein Runbook für den Betrieb im Repository.** Es gibt Alarmierungsregeln
  und Runbooks, aber [interne Notiz, nicht veröffentlicht] ist kein Betriebs-Handbuch. Wer den
  Dienst betreibt, braucht eine Festlegung, wer bei `/ready` 503 alarmiert wird
  und welche Schwellen gelten. **Nicht belegt, offen.**
- **Kein Logpfad festgelegt.** Der Dienst schreibt JSON-Zeilen auf STDOUT
  ([interne Notiz, nicht veröffentlicht], Abschnitt 5). Wohin die gehen, wie lange sie
  bleiben und wer sie liest, ist nicht festgelegt. **Nicht belegt, offen.**
- **Kein Restore oder Migration.** [interne Notiz, nicht veröffentlicht] hält fest,
  dass es keinen persistenten Zustand gibt; das Ergebnis liegt im RAM und ist
  nach `ATTACK_RESULT_TTL_SECONDS` weg. Ein Wiederanlauf nach Datenverlust ist
  damit unkritisch, ein Verfahren dafür ist aber nicht beschrieben. **Offen.**
