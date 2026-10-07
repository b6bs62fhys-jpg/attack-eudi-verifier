# CI

Die Pipeline in `.github/workflows/ci.yml` läuft bei Pushes auf `main` und bei
Pull Requests gegen `main`. Alle Jobs laufen auf `ubuntu-24.04`.

> **Öffentliche Kopie:** Die Pipeline in diesem Repository ist auf fünf Jobs
> reduziert (Typecheck, Lint, Test, Coverage, `npm audit`) und braucht keine
> Secrets. Die folgenden Abschnitte beschreiben auch Jobs der internen
> Pipeline (SDK, Docker, Release Trockenlauf), die hier nicht laufen.

## Runner sind gepinnt, nicht `ubuntu-latest`

`ubuntu-latest` zeigt am 19.10.2026 auf Ubuntu 26. Ein Runner-Wechsel ändert
das Verhalten einer Pipeline, ohne dass eine Datei im Repository sich ändert.
Deshalb steht überall `ubuntu-24.04`.

**Der Wechsel auf `ubuntu-26.04` wird bewusst separat getestet**, in einem
eigenen Commit mit eigenem PR und eigener CI-Lauf. Nicht in einem
gemischten Commit mit funktionalen Änderungen: sonst ist bei einem roten Lauf
nicht mehr zu unterscheiden, ob die Änderung oder der neue Runner ihn
verursacht hat.

## Concurrency

```yaml
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
```

Je Branch eine Gruppe. Ein neuer Push auf denselben Branch bricht einen
laufenden Lauf ab, statt ihn zu verdoppeln — das spart Minuten und
verhindert, dass ein veralteter Lauf später als der aktuelle zurückmeldet.

Auf `main` wird **nicht** abgebrochen. Dort ist der Lauf selbst der
Nachweis für den Merge; ein abgebrochener Push auf `main` hinterließe eine
unvollständige Prüfung ohne Ergebnis.

## Aktionsversionen sind geprüft, nicht geraten

Alle verwendeten Actions laufen nativ auf Node 24. Geprüft wurde das in der
`action.yml` der jeweiligen Version, nicht anhand der Versionsnummer
vermutet:

| Action | Version | `runs.using` |
|---|---|---|
| `actions/checkout` | v7 | `node24` |
| `actions/setup-node` | v7 | `node24` |
| `actions/setup-python` | v7 | `node24` |
| `actions/setup-java` | v6 | `node24` |
| `actions/setup-gradle` (gradle/actions) | v6 | `node24` |

Bei `setup-python` ist die Wahl nicht egal: v5 läuft noch auf `node20`,
erst v6 auf `node24`. `actions/setup-node` und `actions/checkout` sind
bereits ab v5 Node-24-nativ.

## Was der Lauf meldet und was davon bleibt

`annotations_count` ist in allen Jobs 0. Die Hinweise stehen im Log. Vier
Kategorien, alle gemessen am Lauf auf `main` vom 28.09.2026.

### Behoben

**`actions/upload-artifact` auf Node 20.** Wörtlich:

```text
##[warning]Node.js 20 is deprecated. The following actions target Node.js 20 but are being forced to run on Node.js 24: actions/upload-artifact@v4.
```

Aus dem `action.yml` jedes Tags: v7 und v6 sind `node24`, v5 und v4 sind
`node20`. Deshalb **v7**, nicht v6 — der Sprung über zwei Majors ist durch die
Warnlage entschieden, nicht durch Bequemlichkeit.

**`gradle/actions/setup-gradle` mit deprecated Eingabe.** Wörtlich:

```text
##[warning]This job uses deprecated functionality from the 'gradle/actions/setup-gradle' action. Consult the Job Summary for more details.
```

Ursache war `gradle-home-cache-cleanup: true`. Der neue Parameter heißt
`cache-cleanup` und ist **eine Aufzählung, kein Boolean** — `true` lässt den Job
abbrechen:

```text
TypeError: The value 'true' is not valid for cache-cleanup. Valid values are: [never, always, on-success].
```

Gültige Werte laut `action.yml` von v6: `never`, `on-success`, `always`.
Gesetzt ist `on-success`, der Default — dieselbe Wirkung wie vorher.

Im Lauf dieses Pakets: **null `##[warning]`-Zeilen.**

### Bewusst nicht behoben: `@sd-jwt` und der Sicherheitshinweis

Wörtlich aus dem Log:

```text
npm warn deprecated @sd-jwt/decode@0.19.0: Merged into @sd-jwt/core (>= 0.20.0). Security: GHSA-f9j6-8p6x-r9j6.
```

Transitiv, nicht direkt deklariert:

```text
attack@0.1.0
└─┬ @openeudi/openid4vp@0.11.1
  └── @sd-jwt/decode@0.19.0
```

**Ob 0.19.0 von dieser Advisory betroffen ist, wurde gemessen:**

| Prüfung | Ergebnis |
|---|---|
| `npm audit` (alle Schweregrade) | `found 0 vulnerabilities`, **Exit 0** |
| `npm audit --json` | `{"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}` |
| geprüfte Abhängigkeiten | 217 (42 prod, 168 dev, 35 optional) |
| `f9j6-8p6x-r9j6` im Audit-Bericht | **0 Treffer** |
| Einträge in `vulnerabilities` | **0** |
| `gh api /advisories/GHSA-f9j6-8p6x-r9j6` | **404 Not Found** |
| GHSA in der Advisory-Liste | **0 Treffer** |
| Registry-Metadaten `@sd-jwt/decode@0.19.0` | `deprecated`-Text nennt die GHSA, **kein** `vulnerabilities`-Feld |

**Damit das nicht falsch gelesen wird:** Die GHSA-ID steht **nur im
Deprecation-Text** des Paketautors. Sie taucht in der npm-Audit-Ausgabe nicht
auf und ist in der GitHub-Advisory-Datenbank nicht auffindbar. **Ob die
betroffenen Versionen 0.19.0 einschließen, lässt sich von hier aus nicht
feststellen** — die dafür nötige Advisory fehlt öffentlich.

Belastbar belegt ist nur: **`npm audit` bewertet diese Abhängigkeit als
unauffällig.** Ein Wechsel wäre trotzdem ein Abhängigkeitswechsel mit Auswirkung
auf `@openeudi/openid4vp` und gehört in einen eigenen Auftrag.

### Bewusst nicht behoben: Node-Hinweise aus transitiven Paketen

`DeprecationWarning: punycode` und `url.parse()` kommen aus transitiven
Abhängigkeiten, nicht aus eigenem Code. Node-Hinweise, keine Fehler, ohne
Abhängigkeitswechsel nicht zu beheben.

### Bewusst nicht behoben: der Python-Build

```text
WARNING `project.license` as a TOML table is deprecated
By 2027-Feb-18, you need to update your project and remove deprecated calls
```

Setuptools fordert einen SPDX-String oder `license-files`. Steht in
[interne Notiz, nicht veröffentlicht] als offener Punkt.

## Abhängigkeiten

`.github/dependabot.yml` pflegt wöchentlich sieben Ökosysteme: npm in
Wurzel, `sdk/typescript` und `examples/verifier-demo`, pip in `sdk/python`,
Gradle in `sdk/kotlin`, die GitHub Actions und **Docker** (das Basisimage des
Produktionscontainers, ergänzt 28.09.2026). Minor- und Patch-Updates
sind je zu einer Gruppe zusammengefasst, damit nicht zweimal dieselbe
Testsuite für dieselbe Bibliothek läuft. Die PR-Anzahl ist absichtlich klein
gewählt (1 bis 5 je Ökosystem), weil eine große Schlange offener
Dependabot-PRs keiner mehr priorisieren kann.

Beim Docker-Ökosystem ist das Limit **1**. Das Image ist ein einziger
gepinnter Digest in zwei `FROM`-Zeilen; zwei offene PRs wären zwei
konkurrierende Bumps desselben Digests. Dependabot schlägt eine neue
Tag-Version vor, aber **den Digest zu übernehmen bleibt Handarbeit** — er muss
erhoben und mit Datum bestätigt werden. Der `docker-build`-Job prüft die
Erreichbarkeit, nicht die Richtigkeit des Digests.

## Die Jobs

Zweck, Budget und gemessene Zeit stammen aus dem tatsächlichen Lesen von
`.github/workflows/ci.yml` und aus dem Lauf auf `main` vom 28.09.2026
(`gh api repos/{owner}/{repo}/actions/runs/…/jobs`). Budget ist
`timeout-minutes`. Es sind **13 Jobs**.

| Job (`name` im Workflow) | Was er prüft | Budget | gemessen |
|---|---|---|---|
| `Install and cache dependencies` | `npm ci` und Cache-Wärme; alle übrigen Jobs hängen an ihm | 15 min | 0,2 min |
| `Typecheck` | `npm run typecheck` (`tsc --noEmit`) | 15 min | 0,3 min |
| `Lint` | `npm run lint` mit `--max-warnings 0` | 15 min | 0,4 min |
| `Test suite` | `npm test` und `npm run test:coverage` | 20 min | 2,3 min |
| `Flake watch (repeated time-dependent tests)` | `npm run test:flake`, wiederholt die zeitabhängigen Dateien in eigenen Prozessen | 12 min | 2,6 min |
| `SDK consistency` | im Verzeichnis `sdk/typescript`: `npm run generate:check` (Drift-Wächter gegen `openapi.yaml`), `npm run build`, `npm test` | 15 min | 0,3 min |
| `SDK Python (Python 3.9)` | `pip install ".[dev]"`, dann `python -m mypy` und `python -m pytest -q` | 15 min | 0,3 min |
| `SDK Python (Python 3.12)` | dieselben drei Schritte auf der zweiten Version, 3.9 ist die deklarierte Untergrenze | 15 min | 0,3 min |
| `SDK Kotlin` | `gradle test` mit XML-Nachweis der Testzahl, danach `gradle build` | 20 min | 1,9 min |
| `Dependency audit` | `npm audit --audit-level=high` | 15 min | 0,2 min |
| `Coverage threshold` | `npm run test:coverage` gegen die Schwellen in `vitest.config.ts` | 15 min | 1,2 min |
| `Docker build and start` | `docker build`, Inhaltsprüfung des Images, **Start im Produktionsmodus** mit `NODE_ENV=production`, Abfrage von `/live` und `/health`, Nicht-Root-Nachweis, Aufräumen per `if: always()` | 20 min | 0,8 min |
| `Release dry run` | packt alle drei SDKs, prüft die Archive, erzeugt CycloneDX-SBOMs; **ohne** Veröffentlichung | 20 min | 1,6 min |

Die beiden Python-Jobs entstehen aus einer Matrix über die Versionen, sind in der
Statusanzeige aber zwei Einträge. Die Zählung **13** ist die Zahl der
Jobdefinitionen in der Datei und zugleich die Zahl der Statuszeilen eines
Laufs.

**Jeder Job hat mindestens vierfachen Spielraum.** Der engste ist
`Flake watch` mit 2,6 von 12 Minuten.

**Auf `main` wird nicht abgebrochen.** `cancel-in-progress` ist
`${{ github.ref != 'refs/heads/main' }}`: auf einem Branch bricht ein neuer Push
den laufenden Lauf ab, auf `main` läuft er zu Ende. Grund: der Lauf auf `main`
**ist** der Nachweis, ein abgebrochener Push hinterließe eine unvollständige
Prüfung ohne Ergebnis.

## Warum es einen Flake-Wächter gibt

Ein Test, der nur durch Uhrzeit oder Last kippt, liefert einen roten Lauf, dessen
Ursache niemand zuordnen kann. `src/onboarding/gueltigkeit.test.ts` war genau
das: ungefähr jeder neunte Lauf des vollen Laufs war rot, isoliert war der Test
immer grün. Der Test ist an der Wurzel behoben (ein gemeinsam injiziertes
Gültigkeitsfenster für Issuer und Blatt statt einer pro Zertifikat gelesenen
Uhr), der Wächter verhindert, dass so etwas unbemerkt zurückkommt.

`npm run test:flake` wiederholt die neun zeitabhängigen Testdateien zehnmal.
Ein einzelner roter Durchlauf bricht ab. Die Laufzeit ist über `FLAKE_BUDGET_MS`
im Skript (Vorgabe 8 Minuten) und `timeout-minutes` im Workflow begrenzt, damit
ein hängender Durchlauf die Pipeline nicht aufhält.

Die Wiederholungen laufen als **eigener Prozess pro Durchlauf**, nicht über
`vitest --repeats`. `--repeats` führt sie im selben Prozess aus, dann teilen
sich die HTTP-Tests einen Dienst und nach 60 Anfragen je Minute greift das
Ratenlimit: der Lauf meldet dann 429 statt 201. Das ist keine Flake, sondern
das Ratenlimit, das korrekt arbeitet — `--repeats` erzeugt in dieser
Konstellation also systematisch Fehlschläge. Frischer Zustand je Durchlauf ist
Voraussetzung dafür, dass die Wiederholung überhaupt aussagekräftig ist.

Lokal genauso nutzbar:

```bash
npm run test:flake                      # 10 Wiederholungen
FLAKE_REPEATS=50 npm run test:flake    # für eine längere Untersuchung
FLAKE_BUDGET_MS=60000 npm run test:flake
```

## Python-SDK

`npm`-unabhängig, deshalb ein eigener Job mit `actions/setup-python`. Getestet
wird auf **Python 3.9**, der in `sdk/python/pyproject.toml` deklarierten
Untergrenze (`requires-python = ">=3.9"`); mypy ist auf `python_version 3.9`
konfiguriert.

Ablauf, in dieser Reihenfolge:

```bash
python -m pip install --upgrade pip
pip install ".[dev]"        # mypy und pytest als Extra aus pyproject.toml
python -m mypy              # streng, prüft das Paket über die Konfiguration
python -m pytest -q
```

Zwei Punkte, die ohne den Job stillschweigend falsch liefen:

- **Das Paket wird installiert, nicht über `PYTHONPATH` gefunden.** Es liegt
  unter `sdk/python/src`, die Tests importieren `eudi_verify_sdk` direkt. Ohne
  Installation findet pytest das Paket nicht.
- **`python -m mypy` ohne Argument.** Die Konfiguration in `pyproject.toml`
  nennt das Paket, also ist ein Pfargument nicht nötig — und ein Pfargument
  würde die Konfiguration umgehen. Genau das war vorher der Fall: `mypy src`
  meldete "Success", während `mypy` allein mit `Can't find package
  'attack_sdk'` abbrach, weil dort noch der alte Paketname stand. Behoben auf
  `mypy_path = "src"` und `packages = ["eudi_verify_sdk"]`, und mit einem
  eingebauten Typfehler gegengeprüft, dass die Prüfung nicht vakuum grün ist.

Eine zweite Python-Version wäre aussagekräftiger, war hier aber nicht belegbar:
es gibt lokal kein 3.12 und kein startbares Docker. Eine Matrix mit einer zweiten Python-Version ist eine Zeile in
`.github/workflows/ci.yml`, sobald sie nachgewiesen werden kann.

`pip install` erzeugt `sdk/python/build/` und `src/*.egg-info/`; beides ist in
`.gitignore` ausgenommen, damit nach jedem lokalen Lauf nichts Ungetracktes
zurückbleibt.

## Kotlin-SDK

Eigener Job mit `actions/setup-java` (Java 21, Temurin) und
`gradle/actions/setup-gradle` für den Gradle-Cache. Java 21 ist keine freie
Wahl: `sdk/kotlin/build.gradle.kts` legt die Toolchain auf
`JavaLanguageVersion.of(21)` fest, und `allWarningsAsErrors` ist aktiviert.

`gradle test` läuft über JUnit Platform und zieht **beide** Testquellen:
`AttackClientTest.kt` (Kotlin) und `JavaInteropTest.java` (Java). Der
Java-Interop-Test ist der Grund für den Job — er prüft die
Java-Sichtbarkeit der Kotlin-API (`@JvmOverloads`, statische JSON-Fassade,
`@JvmStatic`-Fabrik) und fällt außerhalb dieses Jobs durch, weil keine
andere Stelle ihn ausführt.

Damit eine leere Testauswahl nicht als Erfolg durchgeht, prüft ein
zusätzlicher Schritt die Ergebnisdateien: `JavaInteropTest.xml` muss
existieren, mehr als 0 Tests melden, und es müssen insgesamt mehr Tests sein
als in dieser einen Datei. Ohne diesen Schritt würde ein Job grün, der nur
die Kotlin-Tests gelaufen ist.

Belegt: mit einem absichtlich falschen Erwartungswert in
`JavaInteropTest` meldet `gradle test` `Task :test FAILED` und Endet mit Exit
1. Fehler danach wieder entfernt.

## SDK-Drift

`sdk/typescript/src/generated.ts` wird aus `openapi.yaml` im Repo-Root erzeugt.
`npm run generate:check` erzeugt die Datei frisch und vergleicht byteweise; eine
Änderung der Spec ohne passende Neuerzeugung lässt den Job `sdk` rot werden.
Handgeschriebene Client-Methoden deckt das nicht ab, dafür haben die Clients
eigene Tests.

## Docker-Build in der CI

`docker-build` baut das Image und prüft drei Dinge:

- **Keine Testdateien im Image.** Ein `*.test.ts` unter `/app/src` bedeutet, dass
  die feste Liste der Laufzeitdateien im Dockerfile veraltet und wieder zu grob
  geworden ist.
- **Kein Schlüsselmaterial und keine `.env`** im Image. Beides kommt zur
  Laufzeit über Bind-Mount oder Docker-Secrets.
- **Der Einstiegspunkt existiert.** Fehlt eine der transitiv erreichten
  Laufzeitdateien, bricht der Dienststart mit `Cannot find module` ab.

Der Job **pusht nicht** und braucht **keine Secrets**. Dass das Image mit
`NODE_ENV=production` und echtem Material startet, ist in
[interne Notiz, nicht veröffentlicht] Abschnitt 5.1 belegt; das lässt sich nicht in einer
PR ohne Geheimnisse nachstellen.

Vor `docker build` zieht der Job das Basisimage einmal explizit, damit die im
Dockerfile gepinnte Layer-Digest nicht bei jedem Schritt neu aufgelöst wird.
