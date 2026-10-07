# Diagnose-CLI

Ein kleines Werkzeug, um den Betriebszustand des Verifier-Dienstes zu prüfen,
ohne ihn zu starten und ohne ihn zu verändern. Dazu kommt ein einziger
Schreibbefehl, `tenant`, für die Mandantendatei (siehe unten).

```bash
npm run cli -- status
```

## Wozu

Wenn eine Mandantenregistrierung nicht durchgeht oder ein Zertifikat im
Verdacht steht, ist die erste Frage immer dieselbe: Was hat der Dienst vor dem
Abbruch eigentlich gesehen? Die Antwort steht bisher im Startprotokoll, und nur
dort. Dieses CLI beantwortet dieselbe Frage ohne Dienst, in einer Ausgabe, die
sich in Skripte einbauen lässt.

Es liest dieselben Umgebungsvariablen und ruft dieselben Funktionen auf wie der
Dienst beim Start. Es prüft nicht nach, was in der Dokumentation steht, sondern
was beim Start tatsächlich herauskäme.

## Befehle

| Befehl | Inhalt |
|---|---|
| `status` | Onboarding-Gate, Aussteller-Anker, Laufzeit, alle Routen mit Zugriffsstufe |
| `anchors` | Zertifikate im Detail: Subject, Aussteller, Seriennummer, Gültigkeit, OCSP-Adresse |
| `ocsp` | Erreichbarkeit und Antwortgültigkeit der OCSP-Responder der konfigurierten Anker |
| `ratelimit` | Wirksame Rate-Limit-Werte und welche Routen betroffen sind |
| `doctor` | Alle Prüfungen nacheinander, am Ende ein Gesamturteil |
| `help` | Übersicht |

Diese Befehle sind lesend. Trust List ändern und Anker pflegen bleiben ein
Betriebsprozess mit eigener Freigabe, keine CLI-Aktion.

## Mandantenpflege: `tenant`

Ohne `ATTACK_DEV_MODE` legt der Dienst keine Test-Mandanten an. Mandanten für
den Produktionsbetrieb stehen in einer Mandantendatei, die der Dienst beim
Start über `ATTACK_TENANTS_FILE` liest. `tenant` ist der einzige Befehl, der
schreibt, und er schreibt nur diese eine Datei.

```bash
export ATTACK_TENANTS_FILE=/etc/attack/tenants.json
npm run cli -- tenant add --id kunde-a --name "Kunde A GmbH" --profile pid_basis
npm run cli -- tenant list
npm run cli -- tenant revoke --id kunde-a
```

| Unterbefehl | Wirkung |
|---|---|
| `add --id --name [--profile] [--ttl] [--file]` | legt einen Mandanten an und zeigt seinen API-Schlüssel **genau einmal** auf stdout |
| `list [--file]` | zeigt Mandanten, Status, Profil und Zeitpunkte, nie Schlüssel oder Hash |
| `revoke --id [--file]` | sperrt einen Mandanten; wiederholbar, die ID wird nie neu vergeben |

Regeln:

* Gespeichert wird nur der SHA-256-Hash des Schlüssels. Wer den Klartext beim
  Anlegen nicht notiert, legt einen neuen Mandanten an und sperrt den alten.
* `tenant` lädt keine Dienstkonfiguration und schaltet nie den
  Entwicklungsschalter ein. Er funktioniert mit `NODE_ENV=production`.
* Die Datei wird atomar mit Rechten `0600` geschrieben. Eine vorhandene, aber
  ungültige Datei wird nie überschrieben; der Befehl bricht mit Code 2 ab.
* Der Dienst liest die Datei nur beim Start. Anlegen und Sperren wirken nach
  einem Neustart. Gesperrte Mandanten bleiben in der Datei und bekommen 401.
* Ist `ATTACK_TENANTS_FILE` gesetzt und die Datei fehlerhaft (unlesbar, kein
  JSON, unbekanntes Feld, doppelte ID oder doppelter Schlüssel, unbekanntes
  Profil), bricht der Dienst den Start ab.

## Rückgabewerte

| Code | Bedeutung |
|---|---|
| 0 | Keine Beanstandung |
| 1 | Beanstandung, im Befehl nachzulesen |
| 2 | Aufruf unbrauchbar, etwa unbekannter Befehl |

Damit lässt sich das CLI in eine Überwachung hängen:

```bash
npm run cli -- doctor > /tmp/attack-doctor.txt 2>&1 || echo "Befund: siehe /tmp/attack-doctor.txt"
```

## Beispiele

### Startzustand prüfen, bevor der Dienst hochfährt

```bash
ATTACK_ISSUER_TRUST_ANCHORS_PEM=/etc/attack/issuer-anchors.pem \
ATTACK_ONBOARDING_ACCESS_CA_PEM=/etc/attack/access-ca.pem \
ATTACK_ONBOARDING_WRPRC_ISSUER_PEM=/etc/attack/wrprc-issuer.pem \
npm run cli -- doctor
```

### Warum nimmt der Dienst diese Präsentation nicht an

```bash
npm run cli -- ocsp
```

Prüft je Vertrauensanker, ob das Zertifikat eine AIA-Erweiterung trägt, ob der
Responder erreichbar ist und welchen Status er meldet. Ein Anker ohne AIA
wird ausdrücklich benannt: An ihm kann der Dienst keine Sperrprüfung
vornehmen, auch wenn alles andere stimmt.

### Zertifikate im Detail

```bash
npm run cli -- anchors
```

Ausgegeben werden Subject, Aussteller, Seriennummer, Gültigkeitszeitraum, der
Zustand zum jetzigen Zeitpunkt und die OCSP-Adresse. Ein abgelaufener Anker
wird als Befund gemeldet, weil der Dienst solche Anker zur Laufzeit verwirft.

## Zwei Fälle, die das CLI unterscheidet

**Onboarding nicht konfiguriert.** Fehlen `ATTACK_ONBOARDING_ACCESS_CA_PEM` und
`ATTACK_ONBOARDING_WRPRC_ISSUER_PEM`, entsteht kein Gate. Im Entwicklungsbetrieb
ist das normal und wird als solches gemeldet. In Produktion meldet `/ready`
dafür `failed`, sodass kein Verkehr ankommt.

**Onboarding konfiguriert, aber unbrauchbar.** Der Dienst wirft den Grund
absichtlich weg, wenn sich das Material nicht laden lässt — fehlende
Konfiguration soll ein normaler Zustand bleiben. Damit ist aus dem
Startprotokoll aber nicht mehr zu erkennen, ob ein Pfad falsch getippt wurde
oder wirklich nichts konfiguriert ist. Das CLI prüft das nach und nennt den
konkreten Grund:

```
  Ursache           ATTACK_ONBOARDING_ACCESS_CA_PEM gesetzt, aber es entsteht
                    kein Gate — Konfigurationsfehler.
                    ATTACK_ONBOARDING_ACCESS_CA_PEM: Datei nicht lesbar (Pfad prüfen).
```

## Grenzen

- Das CLI prüft die Konfiguration, nicht den laufenden Dienst. Es meldet keine
  Prozesszustände, keine offenen Verbindungen und keine Metriken. Dafür gibt es
  `/ready`, `/live` und `/metrics`.
- `ocsp` prüft die Erreichbarkeit und die Gültigkeit der OCSP-Antwort, nicht
  die gesamte Dienstbereitschaft. Ein erfolgreicher Lauf bedeutet nicht, dass
  der Dienst startet.
- `ratelimit` zeigt die Konfiguration, nicht die momentane Belastung. Wie viel
  derzeit verbraucht ist, lässt sich nur am laufenden Dienst ermitteln, und
  dafür gibt es bewusst keine Schnittstelle.
- Geprüft werden Zertifikate, keine geheimen Schlüssel. Es gibt keinen Befehl,
  der einen Schlüssel ausgibt.
