# Lizenzinventar der Abhaengigkeiten

Alle direkten und transitiven Produktionsabhaengigkeiten des Dienstes und der
SDKs, mit Name, Version und der jeweils deklarierten Lizenz.

**Das sind Metadaten, keine Rechtsprüfung.** Eine Lizenzangabe in einer
`package.json` sagt, was die Herausgeber deklariert haben. Sie sagt nicht, ob
die Nutzung im eigenen Fall zulässig ist. Das ist eine Frage fuer eine
Rechtsberatung.

Erhoben am 30.09.2026 auf `main` commit `88f9cb8`. Grundlage waren die lokal
installierten Pakete und `package-lock.json`. Es wurde **kein** Werkzeug
installiert und keine Abhaengigkeit ergaenzt.

**Produktname: `Attack`.** Arbeitsname, siehe [interne Notiz, nicht veröffentlicht].

## Kurzfassung

| | |
|---|---|
| Pakete im Produktionsbaum | 49 |
| Lizenz Apache-2.0 | 8 |
| Lizenz MIT | 35 |
| Lizenz BSD-3-Clause | 4 |
| Lizenz 0BSD | 1 |
| Lizenz ISC | 1 |
| **ohne Lizenzangabe** | **0** |
| **Copyleft (GPL, AGPL, LGPL, MPL, EPL)** | **0** |

**Kein Paket im ausgelieferten Baum steht unter einer Copyleft-Lizenz.**

Zwei Abhaengigkeiten sind als optionale Peer-Abhaengigkeit deklariert und
nicht im Produktionsbetrieb installiert: `qrcode` und sechs plattformspezifische
Pakete `@cbor-extract/*`. Sie sind hier aufgeführt, weil sie in der
Auflösungstabelle auftauchen, aber sie werden zur Laufzeit nicht geladen.

## Produktionsabhaengigkeiten des Dienstes

Direkt deklariert in `package.json`, vier Pakete:

| Paket | Version | Lizenz |
|---|---|---|
| `@openeudi/core` | 0.8.0 | Apache-2.0 |
| `@openeudi/dcql` | 0.2.0 | Apache-2.0 |
| `@openeudi/openid4vp` | 0.11.1 | Apache-2.0 |
| `@peculiar/asn1-ocsp` | 2.9.5 | MIT |

Die ersten drei sind die eigentliche Protokollbibliothek, die vierte pruft den
Sperrstatus.

## Vollstaendige Liste des Produktionsbaums

Aufgeloest mit `npm ls --all --omit=dev`, Lizenz aus `package.json` des
installierten Paketes, ergaenzt aus `package-lock.json` wo `npm ls` keine
Angabe lieferte.

| Paket | Version | Deklarierte Lizenz |
|---|---|---|
| `@cbor-extract/cbor-extract-darwin-arm64` | 2.2.2 | MIT |
| `@cbor-extract/cbor-extract-darwin-x64` | 2.2.2 | MIT |
| `@cbor-extract/cbor-extract-linux-arm` | 2.2.2 | MIT |
| `@cbor-extract/cbor-extract-linux-arm64` | 2.2.2 | MIT |
| `@cbor-extract/cbor-extract-linux-x64` | 2.2.2 | MIT |
| `@cbor-extract/cbor-extract-win32-x64` | 2.2.2 | MIT |
| `@noble/hashes` | 1.8.0 | MIT |
| `@openeudi/core` | 0.8.0 | Apache-2.0 |
| `@openeudi/dcql` | 0.2.0 | Apache-2.0 |
| `@openeudi/openid4vp` | 0.11.1 | Apache-2.0 |
| `@peculiar/asn1-asym-key` | 2.9.5 | MIT |
| `@peculiar/asn1-cms` | 2.9.5 | MIT |
| `@peculiar/asn1-csr` | 2.9.5 | MIT |
| `@peculiar/asn1-ecc` | 2.9.5 | MIT |
| `@peculiar/asn1-ocsp` | 2.9.5 | MIT |
| `@peculiar/asn1-pfx` | 2.9.5 | MIT |
| `@peculiar/asn1-pkcs8` | 2.9.5 | MIT |
| `@peculiar/asn1-pkcs9` | 2.9.5 | MIT |
| `@peculiar/asn1-rsa` | 2.9.5 | MIT |
| `@peculiar/asn1-schema` | 2.9.5 | MIT |
| `@peculiar/asn1-x509` | 2.9.5 | MIT |
| `@peculiar/asn1-x509-attr` | 2.9.5 | MIT |
| `@peculiar/asn1-x509-post-quantum` | 2.9.5 | MIT |
| `@peculiar/utils` | 2.0.3 | MIT |
| `@peculiar/x509` | 2.1.0 | MIT |
| `@sd-jwt/decode` | 0.19.0 | Apache-2.0 |
| `@sd-jwt/types` | 0.19.0 | Apache-2.0 |
| `@sd-jwt/utils` | 0.19.0 | Apache-2.0 |
| `@xmldom/xmldom` | 0.9.12 | MIT |
| `asn1js` | 3.0.10 | BSD-3-Clause |
| `bytestreamjs` | 2.0.1 | BSD-3-Clause |
| `cbor-extract` | 2.2.2 | MIT |
| `cbor-x` | 1.6.6 | MIT |
| `detect-libc` | 2.1.2 | Apache-2.0 |
| `jose` | 6.1.3 | MIT |
| `js-base64` | 3.9.4 | BSD-3-Clause |
| `node-gyp-build-optional-packages` | 5.1.1 | MIT |
| `pkijs` | 3.4.1 | BSD-3-Clause |
| `pvtsutils` | 1.3.6 | MIT |
| `pvutils` | 1.2.0 | MIT |
| `qrcode` | ? | MIT |
| `reflect-metadata` | 0.2.2 | Apache-2.0 |
| `tslib` | 2.8.1 | 0BSD |
| `tsyringe` | 4.10.0 | MIT |
| `uuid` | 11.1.1 | MIT |
| `xadesjs` | 2.6.8 | MIT |
| `xml-core` | 1.2.6 | MIT |
| `xmldsigjs` | 2.8.8 | MIT |
| `xpath` | 0.0.34 | MIT |
## Abhaengigkeiten der SDKs

Getrennt gefuehrt, weil die SDKs nicht Teil des laufenden Dienstes sind, aber
unter demselben Namen und derselben Lizenzangabe veroeffentlicht werden.

### TypeScript SDK

`npm run sdk:check` prueft die Konsistenz. Das SDK hat **keine** eigenen
Laufzeitabhaengigkeiten, `peerDependencies` ist leer in
`sdk/typescript/package.json`.

### Python SDK

`sdk/python/pyproject.toml`, Zeile 13: `dependencies = []`, also keine
Laufzeitabhaengigkeiten. Als Bauanforderung steht dort `requires = ["setuptools>=68"]`,
Zeile 2.

### Kotlin SDK

`sdk/kotlin/build.gradle.kts`, Zeile 19, eine einzige Abhaengigkeit:

| Paket | Version | Lizenz |
|---|---|---|
| `org.jetbrains.kotlinx:kotlinx-serialization-json` | 1.11.0 | Apache-2.0, nach Angabe im Repository des Projekts |

Diese Angabe habe ich **nicht** lokal geprueft, das Gradle-Projekt wurde nicht
gebaut. Sie steht so in der Datei und ist vor einer Veroeffentlichung zu
bestaetigen.

## Ohne Lizenzangabe

Keines. Alle 49 Pakete im Produktionsbaum tragen eine Lizenzangabe in ihrer
`package.json` oder im Lockfile.

Anmerkung zu `qrcode`: Das Paket ist nicht installiert und hat keinen Eintrag im
Lockfile. Es ist eine optionale Peer-Abhaengigkeit von `@openeudi/core`
(`node_modules/@openeudi/core/package.json`). Es erscheint in der
Aufloesungsdarstellung, wird aber zur Laufzeit nicht geladen. Eine
Rechtsberatung sollte trotzdem klaeren, ob es in einer spaeteren Installation
mitkommt.

## Nicht im ausgelieferten Baum, aber im Lockfile

12 Pakete unter MPL-2.0, alle von `lightningcss` und damit einer Werkzeugkette
fuer die Website. Sie sind **Entwicklungsabhaengigkeiten** und werden nicht
mitgeliefert. Aufgefuehrt, damit niemand beim Lesen des Lockfiles ueberrascht
wird, mit Ausnahme von `src/site-headers.test.ts` im Testbetrieb, nicht im
Produktivbetrieb.

## Nicht behandelt

- **Lizenztexte im Repository.** Es gibt keine Datei `LICENSE`, `LICENSE.md`,
  `LICENSE.txt` oder `COPYING`.
- **Doppelvergabe.** Ob eine Bibliothek unter mehreren Lizenznamen laeuft, wurde
  nicht geprueft, weil dafuer der Lizenztext gelesen werden muesste.
- **Verlinkung.** Ob Code aus Copyleft-Projekten uebernommen wurde, wurde nicht
  geprueft.
