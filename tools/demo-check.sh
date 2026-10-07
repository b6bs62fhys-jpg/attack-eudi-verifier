#!/bin/sh
# demo-check.sh: prüft, ob die Schritte aus [interne Notiz, nicht veröffentlicht] noch so laufen
# wie dort beschrieben.
#
# Ohne Docker, ohne Colima. Startet den Dienst lokal im Entwicklungsbetrieb auf
# einem freien Port, fährt die Schritte durch und vergleicht die Ergebnisse mit
# den Kernwerten aus dem Dokument.
#
# Aufruf:  sh tools/demo-check.sh
# Ergebnis: OK <anzahl> Prüfungen, oder FEHLER mit Grund und Exit 1.
#
# macOS-tauglich: kein grep -P, kein GNU-sed, /bin/sh, kein bash.

set -u

WURZEL=$(cd "$(dirname "$0")/.." && pwd)
cd "$WURZEL" || exit 2

PORT=${DEMO_CHECK_PORT:-18099}
BASIS="http://127.0.0.1:$PORT"
KEY='authorization: Bearer test-api-key-tenant-A'

ANZAHL=0
FEHLER=0
DIENST_PID=""

# --- Hilfsmittel -------------------------------------------------------------

# Warten bis die Route antwortet, damit der Start nicht racebedingt fluktuiert.
warte_auf_dienst() {
  i=0
  while [ "$i" -lt 60 ]; do
    if curl -s -o /dev/null "$BASIS/live" 2>/dev/null; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

dienst_stoppen() {
  if [ -n "$DIENST_PID" ]; then
    kill "$DIENST_PID" 2>/dev/null
    wait "$DIENST_PID" 2>/dev/null
    DIENST_PID=""
  fi
}
trap dienst_stoppen EXIT INT TERM

# prüfe <Bezeichnung> <erwartet> <tatsächlich>
# Leerer Erwartungswert heißt: nur prüfen, dass etwas da ist.
pruefe() {
  ANZAHL=$((ANZAHL + 1))
  if [ "$2" = "$3" ]; then
    printf '  OK    %s\n' "$1"
  else
    printf '  FEHLER %s\n         erwartet: %s\n         bekommen: %s\n' "$1" "$2" "$3"
    FEHLER=$((FEHLER + 1))
  fi
}

# --- Schritt 1 und 2: Diagnose-CLI, braucht keinen Dienst --------------------

AUSGABE_CLI=$(npm run --silent cli 2>&1)
EXIT_CLI=$?
pruefe 'Schritt 1  Diagnose-CLI zeigt alle Befehle' 1 \
  "$(printf '%s' "$AUSGABE_CLI" | grep -c 'doctor      alle Prüfungen nacheinander')"
pruefe 'Schritt 1  Diagnose-CLI endet mit Rückgabewert-Hinweis' 1 \
  "$(printf '%s' "$AUSGABE_CLI" | grep -c 'Es gibt bewusst keinen Schreibbefehl')"

AUSGABE_STATUS=$(npm run --silent cli -- status 2>&1)
pruefe 'Schritt 2  Status nennt den Onboarding-Zustand' 1 \
  "$(printf '%s' "$AUSGABE_STATUS" | grep -c 'Onboarding-Gate: NICHT aktiv')"
pruefe 'Schritt 2  Status nennt die Laufzeit' 1 \
  "$(printf '%s' "$AUSGABE_STATUS" | grep -c 'Ergebnis-TTL')"
pruefe 'Schritt 2  Status listet die Routen' 1 \
  "$(printf '%s' "$AUSGABE_STATUS" | grep -c 'GET    /live')"
# Der Dienst meldet beim Start eine andere Routenzahl als die ROUTES-Liste
# enthaelt. Siehe Befund in [interner Bericht, nicht veröffentlicht] Hier wird der
# dokumentierte Wert geprueft, der ist derzeit 9.
ROUTEN_STATUS=$(printf '%s' "$AUSGABE_STATUS" | grep -cE '^\s+(GET|POST|DELETE)\s+/')
pruefe 'Schritt 2  Status listet neun Routen' 9 "$ROUTEN_STATUS"

# --- Schritt 3: Dienst starten ----------------------------------------------

NODE_ENV=development ATTACK_DEV_MODE=true ATTACK_ALLOW_SELF_SIGNED=true \
  PORT="$PORT" node --experimental-strip-types src/service/run.ts >/tmp/demo-check-svc.log 2>&1 &
DIENST_PID=$!

if ! warte_auf_dienst; then
  printf '  FEHLER Schritt 3  Dienst antwortet auf /live nicht\n'
  printf '         Log: /tmp/demo-check-svc.log\n'
  exit 1
fi

LOG=$(cat /tmp/demo-check-svc.log)
pruefe 'Schritt 3  Start warnt vor ATTACK_DEV_MODE' 1 \
  "$(printf '%s' "$LOG" | grep -c 'WARNUNG: ATTACK_DEV_MODE=true ist AKTIV')"
pruefe 'Schritt 3  Start warnt vor ATTACK_ALLOW_SELF_SIGNED' 1 \
  "$(printf '%s' "$LOG" | grep -c 'WARNUNG: ATTACK_ALLOW_SELF_SIGNED=true ist AKTIV')"
pruefe 'Schritt 3  Start meldet den laufenden Dienst' 1 \
  "$(printf '%s' "$LOG" | grep -c 'service_started')"
# Die Zahl der Warnzeilen ist in [interne Notiz, nicht veröffentlicht] nicht festgeschrieben,
# sie wuchs von 6 auf 14. Geprueft wird, dass überhaupt gewarnt wird.
pruefe 'Schritt 3  Start warnt mehrfach, nicht nur einmal' 1 \
  "$([ "$(printf '%s' "$LOG" | grep -c bootstrap_warning)" -gt 1 ] && echo 1 || echo 0)"

# --- Schritt 4: Betriebsrouten ---------------------------------------------

LIVE_CODE=$(curl -s -o /tmp/demo-check-live.txt -w '%{http_code}' "$BASIS/live")
READY_CODE=$(curl -s -o /tmp/demo-check-ready.txt -w '%{http_code}' "$BASIS/ready")
LIVE_BODY=$(cat /tmp/demo-check-live.txt)
READY_BODY=$(cat /tmp/demo-check-ready.txt)

pruefe 'Schritt 4  /live antwortet 200' 200 "$LIVE_CODE"
pruefe 'Schritt 4  /live meldet live' 1 \
  "$(printf '%s' "$LIVE_BODY" | grep -c '"status":"live"')"
pruefe 'Schritt 4  /ready antwortet 200' 200 "$READY_CODE"
pruefe 'Schritt 4  /ready nennt die Einzelpruefungen' 1 \
  "$(printf '%s' "$READY_BODY" | grep -c '"issuer_trust":"ok"')"

# --- Schritt 5: Pruefanfrage ------------------------------------------------

curl -s -X POST "$BASIS/v1/verification-requests" \
  -H 'content-type: application/json' -H "$KEY" -d '{}' \
  -o /tmp/demo-check-req.json -w '%{http_code}' >/tmp/demo-check-req.code
REQ_CODE=$(cat /tmp/demo-check-req.code)
pruefe 'Schritt 5  Anfrage wird mit 201 angelegt' 201 "$REQ_CODE"

SESSION=$(node -e '
const fs = require("fs");
const d = JSON.parse(fs.readFileSync("/tmp/demo-check-req.json", "utf8"));
process.stdout.write(String(d.sessionId || ""));
' 2>/dev/null)

FELDER=$(node -e '
const fs = require("fs");
const d = JSON.parse(fs.readFileSync("/tmp/demo-check-req.json", "utf8"));
const pflicht = ["sessionId", "state", "expiresAt", "requestObject", "responseUri", "requestObjectUri"];
process.stdout.write(pflicht.filter((k) => k in d).length + ":" + Object.keys(d).length);
' 2>/dev/null)

pruefe 'Schritt 5  Antwort enthaelt die sechs dokumentierten Felder' 6 "${FELDER%%:*}"
pruefe 'Schritt 5  Antwort enthaelt genau diese sechs Felder' 6 "${FELDER##*:}"
pruefe 'Schritt 5  sessionId ist nicht leer' 1 \
  "$([ -n "$SESSION" ] && echo 1 || echo 0)"

# Schritt 5, dokumentierter Fehlerfall: x-api-key statt authorization
curl -s -X POST "$BASIS/v1/verification-requests" \
  -H 'content-type: application/json' \
  -H 'x-api-key: test-api-key-tenant-A' -d '{}' \
  -o /tmp/demo-check-unauth.json -w '%{http_code}' >/tmp/demo-check-unauth.code
pruefe 'Schritt 5  x-api-key wird mit 401 abgewiesen' 401 "$(cat /tmp/demo-check-unauth.code)"

# --- Schritt 6: signiertes Anfrageobjekt ------------------------------------

RO=$(curl -s -o /tmp/demo-check-ro.txt -w '%{http_code}' \
  "$BASIS/v1/verification-requests/$SESSION/request-object" -H "$KEY")
pruefe 'Schritt 6  Anfrageobjekt wird mit 200 geliefert' 200 "$RO"
# Ein JWT hat drei durch Punkt getrennte Teile.
RO_TEILE=$(awk -F. '{print NF}' /tmp/demo-check-ro.txt)
pruefe 'Schritt 6  Anfrageobjekt hat drei JWT-Teile' 3 "$RO_TEILE"

# --- Schritt 7: Nachweis einreichen ----------------------------------------

# Der SD-JWT stammt aus dem Mock-Wallet des Repositorys, es ist kein Material
# aus einer echten Wallet. Siehe Abschnitt 5 von [interne Notiz, nicht veröffentlicht].
node --experimental-strip-types tools/demo-check-sdjwt.mjs >/tmp/demo-check-sdjwt.out 2>/tmp/demo-check-sdjwt.log
SDJWT=$(cat /tmp/demo-check-sdjwt.out 2>/dev/null)
pruefe 'Schritt 7  Testnachweis laesst sich erzeugen' 1 \
  "$([ -n "$SDJWT" ] && echo 1 || echo 0)"

curl -s -X POST "$BASIS/direct_post" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "vp_token=$SDJWT" --data-urlencode "state=$SESSION" \
  -o /tmp/demo-check-dp.txt -w '%{http_code}' >/tmp/demo-check-dp.code
DP_CODE=$(cat /tmp/demo-check-dp.code)
DP_BODY=$(cat /tmp/demo-check-dp.txt)

pruefe 'Schritt 7  Ablehnung kommt mit 200 und nicht mit 422' 200 "$DP_CODE"
pruefe 'Schritt 7  Antwort meldet valid:false' 1 \
  "$(printf '%s' "$DP_BODY" | grep -c '"valid":false')"
pruefe 'Schritt 7  Antwort nennt den Ablehnungsgrund' 1 \
  "$(printf '%s' "$DP_BODY" | grep -c 'issuer_trust_anchor_not_found')"
# Datenminimierung: es darf nur das Angeforderte im Ergebnis stehen. Bei dieser
# Anfrage wurde kein Claim angefordert, also darf keiner zurueckkommen.
pruefe 'Schritt 7  Antwort enthaelt keine unangeforderten Angaben' 0 \
  "$(printf '%s' "$DP_BODY" | grep -c 'given_name')"

# Schritt 7, dokumentierter Fehlerfall: response statt vp_token
curl -s -X POST "$BASIS/direct_post" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "response=$SDJWT" --data-urlencode "state=$SESSION" \
  -o /tmp/demo-check-dp-bad.txt -w '%{http_code}' >/tmp/demo-check-dp-bad.code
pruefe 'Schritt 7  response statt vp_token wird mit 422 abgewiesen' 422 \
  "$(cat /tmp/demo-check-dp-bad.code)"

# --- Schritt 8: beenden -----------------------------------------------------

# Kein eigener Prozess zu beenden, der Dienst laeuft im Skript. Geprueft wird,
# dass der PID gesetzt ist, damit der trap zuverlaessig greift.
pruefe 'Schritt 8  Dienstprozess ist fuer das Beenden erfasst' 1 \
  "$([ -n "$DIENST_PID" ] && echo 1 || echo 0)"
dienst_stoppen
pruefe 'Schritt 8  nach dem Beenden antwortet /live nicht mehr' 1 \
  "$(curl -s -o /dev/null -m 2 "$BASIS/live" 2>/dev/null || echo 1)"

# --- Ergebnis ---------------------------------------------------------------

rm -f /tmp/demo-check-*.txt /tmp/demo-check-*.json /tmp/demo-check-*.code \
  /tmp/demo-check-*.log /tmp/demo-check-*.out

echo
if [ "$FEHLER" -eq 0 ]; then
  echo "OK $ANZAHL Prüfungen"
  exit 0
fi

echo "FEHLER $FEHLER von $ANZAHL Prüfungen"
exit 1
