/**
 * Zustandsloser Präfixfilter für Warnungen der Prüfbibliothek.
 *
 * Warum das überhaupt nötig ist: `@openeudi/openid4vp` v0.11.1 meldet den
 * Fehlschlag ihres eigenen OCSP-Versuchs nach `console.warn` und schreibt
 * dabei Zertifikat-Subject, Responder-URL und rohe Fehlermeldung der
 * Bibliothek in den Prozesslog. Betroffen sind im Credential-Pfad die
 * Stellen `dist/index.js:7921` (OCSP) und `:7951` (CRL); die Meldung bei
 * `:7748` enthält zusätzlich die Seriennummer des Aussteller-Zertifikats.
 * Das verletzt die Anforderung, dass keine Anspruchs- oder
 * Zertifikatswerte im Log landen.
 *
 * Die Bibliothek bietet dafür **keinen** Schalter: es gibt weder eine
 * Logger-Option noch eine NODE_ENV-Logik noch einen zweiten
 * Export-Einstiegspunkt (geprüft in `node_modules/@openeudi/openid4vp`:
 * kein Treffer für `logger|silent|debug|onWarn`, null Treffer für
 * `NODE_ENV|import.meta.env`, nur der Export `.`).
 *
 * Der Filter ist deshalb ein bewusster, eng begrenzter Eingriff:
 *   - Es wird ausschließlich `console.warn` umhüllt, nicht `error`, `log`
 *     oder `info`.
 *   - Unterdrückt wird ausschließlich, wenn das **erste** Argument eine
 *     Zeichenkette ist, die mit dem Präfix beginnt. Das entspricht genau
 *     den sechs Stellen der Bibliothek, die alle mit einem einzigen
 *     Template-String schreiben.
 *   - Keine Pufferung, kein Verschlucken anderer Meldungen: alle übrigen
 *     Warnungen gehen unverändert und inklusive aller Argumente weiter. Das
 *     betrifft insbesondere die eigenen Warnungen aus `src/config.ts` und
 *     `src/service/bootstrap.ts`, die im Betrieb ausdrücklich sichtbar sein
 *     müssen.
 *   - Die Rückgabefunktion stellt den Originalzustand wieder her (Tests).
 *
 * Zustand und Selbstheilung (B12): Der Zustand hängt **am Wrapper**, nicht am
 * `console`-Objekt. `install()` prüft deshalb nicht „wurde installiert?",
 * sondern „ist **unser** Filter gerade die aktive Funktion?". Nach einem
 * Absturz zwischen `install()` und `restore()` ist unser Wrapper dann nicht mehr
 * `target.warn`, ein späterer `install()` funktioniert wieder, und `restore()`
 * greift. Mit einer Marke am `console`-Objekt war der Zustand nach einem
 * vergessenen `restore()` eingefroren: jedes weitere `install()` wurde von einem
 * `if`-Zweig abgewiesen und lieferte eine wirkungslose Funktion.
 *
 * Bekannte Grenze, bewusst akzeptiert: Die Umhüllung greift für den
 * gesamten Prozess, also auch für Code, der den Filter nicht kennt. Wird
 * `console.warn` von Fremdcode ersetzt, stellt `restore()` diese Änderung
 * **nicht** zurück (es fasst nur an, was selbst installiert wurde) — der
 * Filter ist dann ebenfalls nicht mehr aktiv. Deshalb wird der Filter genau
 * einmal beim Start des Dienstes installiert (siehe `src/service/run.ts`).
 */

/** Präfix, mit dem alle Warnungen der Prüfbibliothek beginnen. */
export const LIBRARY_WARN_PREFIX = '[openid4vp]';

/** Kennzeichnet den Wrapper dieses Filters. */
const OWN_PATCH = Symbol.for('attack.libraryLogFilterOwns');
/** Merkt sich die Funktion, die der Wrapper ersetzt hat. */
const ORIGINAL_WARN = Symbol.for('attack.libraryLogFilterOriginal');

type PatchedWarn = Console['warn'] & {
  [OWN_PATCH]?: true;
  [ORIGINAL_WARN]?: Console['warn'];
};

/**
 * Installiert den Filter und liefert eine Funktion, die den vorherigen
 * Zustand wiederherstellt.
 *
 * Mehrfaches Installieren ist unschädlich: Solange **unser** Filter die aktive
 * Funktion ist, wird nichts erneut umhüllt, und die Rückgabe ist die
 * tatsächliche Restore-Funktion. Ist er es nicht mehr (etwa weil `restore()`
 * nicht aufgerufen wurde), wird neu installiert.
 */
export function installLibraryLogFilter(target: Console = console): () => void {
  // Zustand am Wrapper prüfen, nicht an einer separaten Marke: das ist
  // selbstheilend (B12).
  if ((target.warn as PatchedWarn)[OWN_PATCH] === true) return restoreFilter(target);

  const original = target.warn;
  const patched = ((...args: unknown[]): void => {
    const first = args[0];
    if (typeof first === 'string' && first.startsWith(LIBRARY_WARN_PREFIX)) return;
    original.apply(target, args);
  }) as PatchedWarn;

  patched[OWN_PATCH] = true;
  patched[ORIGINAL_WARN] = original;
  target.warn = patched;
  return restoreFilter(target);
}

/**
 * Stellt die ersetzte Warnfunktion wieder her. Wirkt nur, wenn der Filter noch
 * die aktive Funktion ist; hat Fremdcode `target.warn` inzwischen ersetzt, wird
 * dessen Änderung nicht angefasst.
 */
function restoreFilter(target: Console): () => void {
  let done = false;
  return () => {
    if (done) return;
    done = true;
    const current = target.warn as PatchedWarn;
    if (current?.[OWN_PATCH] === true) {
      target.warn = current[ORIGINAL_WARN] as Console['warn'];
    }
  };
}
