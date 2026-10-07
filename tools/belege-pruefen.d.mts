/**
 * Typen fuer tools/belege-pruefen.mjs.
 *
 * Das Skript ist JavaScript, damit es ohne Build-Schritt von der Kommandozeile
 * laeuft. Damit TypeScript es trotzdem sauber typisieren kann, liegen die
 * Formen hier.
 */

export interface Beleg {
  /** Datei relativ zur Repositorywurzel, mit Endung. */
  datei: string;
  /** Erste Zeile des Belegs, eins gezaehlt. */
  von: number;
  /** Letzte Zeile des Belegs, eins gezaehlt. Bei Einzelzeile gleich `von`. */
  bis: number;
}

/** Holt alle Belege der Form `datei.ts:12` oder `datei.ts:12-20` aus einem Text. */
export function belege(text: string): Beleg[];

/**
 * Prueft einen Beleg. Gibt null zurueck, wenn er stimmt, sonst eine Meldung,
 * die den Fehler benennt.
 */
export function pruefeBeleg(beleg: Beleg): string | null;
