/**
 * Audit-Log ohne personenbezogene Daten (Prototyp). Es werden nur Ereignisse
 * mit Zeitstempel, Mandanten-ID und kurzem Ereignisnamen festgehalten; keine
 * Wallet-Daten, keine Claim-Werte, keine Zugangsdaten. In-Memory wie der übrige
 * Prototyp.
 *
 * Zusaetzlich hash-verkettet: jeder Eintrag traegt `hash`, gebildet aus dem
 * Hash des Vorgaengers und dem Inhalt dieses Eintrags. Damit laesst sich im
 * Nachhinein erkennen, ob ein Eintrag geaendert, geloescht oder vertauscht
 * wurde. `verifyChain` meldet den Index der ersten Abweichung.
 *
 * Was das ausdruecklich NICHT ist: Beweislast vor Dritten. Wer den Prozess
 * kontrolliert, kann die ganze Kette neu berechnen. Eine aeussere Verankerung,
 * etwa eine Signatur, einen Dienstzeitstempel oder externen Speicher, fehlt.
 * Siehe docs/bedrohungsmodell.md S15.
 */
import { createHash, randomBytes } from 'node:crypto';

export type AuditEvent =
  | 'request_created'
  | 'request_rejected'
  | 'request_object_read'
  | 'presentation_valid'
  | 'presentation_invalid'
  | 'presentation_rejected'
  | 'result_read'
  | 'result_expired'
  | 'session_expired'
  | 'session_deleted'
  /**
   * Eine veraltete `good`-OCSP-Antwort wurde aus der Gnadenfrist verwendet
   * (Option B aus [interne Notiz, nicht veröffentlicht]). Der `detail` nennt nur
   * Alter und Frist der verwendeten Antwort, keine Zertifikatsdaten.
   */
  | 'issuer_revocation_grace_period';

export interface AuditEntry {
  at: string;
  tenant: string;
  event: AuditEvent;
  detail?: string;
  /**
   * SHA-256 ueber `hash` des Vorgaengers und den Inhalt dieses Eintrags ohne
   * `hash`. Der erste Eintrag bindet statt des Vorgängers den Startwert aus
   * GENESIS. Optional, damit ein von Hand gebauter Eintrag ohne Kette pruefbar
   * bleibt und die Altdaten in Tests nicht brechen.
   */
  hash?: string;
}

/** Startwert der Kette. Zufaellig, damit ein vorab geratener Hash nichts nutzt. */
const GENESIS = randomBytes(32).toString('hex');

/**
 * Kanonische Darstellung des Inhalts eines Eintrags. Die Felder werden in
 * fester Reihenfolge und mit Trennzeichen geschrieben, die nicht in den Werten
 * vorkommen koennen, damit keine Kollision durch Umstellen entsteht.
 */
function inhaltFuerHash(eintrag: AuditEntry): string {
  return JSON.stringify([eintrag.at, eintrag.tenant, eintrag.event, eintrag.detail ?? null]);
}

/** Berechnet den Hash eines Eintrags aus dem Hash des Vorgaengers. */
export function hashEintrag(vorgaenger: string, eintrag: AuditEntry): string {
  return createHash('sha256')
    .update(vorgaenger, 'utf8')
    .update('\u0000', 'utf8')
    .update(inhaltFuerHash(eintrag), 'utf8')
    .digest('hex');
}

/** Ergebnis von verifyChain. `index` ist der Index der ersten Abweichung. */
export interface ChainPruefung {
  gueltig: boolean;
  /** Index der ersten Abweichung, -1 wenn die Kette gueltig ist. */
  index: number;
  /** Anzahl der geprueften Eintraege. */
  geprueft: number;
  /** Anzahl der Eintraege ohne Hash-Feld, diese gelten als ungekettet. */
  ungekettet: number;
  grund?: 'abweichung' | 'verkettung-unvollstaendig';
}

/**
 * Prueft die Kette und meldet die erste Abweichung mit Index.
 *
 * Drei Angriffe fuehren alle zum selben Befund, der Index ist jeweils der
 * betroffene Eintrag:
 *  - veraendert: der Inhalt eines Eintrags weicht vom Hash ab
 *  - geloescht: ein Eintrag in der Mitte fehlt, der Nachfolger passt nicht mehr
 *  - vertauscht: zwei Eintraege stehen in falscher Reihenfolge
 *
 * Die Art der Abweichung wird bewusst NICHT unterschieden. Sie ist aus den
 * Daten nicht entscheidbar, alle drei erzeugen dasselbe Muster. Siehe den
 * Kommentar in der Schleife.
 *
 * Ohne Hash-Feld gilt der Eintrag als ungekettet und wird uebersprungen, das
 * haelt Altdaten und von Hand gebaute Eintraege pruefbar.
 */
export function verifyChain(entries: readonly AuditEntry[]): ChainPruefung {
  let erwartet = GENESIS;
  let ersterFehler = -1;
  let grund: ChainPruefung['grund'];
  let ungekettet = 0;

  entries.forEach((eintrag, index) => {
    if (typeof eintrag.hash !== 'string') {
      ungekettet += 1;
      return;
    }
    if (ersterFehler >= 0) return;
    const berechnet = hashEintrag(erwartet, eintrag);
    if (berechnet === eintrag.hash) {
      erwartet = eintrag.hash;
      return;
    }
    ersterFehler = index;
    // Bewusst KEINE Unterscheidung nach der Art der Abweichung. Der Pruefer
    // sieht nur den Eintrag (Inhalt und Hash) und den erwarteten Vorgaengerhash.
    // Ein geaenderter Inhalt, ein geloeschter Eintrag und zwei vertauschte
    // Eintraege erzeugen dasselbe Muster: hashEintrag(erwartet, eintrag)
    // passt nicht zu eintrag.hash. Ohne eine aeussere Referenz, etwa eine
    // Signatur oder einen externen Zeitstempel, ist nicht entscheidbar, was
    // passiert ist. Erhebbar ist ausschliesslich: die Kette ist ab hier
    // unterbrochen. Wer den Grund wissen will, muss den Eintrag gegen eine
    // unabhaengige Quelle halten.
    grund = 'abweichung';
  });

  if (ersterFehler < 0 && ungekettet > 0) {
    return { gueltig: false, index: -1, geprueft: entries.length, ungekettet, grund: 'verkettung-unvollstaendig' };
  }
  if (ersterFehler < 0) {
    return { gueltig: true, index: -1, geprueft: entries.length, ungekettet };
  }
  return { gueltig: false, index: ersterFehler, geprueft: entries.length, ungekettet, grund };
}

export class AuditLog {
  private readonly entries: AuditEntry[] = [];
  /** Letzter Hash der Kette, beim Start der Startwert. */
  private letzterHash: string = GENESIS;

  record(tenant: string, event: AuditEvent, detail?: string): void {
    const eintrag: AuditEntry = { at: new Date().toISOString(), tenant, event, detail };
    eintrag.hash = hashEintrag(this.letzterHash, eintrag);
    this.letzterHash = eintrag.hash;
    this.entries.push(eintrag);
  }

  list(): readonly AuditEntry[] {
    return [...this.entries];
  }

  /**
   * Prueft die Verkettung der aktuellen Eintraege. Praktisch fuer einen Test
   * und fuer einen Abruf, nicht fuer einen laufenden Betrieb.
   */
  verify(): ChainPruefung {
    return verifyChain(this.entries);
  }

  clear(): void {
    this.entries.length = 0;
    this.letzterHash = GENESIS;
  }
}
