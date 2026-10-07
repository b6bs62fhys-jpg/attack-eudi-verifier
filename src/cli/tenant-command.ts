/**
 * Unterbefehl `tenant` des CLI: Mandantendatei anlegen, auflisten, sperren.
 *
 * Eigenes Modul, damit der Befehl auch im Prozess getestet werden kann; der
 * Prozesstest in main.test.ts prüft zusätzlich Exit-Code, stdout und stderr.
 * Ausgaben laufen über `io`, damit ein Test sie einsammeln kann.
 */
import { access } from 'node:fs/promises';
import { parseArgs } from 'node:util';

import { REQUEST_PROFILE_TEMPLATES } from '../service/profile.ts';
import {
  addTenantEntry,
  emptyTenantFile,
  ENV_ATTACK_TENANTS_FILE,
  loadTenantFile,
  revokeTenantEntry,
  TENANT_TTL_DEFAULT_SECONDS,
  writeTenantFile,
  type TenantFile,
} from '../service/tenant-file.ts';

const OK = 0;
const UNBRAUCHBAR = 2;

export interface TenantCommandIo {
  out: (text: string) => void;
  err: (text: string) => void;
}

/**
 * Mandantenpflege. Bewusst ohne `basisConfig`: die Diagnosebefehle setzen dort
 * zur Toleranz ATTACK_DEV_MODE als Standard, das darf hier nicht greifen.
 */
export async function runTenantCommand(argv: string[], env: Record<string, string | undefined>, io: TenantCommandIo): Promise<number> {
  const { out, err: fehler } = io;
  const unter = argv[0];
  if (unter !== 'add' && unter !== 'list' && unter !== 'revoke') {
    fehler('tenant: Unterbefehl add, list oder revoke angeben. Siehe "npm run cli -- help".');
    return UNBRAUCHBAR;
  }
  let werte: { id?: string; name?: string; profile?: string; ttl?: string; file?: string };
  try {
    ({ values: werte } = parseArgs({
      args: argv.slice(1),
      options: {
        id: { type: 'string' },
        name: { type: 'string' },
        profile: { type: 'string' },
        ttl: { type: 'string' },
        file: { type: 'string' },
      },
      strict: true,
      allowPositionals: false,
    }));
  } catch (e) {
    fehler(`tenant: ${(e as Error).message}`);
    return UNBRAUCHBAR;
  }
  const pfad = werte.file ?? env[ENV_ATTACK_TENANTS_FILE];
  if (!pfad) {
    fehler(`tenant: keine Mandantendatei angegeben. --file <pfad> oder ${ENV_ATTACK_TENANTS_FILE} setzen.`);
    return UNBRAUCHBAR;
  }

  let vorhanden = true;
  try {
    await access(pfad);
  } catch {
    vorhanden = false;
  }
  // Eine vorhandene, aber kaputte Datei wird nie überschrieben: erst reparieren,
  // dann ändern. Sonst gingen Mandanten verloren, die nur der Prüfer nicht
  // lesen konnte.
  let datei: TenantFile;
  try {
    datei = vorhanden ? await loadTenantFile(pfad, pfad) : emptyTenantFile();
  } catch (e) {
    fehler(`tenant: ${(e as Error).message}`);
    return UNBRAUCHBAR;
  }

  switch (unter) {
    case 'add': {
      if (!werte.id || !werte.name) {
        fehler('tenant add: --id und --name sind Pflicht.');
        return UNBRAUCHBAR;
      }
      const profil = werte.profile ?? 'pid_basis';
      if (!REQUEST_PROFILE_TEMPLATES[profil]) {
        fehler(`tenant add: unbekannte Profilvorlage "${profil}". Bekannt: ${Object.keys(REQUEST_PROFILE_TEMPLATES).join(', ')}.`);
        return UNBRAUCHBAR;
      }
      const ttl = werte.ttl === undefined ? TENANT_TTL_DEFAULT_SECONDS : Number(werte.ttl);
      let ergebnis: { file: TenantFile; apiKey: string };
      try {
        ergebnis = addTenantEntry(datei, { id: werte.id, name: werte.name, requestProfile: profil, requestTtlSeconds: ttl });
        await writeTenantFile(pfad, ergebnis.file);
      } catch (e) {
        fehler(`tenant add: ${(e as Error).message}`);
        return UNBRAUCHBAR;
      }
      out(`Mandant angelegt: ${werte.id} (${werte.name}), Profil ${profil}, Sitzungsdauer ${ttl} s`);
      out(`Datei: ${pfad}`);
      out('');
      out('API-Schlüssel. Er wird nur dieses eine Mal angezeigt und nirgends gespeichert:');
      out(ergebnis.apiKey);
      out('');
      out('Gespeichert ist nur der SHA-256-Hash. Der Dienst liest die Datei beim Start; zum Wirksamwerden neu starten.');
      return OK;
    }
    case 'list': {
      out('');
      out(`Mandanten in ${pfad}`);
      out('='.repeat(`Mandanten in ${pfad}`.length));
      if (!vorhanden) {
        out('  Datei existiert noch nicht. Mit "tenant add" anlegen.');
        return OK;
      }
      if (datei.tenants.length === 0) out('  keine Einträge');
      for (const t of datei.tenants) {
        const profil = typeof t.requestProfile === 'string' ? t.requestProfile : `eigenes Profil (${String(t.requestProfile.id ?? 'custom')})`;
        const gesperrt = t.revokedAt ? `, gesperrt seit ${t.revokedAt}` : '';
        out(`  ${t.id.padEnd(24)} ${t.status === 'active' ? 'aktiv   ' : 'gesperrt'} ${t.name}`);
        out(`  ${''.padEnd(24)} Profil ${profil}, Sitzungsdauer ${t.requestTtlSeconds} s, angelegt ${t.createdAt}${gesperrt}`);
      }
      const aktiv = datei.tenants.filter((t) => t.status === 'active').length;
      out('');
      out(`  ${aktiv} aktiv, ${datei.tenants.length - aktiv} gesperrt. Schlüssel werden nicht angezeigt, gespeichert ist nur ihr Hash.`);
      return OK;
    }
    case 'revoke': {
      if (!werte.id) {
        fehler('tenant revoke: --id ist Pflicht.');
        return UNBRAUCHBAR;
      }
      if (!vorhanden) {
        fehler(`tenant revoke: Datei ${pfad} existiert nicht.`);
        return UNBRAUCHBAR;
      }
      let ergebnis: { file: TenantFile; alreadyRevoked: boolean };
      try {
        ergebnis = revokeTenantEntry(datei, werte.id);
        if (!ergebnis.alreadyRevoked) await writeTenantFile(pfad, ergebnis.file);
      } catch (e) {
        fehler(`tenant revoke: ${(e as Error).message}`);
        return UNBRAUCHBAR;
      }
      out(ergebnis.alreadyRevoked ? `Mandant ${werte.id} war bereits gesperrt, nichts geändert.` : `Mandant ${werte.id} gesperrt.`);
      out('Der Dienst liest die Datei beim Start; zum Wirksamwerden neu starten.');
      return OK;
    }
  }
}
