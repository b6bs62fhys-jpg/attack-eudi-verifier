/**
 * Client-Adresse hinter einem Reverse Proxy oder Tunnel.
 *
 * Problem: Hinter Caddy oder einem Cloudflare Tunnel sieht der Dienst für jede
 * Wallet dieselbe Quelladresse, nämlich die des Proxys. Die Ratenbegrenzung der
 * öffentlichen Routen zählt dann alle Wallets zusammen.
 *
 * Lösung: `X-Forwarded-For` wird nur ausgewertet, wenn die direkte Gegenstelle
 * in der Liste vertrauenswürdiger Proxys steht (ATTACK_TRUSTED_PROXIES).
 * Von allen anderen Gegenstellen wird der Header ignoriert, sonst könnte jeder
 * Client seine Adresse frei wählen und die Begrenzung umgehen.
 *
 * Auswertung (wie üblich von rechts): Jeder Proxy hängt die Adresse seiner
 * Gegenstelle rechts an. Von rechts gelesen sind die ersten Einträge die
 * eigenen Proxys; der erste Eintrag, der kein vertrauenswürdiger Proxy ist, ist
 * der Client. Links davon steht nur, was der Client selbst behauptet hat, und
 * wird nie verwendet.
 *
 * Fail closed: Ist der Header unbrauchbar (kein gültiger Eintrag, mehr als 20
 * Einträge, länger als 1024 Zeichen), gilt die direkte Gegenstelle.
 */
import { BlockList, isIP } from 'node:net';

import { ConfigError } from '../config.ts';

export const ENV_ATTACK_TRUSTED_PROXIES = 'ATTACK_TRUSTED_PROXIES';
const MAX_HEADER_CHARS = 1024;
const MAX_ENTRIES = 20;

export interface TrustedProxies {
  /** Die Liste, wie sie konfiguriert wurde (für Anzeige und Tests). */
  readonly entries: readonly string[];
  contains(address: string): boolean;
}

/** `::ffff:1.2.3.4` ist dieselbe Adresse wie `1.2.3.4`. */
export function normalizeAddress(address: string): string {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address);
  return mapped ? (mapped[1] as string) : address;
}

/**
 * Liest ATTACK_TRUSTED_PROXIES: Adressen oder Netze (CIDR), durch Komma
 * getrennt, IPv4 und IPv6. Ungültige Einträge brechen den Start ab, ebenso ein
 * Netz mit Präfixlänge 0 (das vertraute jeder Adresse und machte die
 * Fälschung des Headers wieder möglich).
 */
export function parseTrustedProxies(raw: string | undefined): TrustedProxies | undefined {
  if (raw === undefined || raw.trim() === '') return undefined;
  const list = new BlockList();
  const entries: string[] = [];
  for (const part of raw.split(',')) {
    const item = part.trim();
    const [address, prefixText, ...rest] = item.split('/');
    const family = address === undefined ? 0 : isIP(address);
    if (item === '' || family === 0 || rest.length > 0) {
      throw new ConfigError(`${ENV_ATTACK_TRUSTED_PROXIES}: "${item}" ist weder eine IP-Adresse noch ein Netz in CIDR-Schreibweise. Start abgebrochen.`);
    }
    const type = family === 4 ? 'ipv4' : 'ipv6';
    if (prefixText === undefined) {
      list.addAddress(address as string, type);
    } else {
      const max = family === 4 ? 32 : 128;
      const prefix = /^\d{1,3}$/.test(prefixText) ? Number(prefixText) : Number.NaN;
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) {
        throw new ConfigError(`${ENV_ATTACK_TRUSTED_PROXIES}: Präfixlänge in "${item}" muss zwischen 0 und ${max} liegen. Start abgebrochen.`);
      }
      if (prefix === 0) {
        throw new ConfigError(`${ENV_ATTACK_TRUSTED_PROXIES}: "${item}" würde jeder Adresse vertrauen. Start abgebrochen.`);
      }
      list.addSubnet(address as string, prefix, type);
    }
    entries.push(item);
  }
  return {
    entries,
    contains(address: string): boolean {
      const normalized = normalizeAddress(address);
      const family = isIP(normalized);
      if (family === 0) return false;
      return list.check(normalized, family === 4 ? 'ipv4' : 'ipv6');
    },
  };
}

/**
 * Die Adresse, die für die Ratenbegrenzung zählt.
 *
 * @param remote  direkte Gegenstelle (`req.socket.remoteAddress`)
 * @param forwarded  Wert von `X-Forwarded-For`, mehrere Header sind bereits zusammengefasst
 */
export function resolveClientAddress(remote: string | undefined, forwarded: string | undefined, trusted: TrustedProxies | undefined): string {
  const direct = remote === undefined ? 'unknown' : normalizeAddress(remote);
  if (!trusted || direct === 'unknown' || !trusted.contains(direct)) return direct;
  if (forwarded === undefined || forwarded.length === 0 || forwarded.length > MAX_HEADER_CHARS) return direct;
  const entries = forwarded.split(',').map((entry) => normalizeAddress(entry.trim()));
  if (entries.length > MAX_ENTRIES || entries.some((entry) => isIP(entry) === 0)) return direct;
  for (let i = entries.length - 1; i >= 0; i -= 1) {
    const entry = entries[i] as string;
    if (!trusted.contains(entry)) return entry;
  }
  // Alle Einträge sind eigene Proxys: es gibt keinen Client, den man benennen könnte.
  return direct;
}
