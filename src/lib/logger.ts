/**
 * Kleiner strukturierter Logger mit einer sicheren Feld-Whitelist.
 * Sensible Werte werden auch dann verworfen, wenn ein Aufrufer sie versehentlich
 * unter einem ungeeigneten Feldnamen übergibt.
 */

export type LogLevel = 'info' | 'warn' | 'error';
export type LogValue = string | number | boolean;
export type LogFields = Record<string, LogValue | undefined>;

const SENSITIVE_FIELD = /(token|claim|cert|key|secret|authorization|vp|jwe|jwt|nonce|state|subject|serial|pem|der)/i;

function safeFields(fields: LogFields): Record<string, LogValue> {
  return Object.fromEntries(Object.entries(fields).filter(([key, value]) => value !== undefined && !SENSITIVE_FIELD.test(key))) as Record<string, LogValue>;
}

export interface Logger {
  info(event: string, fields?: LogFields): void;
  warn(event: string, fields?: LogFields): void;
  error(event: string, fields?: LogFields): void;
}

function write(level: LogLevel, event: string, fields: LogFields = {}): void {
  const record = { ts: new Date().toISOString(), level, event, ...safeFields(fields) };
  if (level === 'error') console.error(JSON.stringify(record));
  else if (level === 'warn') console.warn(JSON.stringify(record));
  else console.log(JSON.stringify(record));
}

export const logger: Logger = Object.freeze({
  info: (event: string, fields?: LogFields) => write('info', event, fields),
  warn: (event: string, fields?: LogFields) => write('warn', event, fields),
  error: (event: string, fields?: LogFields) => write('error', event, fields),
});

export function redactLogFields(fields: LogFields): Record<string, LogValue> {
  return safeFields(fields);
}
