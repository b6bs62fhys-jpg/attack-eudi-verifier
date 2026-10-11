import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import { DEV_TEST_TENANTS } from './bootstrap.ts';
import { resolveRequestProfile } from './profile.ts';

describe('DEV_TEST_TENANTS', () => {
  it('hat eindeutige Kennungen und Schlüssel', () => {
    const ids = DEV_TEST_TENANTS.map((t) => t.id);
    const keys = DEV_TEST_TENANTS.map((t) => t.apiKey);
    expect(new Set(ids).size).toBe(ids.length);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('enthält einen Altersprüfungs-Mandanten, der nur die Schwelle 18 anfragt', () => {
    const t = DEV_TEST_TENANTS.find((x) => x.id === 'tenant-age');
    expect(t).toBeDefined();
    const profil = resolveRequestProfile((t as { requestProfile?: string }).requestProfile ?? 'pid_basis');
    expect(profil.id).toBe('age_over_18_de');
    expect(profil.claims).toEqual(['age_equal_or_over.18']);
  });
});
