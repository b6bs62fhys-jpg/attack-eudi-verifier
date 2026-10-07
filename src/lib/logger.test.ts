import assert from 'node:assert/strict';
import { describe, it } from 'vitest';

import { redactLogFields } from './logger.ts';

describe('structured logger redaction', () => {
  it('drops credential, token and claim fields before serialization', () => {
    assert.deepEqual(redactLogFields({ route: '/ready', status: 200, token: 'secret', claims: 'private', certificate: 'der' }), { route: '/ready', status: 200 });
  });
});
