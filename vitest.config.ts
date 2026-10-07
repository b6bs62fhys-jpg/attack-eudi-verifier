import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
    pool: 'forks',
    testTimeout: 30_000,
    hookTimeout: 30_000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts'],
      // Gemessener Stand vom 28.09.2026 auf `tests-vertiefen` (Basis a5f89b3):
      // Statements 79.20 %, Branches 78.17 %, Functions 84.56 %, Lines 82.10 %.
      // Abwaertsgerundet auf ganze Prozentpunkte. Gerundet **nach unten**, weil
      // die Schwelle den Stand erreichen soll und nicht knapp verfehlen: bei
      // 79.2 wuerde schon eine einzige neue Zeile ohne Test den Lauf rot
      // machen, und bei 79.0 wird genau das vermieden, ohne dass eine echte
      // Verschlechterung durchrutscht. Wer die Grenze anhebt, soll den gemessenen
      // Stand im PR nennen, nicht die Zahl runden.
      thresholds: {
        statements: 79,
        branches: 78,
        functions: 84,
        lines: 82,
      },
    },
  },
});
