import eslint from '@eslint/js';
import promise from 'eslint-plugin-promise';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/coverage/**',
      '**/dist/**',
      'eslint.config.js',
      '**/*.js',
      'docs/eudi-verify-e2e-sicherung/**',
      'test/eudi-verify/**',
      'test/miEUDIverifier/**',
      'test/waltid/**',
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    // Werkzeugskripte, die direkt mit `node` laufen und deshalb nicht
    // ueber tsc laufen. Sie brauchen die Node-Globals, sonst ist jedes
    // process.stdout als no-undef rot.
    files: ['**/*.mjs', '**/*.cjs'],
    languageOptions: {
      sourceType: 'module',
      globals: {
        process: 'readonly',
        console: 'readonly',
        URL: 'readonly',
        Buffer: 'readonly',
      },
    },
  },
  {
    files: ['**/*.ts'],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      promise,
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': [
        'error',
        { checksVoidReturn: { arguments: false, attributes: false } },
      ],
      'promise/always-return': 'warn',
      'promise/no-return-wrap': 'error',
      'promise/no-nesting': 'warn',
      'promise/no-promise-in-callback': 'warn',
      // Diese Regeln standen als Warnung, damit der Bestand beim Einführen
      // des Lintings sichtbar, aber nicht blockierend war. Der Bestand ist
      // abgeräumt (Stand 28.09.2026, npm run lint meldet null Meldungen),
      // deshalb sind sie jetzt Fehler. Aus einer Warnung, die niemand
      // beachtet, ist sonst über die Zeit eine Grundregel geworden.
      //
      // `promise/always-return` und `promise/no-nesting` bleiben Warnung: sie
      // melden Muster, die in asyncem Code an mehreren Stellen legitim sind
      // (Zwischenstationen, verschachtelte Prüfungen) und deren Umbau
      // Anwendungslogik anfassen würde.
      '@typescript-eslint/no-unused-vars': 'error',
      'no-useless-assignment': 'error',
      'prefer-const': 'error',
      'preserve-caught-error': 'error',
      '@typescript-eslint/await-thenable': 'error',
    },
  },
);
