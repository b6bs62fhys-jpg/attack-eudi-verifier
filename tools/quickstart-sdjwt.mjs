/**
 * Erzeugt einen SD-JWT-VC aus dem Mock-Wallet des Repositorys und schreibt ihn
 * nach stdout. Wird von docs/quickstart-integration.md in Schritt 2 benutzt,
 * dort über einen ```bash quickstart Block.
 *
 * Der Nachweis ist Testmaterial aus diesem Repository. Es war kein Lauf gegen
 * eine echte Wallet, siehe Abschnitt 7 des Quickstarts.
 *
 * Läuft nur mit: node --experimental-strip-types tools/quickstart-sdjwt.mjs
 */
import 'reflect-metadata';
import { generateTestKeyMaterial, buildSdJwtVc } from '../src/decision-test/mock-wallet.ts';

const issuerKey = await generateTestKeyMaterial('quickstart Issuer TEST');
const holderKey = await generateTestKeyMaterial('quickstart Holder TEST');

const gebaut = await buildSdJwtVc({
  issuerKey,
  holderKey,
  claimName: 'given_name',
  claimValue: 'Erika',
});

process.stdout.write(gebaut.sdJwt);
