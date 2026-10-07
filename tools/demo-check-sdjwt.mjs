/**
 * Erzeugt einen SD-JWT-VC aus dem Mock-Wallet des Repositorys und schreibt ihn
 * nach stdout. Wird von tools/demo-check.sh aufgerufen, dort für Schritt 7 von
 * [interne Notiz, nicht veröffentlicht].
 *
 * Der Nachweis stammt aus lokal erzeugtem Testmaterial. Es war kein Lauf gegen
 * eine echte Wallet. Siehe Abschnitt 5 von [interne Notiz, nicht veröffentlicht].
 *
 * Läuft nur mit: node --experimental-strip-types tools/demo-check-sdjwt.mjs
 */
import 'reflect-metadata';
import { generateTestKeyMaterial, buildSdJwtVc } from '../src/decision-test/mock-wallet.ts';

const issuerKey = await generateTestKeyMaterial('demo-check Issuer TEST');
const holderKey = await generateTestKeyMaterial('demo-check Holder TEST');

const gebaut = await buildSdJwtVc({
  issuerKey,
  holderKey,
  claimName: 'given_name',
  claimValue: 'Erika',
});

process.stdout.write(gebaut.sdJwt);
