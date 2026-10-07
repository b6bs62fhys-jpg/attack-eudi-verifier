# Production image for the Attack verifier. Node 22 strips TypeScript types at
# runtime; the build stage still runs the strict typecheck before packaging.
#
# The base image is pinned by digest, not by tag alone. A tag moves; a digest
# does not. Without the pin, "rebuild the same image" pulls whatever
# `node:22-bookworm-slim` points to today, which can be a different base with
# different patches. Digest and date, both verified on 2026-09-28 via
# `docker pull node:22-bookworm-slim`:
#
#   Digest: sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c
#
# The tag is kept next to the digest so a human can see which release this is.
# To update, change the digest here and let Dependabot propose the bump (the
# `docker` ecosystem in .github/dependabot.yml watches the Dockerfile).
FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json vitest.config.ts ./
COPY src ./src
RUN npm run typecheck

FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS production

ENV NODE_ENV=production \
    ATTACK_HOST=0.0.0.0 \
    PORT=8080
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Nur die Dateien, die der Dienst zur Laufzeit tatsaechlich laedt. Nicht
# importierter Code und Testdateien bleiben draussen.
#
# Warum die Liste fest ist und nicht alles kopiert: der Dienst laedt ueber
# `node --experimental-strip-types` einzelne Dateien und folgt dabei den
# `import`-Anweisungen. Alles, was er nicht importiert, wird nie gelesen —
# im Image ist es nur Ballast und ein Hinweis auf Quelltext, der nicht
# gebraucht wird.
#
# `decision-test/mock-wallet.ts` ist KEIN Testmaterial im Sinne dieses
# Filters: `src/service/bootstrap.ts` importiert es fuer die
# Verifier-Identitaet. Ohne diese Datei startet der Dienst nicht. Sie bleibt
# deshalb drin, mit dem Nachteil, dass Testschluessel-Erzeugungscode im
# Produktionsimage liegt. Das ist als Entscheidung dokumentiert, nicht
# geaendert.
#
# Dasselbe gilt fuer `onboarding/mock-pki.ts`: es wird ueber
# `onboarding/mock-registrar.ts` und die Gate-Verdrahtung erreicht.
#
# Die Liste ist per Reachability-Analyse aus `src/service/run.ts` erstellt
# (alle relativen `import` aufloesen, transitiv) und gegengeprueft: Build und
# Produktionsstart. Bei einer neuen Laufzeitdatei muss sie hier ergaenzt
# werden — der `docker-build`-Job in der CI faellt dann auf, weil der Start
# mit "Cannot find module" abbricht.
COPY --from=build /app/src/service/run.ts ./src/service/run.ts
COPY --from=build /app/src/service/app.ts ./src/service/app.ts
COPY --from=build /app/src/service/audit.ts ./src/service/audit.ts
COPY --from=build /app/src/service/bootstrap.ts ./src/service/bootstrap.ts
COPY --from=build /app/src/service/credential-status.ts ./src/service/credential-status.ts
COPY --from=build /app/src/service/issuer-anchors.ts ./src/service/issuer-anchors.ts
COPY --from=build /app/src/service/issuer-revocation.ts ./src/service/issuer-revocation.ts
COPY --from=build /app/src/service/limits.ts ./src/service/limits.ts
COPY --from=build /app/src/service/metrics.ts ./src/service/metrics.ts
COPY --from=build /app/src/service/profile.ts ./src/service/profile.ts
COPY --from=build /app/src/service/rate-limit.ts ./src/service/rate-limit.ts
COPY --from=build /app/src/service/service.ts ./src/service/service.ts
COPY --from=build /app/src/service/tenant.ts ./src/service/tenant.ts
COPY --from=build /app/src/service/tenant-file.ts ./src/service/tenant-file.ts
COPY --from=build /app/src/service/registration-certificate.ts ./src/service/registration-certificate.ts
COPY --from=build /app/src/service/verifier-identity.ts ./src/service/verifier-identity.ts
COPY --from=build /app/src/decision-test/mock-wallet.ts ./src/decision-test/mock-wallet.ts
COPY --from=build /app/src/lib/cert-validity.ts ./src/lib/cert-validity.ts
COPY --from=build /app/src/lib/library-log-filter.ts ./src/lib/library-log-filter.ts
COPY --from=build /app/src/lib/limited-fetch.ts ./src/lib/limited-fetch.ts
COPY --from=build /app/src/lib/logger.ts ./src/lib/logger.ts
COPY --from=build /app/src/lib/session.ts ./src/lib/session.ts
COPY --from=build /app/src/onboarding/entitlement-source.ts ./src/onboarding/entitlement-source.ts
COPY --from=build /app/src/onboarding/errors.ts ./src/onboarding/errors.ts
COPY --from=build /app/src/onboarding/jar.ts ./src/onboarding/jar.ts
COPY --from=build /app/src/onboarding/oid.ts ./src/onboarding/oid.ts
COPY --from=build /app/src/onboarding/ocsp-revocation.ts ./src/onboarding/ocsp-revocation.ts
COPY --from=build /app/src/onboarding/onboarding-gate.ts ./src/onboarding/onboarding-gate.ts
COPY --from=build /app/src/onboarding/onboarding-wiring.ts ./src/onboarding/onboarding-wiring.ts
COPY --from=build /app/src/onboarding/registration-ref.ts ./src/onboarding/registration-ref.ts
COPY --from=build /app/src/onboarding/revocation.ts ./src/onboarding/revocation.ts
COPY --from=build /app/src/onboarding/revocation-source.ts ./src/onboarding/revocation-source.ts
COPY --from=build /app/src/onboarding/crl-revocation.ts ./src/onboarding/crl-revocation.ts
COPY --from=build /app/src/onboarding/wrpac.ts ./src/onboarding/wrpac.ts
COPY --from=build /app/src/onboarding/wrprc.ts ./src/onboarding/wrprc.ts
COPY --from=build /app/src/config.ts ./src/config.ts
COPY --from=build /app/src/trustlist/monitor.ts ./src/trustlist/monitor.ts
COPY --from=build /app/src/trustlist/types.ts ./src/trustlist/types.ts
COPY --from=build /app/src/onboarding/mock-pki.ts ./src/onboarding/mock-pki.ts
COPY --from=build /app/src/onboarding/registrar.ts ./src/onboarding/registrar.ts

USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD node -e "fetch('http://127.0.0.1:8080/live').then(r => { if (!r.ok) process.exit(1) }).catch(() => process.exit(1))"
CMD ["node", "--experimental-strip-types", "src/service/run.ts"]
