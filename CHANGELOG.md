# Changelog

## 2026-10-08: security fix, revocation check of the issuer chain

**This was a vulnerability.** If the `x5c` header of a presented PID contained
the configured trust anchor as its last certificate, the certificate in front of
it (the leaf or an intermediate CA) was never checked for revocation. A revoked
issuer certificate was accepted as soon as the issuer appended the anchor to the
header. Affected: `enforceIssuerChainRevocation`
(`src/service/issuer-revocation.ts`) and with it every verification in
production mode.

Not affected: chains without the anchor in `x5c`, and the case where the leaf
itself is the anchor. The library check (`revocationPolicy: 'prefer'`) can only
reject and did not close the gap.

Exploiting it needed an issuer certificate that was once validly issued but has
been revoked since. No such case is known. Whether it ever happened was not
checked: the service has so far only been run against test material.

Fixed: the anchor stays as the last element of the chain, so the certificate in
front of it is checked against it. Regression test:
`src/service/issuer-revocation-anker-im-x5c.test.ts` (four cases, one of them
fails on the old code).

If you deployed an earlier commit, update. The older code is affected from the
first public release (`8c8cf1c`) up to the commit before this fix.
