# Security Policy

## Status

Attack is a prototype and not intended for production use. It has not had an external security review or penetration test. It has been tested end to end only against the mock wallet in this repository, not with a real wallet. Please keep that in mind when you evaluate findings and when you deploy it.

Implemented security properties and known gaps are documented in [`docs/security.md`](docs/security.md) (German: [`docs/sicherheit.md`](docs/sicherheit.md)).

## Reporting a vulnerability

Please report vulnerabilities privately by email to **yaf.wimhoefer@gmail.com**. Do not open a public issue for security problems.

Helpful information:

* affected file, endpoint or version (commit hash)
* steps to reproduce, ideally with a minimal request or test
* impact as you understand it

You will get an acknowledgement as soon as possible. Once a fix is available, the report can be credited in the commit or release notes if you wish.

## Scope

In scope: the verifier service in `src/`, the SDKs in `sdk/` and the CI configuration.

Out of scope: the deliberately insecure TEST material used in dev mode and tests (TEST keys, TEST certificates, the TEST API keys `test-api-key-tenant-A` and `test-api-key-tenant-B`, the mock wallet). These are public on purpose and must never be used outside local development.

## Bug bounty

There is no bug bounty program and no monetary reward.
