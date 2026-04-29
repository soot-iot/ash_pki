# Changelog

All notable changes to `ash_pki` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to semantic versioning.

## [Unreleased]

### Added
- `mix ash_pki.install` now generates AshPostgres-backed consumer
  resource modules for all four ash_pki resources
  (`CertificateAuthority`, `Certificate`, `RevocationList`,
  `EnrollmentToken`) under `lib/<app>/` and registers them in
  `config/config.exs` under `:ash_pki, <key>:`. The installer composes
  `ash_postgres.install` to wire the consumer's Repo and the
  `:ash_postgres` dep. The library's own concrete defaults stay on
  `Ash.DataLayer.Ets` for the ash_pki test suite; consumer projects
  always boot against AshPostgres, which is mandatory in the soot
  stack.

## v0.1.0 (unreleased)

Initial release. Phase 1 deliverable.

### Resources

- `AshPki.CertificateAuthority` — root and intermediate CA generation,
  rotation, lookup by name.
- `AshPki.Certificate` — `issue` (sign a CSR), `import_certificate`
  (pre-provisioned device cert), `revoke`, lookups by fingerprint and
  by `(issuer_id, serial)`.
- `AshPki.RevocationList` — sequenced CRLs per CA with current/superseded
  status.
- `AshPki.EnrollmentToken` — hashed-at-rest bootstrap credential.
  Plaintext is returned on the result of `mint/3` via Ash resource
  metadata and is the only point at which it is recoverable.

### Surfaces

- `AshPki.Plug.MTLS` — terminate mTLS in front of an Ash app, populate
  `conn.assigns.ash_pki_actor` with a verified peer struct.
- `AshPki.KeyStrategy` behavior with `Software`, `Imported`, and stub
  `PKCS11` / `KMS` implementations.
- Mix tasks `ash_pki.init` and `ash_pki.gen.cert` for bootstrap and
  one-off cert issuance.
