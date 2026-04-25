# Changelog

All notable changes to `ash_pki` are documented here.

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
