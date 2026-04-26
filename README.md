# `ash_pki`

PKI primitives as an Ash extension: certificate authorities, certificates,
revocation lists, an enrollment-token resource, and an mTLS plug. The library
is independent of any particular application layer — it deals in CAs, certs,
keys, and trust stores.

## Resources

* `AshPki.CertificateAuthority` — root or intermediate CAs. Generates
  keypairs and self-signs (root) or has its CSR signed by a parent
  (intermediate).
* `AshPki.Certificate` — issued or imported leaf certificates. Actions for
  `issue` (sign a CSR), `import_certificate` (pre-provisioned device cert),
  `revoke`.
* `AshPki.RevocationList` — signed CRLs per CA, with a sequence number and a
  current/superseded status.
* `AshPki.EnrollmentToken` — short-lived bootstrap credential, hashed at
  rest.
* `AshPki.Plug.MTLS` — terminate mTLS in front of an Ash app. Reads the
  peer cert from the SSL connection (or a configured header in
  LB-termination mode), verifies the chain against the active trust
  anchors, looks the cert up in `AshPki.Certificate`, and assigns the
  verified peer to `conn.assigns.ash_pki_actor` for use by Ash policies.

## Key strategies

`AshPki.KeyStrategy` is a behavior; each implementation decides how key
material is stored and used:

* `Software` — keys generated and stored as PEM in the descriptor map.
  Suitable for development and small fleets. (Production deployments should
  wrap the descriptor with envelope encryption; the descriptor shape is
  opaque so this can be added later without schema changes.)
* `Imported` — public-only entries for pre-provisioned secure-element keys
  (ATECC, OPTIGA, EdgeLock). The backend never holds signing material.
  See **Bulk import** below for the manufacturing-line flow.
* `PKCS11` — HSM-backed CA signing keys via Erlang's `:crypto.engine_load`
  bridge to OpenSSL's pkcs11 engine. The descriptor stores the module
  path, key id (PKCS#11 URI), algorithm, cached public-key PEM, and the
  name of the env var holding the PIN — never the PIN itself. Key
  generation is intentionally external: provision keys with
  `pkcs11-tool --keypairgen` (or vendor tooling) and import the
  descriptor. SoftHSM2 works as a local test target.
* `KMS` — interface only; implementation deferred.

## Bulk import

`AshPki.Certificate.Bulk` and `mix ash_pki.import_certs` handle the
production-line flow where a silicon vendor (ATECC, OPTIGA, EdgeLock)
hands over a manifest of pre-issued device certs:

```sh
# CSV: serial,certificate_pem,vendor[,vendor_meta]
mix ash_pki.import_certs --issuer intermediate --csv vendor_manifest.csv

# Concatenated PEM bundle
mix ash_pki.import_certs --issuer intermediate --bundle device_certs.pem \
                         --vendor atecc608

# Single PEM
mix ash_pki.import_certs --issuer intermediate --cert device_001.pem \
                         --vendor optiga_trust_m
```

Vendor-specific manifests almost always need a one-time conversion to
the CSV shape; that conversion is the operator's job (or the silicon
vendor's tooling). Rows that fail validation are skipped and reported
with their (line / cert index, reason) — the rest of the manifest is
not aborted.

## Demo

```sh
mix deps.get
mix ash_pki.init --out priv/pki
mix ash_pki.gen.cert --issuer intermediate \
                     --subject "/CN=device-001/O=Example" \
                     --name device-001 \
                     --san dns:device-001.local
openssl verify -CAfile priv/pki/root_ca.pem \
               -untrusted priv/pki/intermediate_ca.pem \
               priv/pki/device-001.cert.pem
```

The two tasks share state across `mix` invocations via
`priv/pki/ash_pki.json`. Deployments running against AshPostgres ignore that
file and rely on database persistence.

## Data layer

Resources default to `Ash.DataLayer.Ets` so the demo and tests run without a
database. Real deployments swap to `AshPostgres.DataLayer`; the resource
definitions stay the same.

## Out of scope (v0.1)

* HSM/PKCS#11 and KMS implementations (interfaces designed only).
* Cross-CA federation, ACME issuance, OCSP responder, certificate
  transparency log integration.
* End-to-end pre-provisioned cert import with vendor-specific metadata
  decoding.

## Tests

```sh
mix test
```

14 tests covering CA bootstrap, intermediate signing, leaf issuance, chain
validation, revocation + CRL publication, and the mTLS plug across
known/unknown/revoked cert paths.
