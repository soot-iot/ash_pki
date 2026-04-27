# `ash_pki`

PKI primitives as an Ash extension: certificate authorities, certificates,
revocation lists, an enrollment-token resource, and an mTLS plug. The library
is independent of any particular application layer — it deals in CAs, certs,
keys, and trust stores.

## Resources you own

The four PKI primitives ship as `Ash.Resource` extensions. Apply them to
your own resource modules so you can mix in custom fields, per-tenant
scoping, policies, or a different data layer:

```elixir
defmodule MyApp.Certificate do
  use Ash.Resource,
    domain: MyApp.PKI,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPki.Resource.Certificate]

  postgres do
    table "certificates"
    repo MyApp.Repo
  end

  pki do
    certificate_authority MyApp.CertificateAuthority
  end

  attributes do
    attribute :tenant_id, :uuid, public?: true
    attribute :hardware_attestation, :map
  end
end

defmodule MyApp.CertificateAuthority do
  use Ash.Resource,
    domain: MyApp.PKI,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPki.Resource.CertificateAuthority]

  pki do
    certificate MyApp.Certificate
    revocation_list MyApp.RevocationList
  end
end

defmodule MyApp.RevocationList do
  use Ash.Resource,
    domain: MyApp.PKI,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPki.Resource.RevocationList]

  pki do
    certificate_authority MyApp.CertificateAuthority
    certificate MyApp.Certificate
  end
end
```

Each resource declares its siblings in a `pki do ... end` block — that
is the only "registry" AshPki uses. Internal changes (`issue`,
`import_certificate`, `publish` CRL) discover their siblings through
`AshPki.Info` introspection of the resource being acted on. There is no
application-global config to set, and you can run multiple independent
PKI hierarchies in the same app (e.g. one per tenant) just by writing
multiple sets of resources.

The four extensions:

* `AshPki.Resource.CertificateAuthority` — root + intermediate CAs.
  Injects `create_root` / `create_intermediate` / `rotate` actions and
  `:issued_certificates` / `:revocation_lists` has_many relationships.
* `AshPki.Resource.Certificate` — leaf certs. Injects `issue` (sign a
  CSR), `import_certificate` (pre-provisioned device cert), `revoke`.
* `AshPki.Resource.RevocationList` — signed CRLs per CA with a sequence
  number and a current/superseded status.
* `AshPki.Resource.EnrollmentToken` — short-lived bootstrap credential,
  hashed at rest. (No siblings; no `pki` block needed.)

Anything you declare yourself (an attribute, an action, an identity, the
`:issuer` relationship) takes precedence — the extensions use
`add_new_*` builders that no-op when the entity already exists.

If you don't need any customization, the library also ships
zero-configuration defaults — `AshPki.Certificate`,
`AshPki.CertificateAuthority`, `AshPki.RevocationList`, and
`AshPki.EnrollmentToken` — backed by `Ash.DataLayer.Ets`. Every
extension's `pki` options default to those modules, so the defaults work
without anyone declaring a `pki` block.

`AshPki.Plug.MTLS` terminates mTLS in front of an Ash app. It reads the
peer cert from the SSL connection (or a configured header in
LB-termination mode), verifies the chain against the active trust
anchors, looks the cert up in the configured `Certificate` module, and
assigns the verified peer to `conn.assigns.ash_pki_actor` for use by Ash
policies. Wire your own resource via the `:certificate` option:

```elixir
plug AshPki.Plug.MTLS, certificate: MyApp.Certificate
```

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

The default resources use `Ash.DataLayer.Ets` so the demo and tests run
without a database. Operator-owned resources pick whichever data layer
they want — the extensions are data-layer agnostic.

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

Tests cover CA bootstrap, intermediate signing, leaf issuance, chain
validation, revocation + CRL publication, the mTLS plug across
known/unknown/revoked cert paths, and the resource-extension pattern
applied to consumer-owned modules.
