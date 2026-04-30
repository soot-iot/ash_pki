defmodule AshPki.Certificate do
  @moduledoc """
  Default `Certificate` resource shipped with `ash_pki`.

  The schema (attributes, identities, the `:issuer` relationship, the
  `issue` / `import_certificate` / `revoke` actions, and the code
  interface) is provided by the `AshPki.Resource.Certificate` extension,
  so an operator who doesn't need any extra fields can use this module
  unchanged. Anyone who wants custom fields, per-tenant scoping, or a
  different data layer should write their own resource module that
  applies the extension and register it via
  `config :ash_pki, certificate: MyApp.Certificate`.
  """

  use Ash.Resource,
    otp_app: :ash_pki,
    domain: AshPki.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshPki.Resource.Certificate]

  ets do
    private? false
  end

  # Default policies (POLICY-SPEC §4.1). `:issuer` covers
  # certificate issuance (CA load + leaf insert via the
  # `IssueCertificate` change) and bulk import. `:mtls_resolver`
  # covers the per-request fingerprint lookup. `:crl_publisher`
  # covers the revoked-cert read for CRL generation.
  policies do
    bypass actor_attribute_equals(:role, :admin) do
      authorize_if always()
    end

    policy always() do
      access_type :strict
      authorize_if actor_attribute_equals(:part, :issuer)
      authorize_if actor_attribute_equals(:part, :mtls_resolver)
      authorize_if actor_attribute_equals(:part, :crl_publisher)
    end
  end
end
