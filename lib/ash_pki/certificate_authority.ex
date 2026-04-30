defmodule AshPki.CertificateAuthority do
  @moduledoc """
  Default `CertificateAuthority` resource shipped with `ash_pki`.

  The schema is provided by the `AshPki.Resource.CertificateAuthority`
  extension. Operators who need custom fields, per-tenant scoping, or a
  different data layer should write their own resource module that
  applies the extension and register it via
  `config :ash_pki, certificate_authority: MyApp.CertificateAuthority`.
  """

  use Ash.Resource,
    otp_app: :ash_pki,
    domain: AshPki.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshPki.Resource.CertificateAuthority]

  ets do
    private? false
  end

  # Default policies (POLICY-SPEC §4.1). Operators overriding this
  # resource (`MyApp.CertificateAuthority`) get their own policies
  # block; they widen the allow set for their roles.
  policies do
    bypass actor_attribute_equals(:role, :admin) do
      authorize_if always()
    end

    policy always() do
      access_type :strict
      authorize_if actor_attribute_equals(:part, :trust_loader)
      authorize_if actor_attribute_equals(:part, :issuer)
      authorize_if actor_attribute_equals(:part, :crl_publisher)
    end
  end
end
