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
    extensions: [AshPki.Resource.CertificateAuthority]

  ets do
    private? false
  end
end
