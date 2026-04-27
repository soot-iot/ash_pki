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
    extensions: [AshPki.Resource.Certificate]

  ets do
    private? false
  end
end
