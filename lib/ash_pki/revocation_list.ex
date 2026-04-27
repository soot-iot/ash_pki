defmodule AshPki.RevocationList do
  @moduledoc """
  Default `RevocationList` resource shipped with `ash_pki`.

  The schema is provided by the `AshPki.Resource.RevocationList`
  extension. Each call to `publish/1` writes a new row with a fresh
  sequence number, marking earlier rows for the same CA as
  `:superseded`. The current row is what gets served at the CRL
  distribution point. Operators who need custom fields or a different
  data layer should write their own resource module that applies the
  extension and register it via
  `config :ash_pki, revocation_list: MyApp.RevocationList`.
  """

  use Ash.Resource,
    otp_app: :ash_pki,
    domain: AshPki.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshPki.Resource.RevocationList]

  ets do
    private? false
  end
end
