defmodule AshPki.EnrollmentToken do
  @moduledoc """
  Default `EnrollmentToken` resource shipped with `ash_pki`.

  The schema is provided by the `AshPki.Resource.EnrollmentToken`
  extension. Tokens are stored hashed; the plaintext is returned exactly
  once on the result of `mint/3` via Ash resource metadata:

      {:ok, token} = AshPki.EnrollmentToken.mint(:device, "serial-001", at)
      Ash.Resource.get_metadata(token, :plaintext_token)
      # => "..."  (URL-safe base64, 32 random bytes)

  Operators who need custom fields, scope_ref typing, or a different data
  layer should write their own resource module that applies the extension
  and register it via `config :ash_pki, enrollment_token:
  MyApp.EnrollmentToken`.
  """

  use Ash.Resource,
    otp_app: :ash_pki,
    domain: AshPki.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshPki.Resource.EnrollmentToken]

  ets do
    private? false
  end
end
