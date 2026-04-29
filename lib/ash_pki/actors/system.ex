defmodule AshPki.Actors.System do
  @moduledoc """
  Internal-subsystem actor for `ash_pki`.

  `:part` enumerates which PKI subsystem is acting:

    * `:issuer` — certificate issuance / import flows (CA load,
      bulk insert).
    * `:crl_publisher` — CRL generation / supersession.
    * `:trust_loader` — reads active CAs to build the SSL trust
      anchor list.
    * `:mtls_resolver` — looks up a Certificate row by fingerprint
      during mTLS plug verification.

  `:tenant_id` is set when the operation is scoped to one tenant;
  `nil` for cross-tenant flows like CRL publishing or trust-anchor
  loading.
  """

  @enforce_keys [:part]
  defstruct [:part, :tenant_id]

  @type part :: :issuer | :crl_publisher | :trust_loader | :mtls_resolver

  @type t :: %__MODULE__{
          part: part(),
          tenant_id: String.t() | nil
        }
end
