defmodule AshPki.Domain do
  @moduledoc """
  Ash domain for the PKI resources.

  Operators using `ash_pki` standalone can either include this domain
  directly or generate their own resources using these as templates.
  """

  use Ash.Domain,
    otp_app: :ash_pki,
    validate_config_inclusion?: false

  resources do
    allow_unregistered? true

    resource AshPki.CertificateAuthority
    resource AshPki.Certificate
    resource AshPki.RevocationList
    resource AshPki.EnrollmentToken
  end
end
