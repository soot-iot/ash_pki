defmodule AshPki do
  @moduledoc """
  PKI primitives as an Ash extension.

  Provides Ash resources for `CertificateAuthority`, `Certificate`,
  `RevocationList`, and `EnrollmentToken`, plus a key-strategy behavior, an
  mTLS plug, and mix tasks for bootstrapping a CA hierarchy.

  See `AshPki.Domain` for the resources and `AshPki.Plug.MTLS` for
  terminating mTLS in front of an Ash app.
  """

  @typedoc "PEM-encoded certificate string"
  @type pem :: binary()

  @typedoc "Hex-encoded SHA-256 fingerprint of a certificate (DER)"
  @type fingerprint :: String.t()

  @typedoc "Big-int serial number rendered as a decimal string"
  @type serial :: String.t()

  @doc """
  Returns the configured key strategy module for the given strategy name.
  """
  @spec key_strategy(atom()) :: module()
  def key_strategy(:software), do: AshPki.KeyStrategy.Software
  def key_strategy(:imported), do: AshPki.KeyStrategy.Imported
  def key_strategy(:pkcs11), do: AshPki.KeyStrategy.PKCS11
  def key_strategy(:kms), do: AshPki.KeyStrategy.KMS

  @doc "Resource module for `Certificate` (operator override or library default)."
  @spec certificate() :: module()
  def certificate, do: Application.get_env(:ash_pki, :certificate, AshPki.Certificate)

  @doc "Resource module for `CertificateAuthority` (operator override or library default)."
  @spec certificate_authority() :: module()
  def certificate_authority,
    do:
      Application.get_env(:ash_pki, :certificate_authority, AshPki.CertificateAuthority)

  @doc "Resource module for `RevocationList` (operator override or library default)."
  @spec revocation_list() :: module()
  def revocation_list,
    do: Application.get_env(:ash_pki, :revocation_list, AshPki.RevocationList)

  @doc "Resource module for `EnrollmentToken` (operator override or library default)."
  @spec enrollment_token() :: module()
  def enrollment_token,
    do: Application.get_env(:ash_pki, :enrollment_token, AshPki.EnrollmentToken)
end
