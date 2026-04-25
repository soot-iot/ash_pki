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
end
