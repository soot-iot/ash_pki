defmodule AshPki.KeyStrategy.KMS do
  @moduledoc """
  Stub for KMS-wrapped keys (AWS KMS, GCP KMS, Azure Key Vault, ...).

  Descriptor shape (when implemented):

      %{
        "type"     => "kms",
        "provider" => "aws" | "gcp" | "azure",
        "key_id"   => "...",
        "region"   => "..."
      }

  Signing happens by sending the TBS digest to the KMS for signing and
  reconstructing the cert/CRL with the returned signature. No implementation
  in v1; deferred to Phase 6.
  """
  @behaviour AshPki.KeyStrategy

  @impl true
  def name, do: :kms

  @impl true
  def can_sign?, do: true

  @impl true
  def generate(_opts), do: {:error, :not_implemented}

  @impl true
  def public_key(_descriptor), do: {:error, :not_implemented}

  @impl true
  def sign_csr(_descriptor, _csr, _issuer, _opts), do: {:error, :not_implemented}

  @impl true
  def self_sign(_descriptor, _subject, _opts), do: {:error, :not_implemented}

  @impl true
  def sign_crl(_descriptor, _issuer, _entries, _opts), do: {:error, :not_implemented}

  @impl true
  def sign(_descriptor, _body, _opts), do: {:error, :not_implemented}
end
