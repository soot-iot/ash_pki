defmodule AshPki.KeyStrategy.Imported do
  @moduledoc """
  Strategy for pre-provisioned device keys (ATECC, OPTIGA, EdgeLock, ...).

  The backend never sees a private key — it stores only the public certificate
  chain provided by the silicon vendor. Signing operations always fail; the
  device handles signatures locally with its secure element.

  The descriptor stores:

      %{
        "type"           => "imported",
        "public_key_pem" => "-----BEGIN PUBLIC KEY...",
        "vendor"         => "atecc608" | "optiga_trust_m" | "edgelock_se05x" | "custom",
        "vendor_meta"    => map() | nil
      }
  """

  @behaviour AshPki.KeyStrategy

  @impl true
  def name, do: :imported

  @impl true
  def can_sign?, do: false

  @impl true
  def generate(_opts), do: {:error, :no_signing_capability}

  @impl true
  def public_key(%{"public_key_pem" => pem}) when is_binary(pem) do
    case X509.PublicKey.from_pem(pem) do
      {:ok, key} -> {:ok, key}
      {:error, reason} -> {:error, {:invalid_public_key, reason}}
    end
  end

  def public_key(_), do: {:error, :missing_public_key}

  @impl true
  def sign_csr(_descriptor, _csr, _issuer, _opts), do: {:error, :no_signing_capability}

  @impl true
  def self_sign(_descriptor, _subject, _opts), do: {:error, :no_signing_capability}

  @impl true
  def sign_crl(_descriptor, _issuer, _entries, _opts), do: {:error, :no_signing_capability}

  @impl true
  def sign(_descriptor, _body, _opts), do: {:error, :no_signing_capability}

  @impl true
  def import_public(cert_pem, opts) when is_binary(cert_pem) do
    case X509.Certificate.from_pem(cert_pem) do
      {:ok, cert} ->
        public = X509.Certificate.public_key(cert)

        {:ok,
         %{
           "type" => "imported",
           "public_key_pem" => X509.PublicKey.to_pem(public),
           "vendor" => Keyword.get(opts, :vendor, "custom") |> to_string(),
           "vendor_meta" => Keyword.get(opts, :vendor_meta)
         }}

      {:error, reason} ->
        {:error, {:invalid_certificate_pem, reason}}
    end
  end
end
