defmodule AshPki.KeyStrategy.Software do
  @moduledoc """
  Software-keys strategy.

  Stores PEM-encoded private and public keys in the descriptor map. Suitable
  for development and for production fleets where HSM/KMS isn't available.

  The descriptor is shaped:

      %{
        "type"            => "software",
        "algorithm"       => "ec" | "rsa",
        "private_key_pem" => "-----BEGIN ...",
        "public_key_pem"  => "-----BEGIN PUBLIC KEY..."
      }

  Production deployments should wrap the private key PEM with envelope
  encryption (a KEK held outside the DB). The descriptor shape is stable
  across that change because callers treat it as opaque.
  """

  @behaviour AshPki.KeyStrategy

  @impl true
  def name, do: :software

  @impl true
  def can_sign?, do: true

  @impl true
  def generate(opts \\ []) do
    private =
      case Keyword.get(opts, :type, :ec) do
        :ec ->
          curve = Keyword.get(opts, :curve, :secp256r1)
          X509.PrivateKey.new_ec(curve)

        :rsa ->
          bits = Keyword.get(opts, :bits, 2048)
          X509.PrivateKey.new_rsa(bits)
      end

    public = X509.PublicKey.derive(private)

    descriptor = %{
      "type" => "software",
      "algorithm" => Keyword.get(opts, :type, :ec) |> Atom.to_string(),
      "private_key_pem" => X509.PrivateKey.to_pem(private),
      "public_key_pem" => X509.PublicKey.to_pem(public)
    }

    {:ok, descriptor}
  end

  @impl true
  def public_key(%{"public_key_pem" => pem}) when is_binary(pem) do
    case X509.PublicKey.from_pem(pem) do
      {:ok, key} -> {:ok, key}
      {:error, reason} -> {:error, {:invalid_public_key, reason}}
    end
  end

  def public_key(_), do: {:error, :missing_public_key}

  @impl true
  def sign_csr(descriptor, csr, issuer_cert, opts \\ []) do
    with {:ok, issuer_key} <- private_key(descriptor),
         true <- X509.CSR.valid?(csr) || {:error, :invalid_csr_signature} do
      subject = X509.CSR.subject(csr)
      public = X509.CSR.public_key(csr)

      base_extensions = Keyword.get(opts, :extensions, [])
      template = Keyword.get(opts, :template, :server)
      validity_days = Keyword.get(opts, :validity_days, 90)
      hash = Keyword.get(opts, :hash, :sha256)

      cert =
        X509.Certificate.new(public, subject, issuer_cert, issuer_key,
          template: template,
          validity: validity_days,
          extensions: base_extensions,
          hash: hash,
          serial: Keyword.get(opts, :serial, {:random, 20})
        )

      {:ok, cert}
    end
  end

  @impl true
  def self_sign(descriptor, subject, opts \\ []) do
    with {:ok, private} <- private_key(descriptor) do
      template = Keyword.get(opts, :template, :root_ca)
      validity_days = Keyword.get(opts, :validity_days, 365 * 10)
      hash = Keyword.get(opts, :hash, :sha256)

      cert =
        X509.Certificate.self_signed(private, subject,
          template: template,
          validity: validity_days,
          hash: hash,
          serial: Keyword.get(opts, :serial, {:random, 20}),
          extensions: Keyword.get(opts, :extensions, [])
        )

      {:ok, cert}
    end
  end

  @impl true
  def sign_crl(descriptor, issuer_cert, entries, opts \\ []) do
    with {:ok, private} <- private_key(descriptor) do
      crl =
        X509.CRL.new(entries, issuer_cert, private,
          hash: Keyword.get(opts, :hash, :sha256),
          next_update_in_days: Keyword.get(opts, :next_update_in_days, 7)
        )

      {:ok, crl}
    end
  end

  @impl true
  def sign(descriptor, body, opts \\ []) when is_binary(body) do
    digest_alg = Keyword.get(opts, :digest_alg, :sha256)

    with {:ok, private} <- private_key(descriptor) do
      {:ok, :public_key.sign(body, digest_alg, private)}
    end
  end

  @impl true
  def import_public(_cert_pem, _opts) do
    {:error, :use_imported_strategy}
  end

  @doc false
  def private_key(%{"private_key_pem" => pem}) when is_binary(pem) do
    case X509.PrivateKey.from_pem(pem) do
      {:ok, key} -> {:ok, key}
      {:error, reason} -> {:error, {:invalid_private_key, reason}}
    end
  end

  def private_key(_), do: {:error, :missing_private_key}
end
