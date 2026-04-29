defmodule AshPki.TrustStore do
  require Ash.Query

  @moduledoc """
  Aggregates trusted CA certificates for mTLS validation.

  By default the trust store reads from `AshPki.CertificateAuthority` (every
  active CA is implicitly trusted) and adds any roots pinned via
  configuration. Operators with their own `CertificateAuthority` resource
  pass it via the `:certificate_authority` option:

      AshPki.TrustStore.trust_anchors(certificate_authority: MyApp.CertificateAuthority)
  """

  @default_ca AshPki.CertificateAuthority

  @doc """
  All active CAs as OTPCertificate records.

  Options:

    * `:certificate_authority` — the CA resource module to read from.
      Defaults to `AshPki.CertificateAuthority`.
  """
  @spec active_cas(keyword()) :: [X509.Certificate.t()]
  def active_cas(opts \\ []) do
    ca_module = Keyword.get(opts, :certificate_authority, @default_ca)

    {:ok, cas} =
      ca_module
      |> Ash.Query.filter(status == :active)
      |> Ash.read(actor: AshPki.Actors.system(:trust_loader))

    Enum.flat_map(cas, fn ca ->
      case X509.Certificate.from_pem(ca.certificate_pem || "") do
        {:ok, cert} -> [cert]
        _ -> []
      end
    end)
  end

  @doc """
  Roots pinned via configuration.

      config :ash_pki, :pinned_roots, ["/etc/ssl/extra-root.pem", ...]
  """
  @spec pinned_roots() :: [X509.Certificate.t()]
  def pinned_roots do
    Application.get_env(:ash_pki, :pinned_roots, [])
    |> Enum.flat_map(&load_pem_file/1)
  end

  defp load_pem_file(path) do
    case File.read(path) do
      {:ok, pem} ->
        pem
        |> :public_key.pem_decode()
        |> Enum.flat_map(fn
          {:Certificate, der, _} -> [:public_key.pkix_decode_cert(der, :otp)]
          _ -> []
        end)

      _ ->
        []
    end
  end

  @doc """
  Combined trust anchors (active CAs + pinned roots). Same options as
  `active_cas/1`.
  """
  @spec trust_anchors(keyword()) :: [X509.Certificate.t()]
  def trust_anchors(opts \\ []) do
    Enum.uniq_by(active_cas(opts) ++ pinned_roots(), &X509.Certificate.to_der/1)
  end
end
