defmodule AshPki.TrustStore do
  require Ash.Query

  @moduledoc """
  Aggregates trusted CA certificates for mTLS validation.

  The trust store is read from the `AshPki.CertificateAuthority` resource by
  default (every active CA is implicitly trusted). Callers can also pin
  additional roots from PEM files for environments where some trust anchors
  are not managed through this app.
  """

  @doc """
  All active CAs as OTPCertificate records.
  """
  @spec active_cas() :: [X509.Certificate.t()]
  def active_cas do
    {:ok, cas} =
      AshPki.CertificateAuthority
      |> Ash.Query.filter(status == :active)
      |> Ash.read(authorize?: false)

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
  Combined trust anchors (active CAs + pinned roots).
  """
  @spec trust_anchors() :: [X509.Certificate.t()]
  def trust_anchors do
    Enum.uniq_by(active_cas() ++ pinned_roots(), &X509.Certificate.to_der/1)
  end
end
