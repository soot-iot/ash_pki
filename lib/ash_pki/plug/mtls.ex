defmodule AshPki.Plug.MTLS do
  @moduledoc """
  Terminates mTLS for an Ash app behind Bandit.

  Reads the peer certificate from the SSL connection, validates the chain
  against the active trust anchors (`AshPki.TrustStore`), and ensures the
  cert is on file (`AshPki.Certificate`) and not revoked. On success it
  populates `conn.assigns.ash_pki_actor` with a struct that policies can
  reference.

  ## Options

    * `:trust_anchors` — function returning OTPCertificates to trust;
      defaults to `AshPki.TrustStore.trust_anchors/0`.
    * `:require_known_certificate` — if `true` (default), the cert must be
      present in `AshPki.Certificate`. Set to `false` for endpoints that
      should accept any chain-valid client cert (e.g. enrollment).
    * `:on_failure` — `:halt_with_403` (default), `:assign_only`, or
      `{:halt_with, fn conn, reason -> conn end}`.
    * `:header_mode` — set to `{:enabled, header_name}` to read the cert
      from a header (PEM, URL-decoded) instead of the SSL connection. This
      is the LB-termination escape hatch and emits a single startup warning;
      only enable it on a network you fully control.

  ## Wiring

      plug AshPki.Plug.MTLS

  Or with options:

      plug AshPki.Plug.MTLS,
        require_known_certificate: false,
        header_mode: {:enabled, "x-client-cert"}
  """

  @behaviour Plug
  require Logger

  alias AshPki.PKI

  defmodule Actor do
    @moduledoc """
    The verified peer presented to Ash policies.

    `:certificate_id` is the row id when the cert is known to AshPki, or
    `nil` for chain-valid but unknown certs.
    """
    defstruct [
      :certificate_id,
      :issuer_id,
      :subject_dn,
      :serial,
      :fingerprint,
      :san,
      :pem,
      :raw_cert
    ]

    @type t :: %__MODULE__{
            certificate_id: String.t() | nil,
            issuer_id: String.t() | nil,
            subject_dn: String.t(),
            serial: String.t(),
            fingerprint: String.t(),
            san: [tuple()],
            pem: binary(),
            raw_cert: term()
          }
  end

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, opts) do
    require_known? = Keyword.get(opts, :require_known_certificate, true)
    trust_anchors_fun = Keyword.get(opts, :trust_anchors, &AshPki.TrustStore.trust_anchors/0)
    on_failure = Keyword.get(opts, :on_failure, :halt_with_403)
    header_mode = Keyword.get(opts, :header_mode, :disabled)

    with {:ok, peer_cert} <- read_peer_cert(conn, header_mode),
         trust_anchors <- trust_anchors_fun.(),
         {:ok, _chain} <- validate_chain(peer_cert, trust_anchors),
         {:ok, actor} <- build_actor(peer_cert, require_known?) do
      Plug.Conn.assign(conn, :ash_pki_actor, actor)
    else
      {:error, reason} -> handle_failure(conn, reason, on_failure)
    end
  end

  defp read_peer_cert(conn, :disabled) do
    case Plug.Conn.get_peer_data(conn) do
      %{ssl_cert: nil} -> {:error, :no_peer_certificate}
      %{ssl_cert: der} when is_binary(der) -> {:ok, :public_key.pkix_decode_cert(der, :otp)}
    end
  rescue
    error -> {:error, {:peer_cert_decode, error}}
  end

  defp read_peer_cert(conn, {:enabled, header}) do
    Logger.warning(
      "AshPki.Plug.MTLS reading client cert from header #{inspect(header)} — only safe behind a trusted TLS terminator"
    )

    case Plug.Conn.get_req_header(conn, header) do
      [pem | _] ->
        with pem <- URI.decode(pem),
             {:ok, cert} <- X509.Certificate.from_pem(pem) do
          {:ok, cert}
        else
          _ -> {:error, :invalid_header_pem}
        end

      _ ->
        {:error, :no_client_cert_header}
    end
  end

  defp validate_chain(_peer, []), do: {:error, :no_trust_anchors}

  defp validate_chain(peer, trust_anchors) do
    PKI.verify(peer, trust_anchors, [])
  end

  defp build_actor(peer, require_known?) do
    fingerprint = PKI.fingerprint(peer)
    pem = X509.Certificate.to_pem(peer)
    serial = PKI.serial_string(peer)
    subject = PKI.subject_string(peer)
    san = PKI.subject_alt_names(peer)

    base = %Actor{
      certificate_id: nil,
      issuer_id: nil,
      subject_dn: subject,
      serial: serial,
      fingerprint: fingerprint,
      san: san,
      pem: pem,
      raw_cert: peer
    }

    case AshPki.Certificate.get_by_fingerprint(fingerprint, authorize?: false) do
      {:ok, %AshPki.Certificate{status: :active} = cert} ->
        {:ok, %Actor{base | certificate_id: cert.id, issuer_id: cert.issuer_id}}

      {:ok, %AshPki.Certificate{status: status}} ->
        {:error, {:certificate_not_active, status}}

      {:error, _} when require_known? ->
        {:error, :certificate_not_on_file}

      {:error, _} ->
        {:ok, base}
    end
  end

  defp handle_failure(conn, reason, :assign_only) do
    Plug.Conn.assign(conn, :ash_pki_mtls_error, reason)
  end

  defp handle_failure(conn, reason, :halt_with_403) do
    body = Jason.encode!(%{error: "mtls_failed", reason: inspect(reason)})

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(403, body)
    |> Plug.Conn.halt()
  end

  defp handle_failure(conn, reason, {:halt_with, fun}) when is_function(fun, 2) do
    fun.(conn, reason)
  end
end
