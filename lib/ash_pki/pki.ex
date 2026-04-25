defmodule AshPki.PKI do
  @moduledoc """
  Pure helpers for X.509 certificate inspection and trust chain assembly.

  Resource actions and the mTLS plug share these primitives so encoding
  decisions (PEM vs DER, hex vs colon-separated fingerprint, etc.) live in
  one place.
  """

  @typedoc "PEM-encoded certificate string"
  @type pem :: binary()

  @doc """
  Hex-encoded SHA-256 fingerprint of a certificate's DER form (lowercase).
  """
  @spec fingerprint(X509.Certificate.t()) :: String.t()
  def fingerprint(otp_cert) do
    otp_cert
    |> X509.Certificate.to_der()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  @spec fingerprint_pem(pem()) :: {:ok, String.t()} | {:error, term()}
  def fingerprint_pem(pem) do
    with {:ok, cert} <- X509.Certificate.from_pem(pem) do
      {:ok, fingerprint(cert)}
    end
  end

  @doc "Decimal-string serial number of an OTPCertificate."
  @spec serial_string(X509.Certificate.t()) :: String.t()
  def serial_string(otp_cert) do
    otp_cert |> X509.Certificate.serial() |> Integer.to_string()
  end

  @doc """
  Stringify the subject RDN of a certificate as `/C=US/O=ACME/CN=...`.
  """
  @spec subject_string(X509.Certificate.t()) :: String.t()
  def subject_string(otp_cert) do
    otp_cert
    |> X509.Certificate.subject()
    |> X509.RDNSequence.to_string()
  end

  @doc """
  Parse a PEM bundle and return the leaf followed by intermediates and root,
  in the order they appear in the bundle.
  """
  @spec parse_chain(pem()) :: {:ok, [X509.Certificate.t()]} | {:error, term()}
  def parse_chain(pem) do
    pem
    |> :public_key.pem_decode()
    |> Enum.filter(fn
      {:Certificate, _der, _} -> true
      _ -> false
    end)
    |> case do
      [] ->
        {:error, :no_certificates}

      entries ->
        certs =
          Enum.map(entries, fn {:Certificate, der, _} ->
            :public_key.pkix_decode_cert(der, :otp)
          end)

        {:ok, certs}
    end
  end

  @doc """
  Extract Subject Alternative Names (DNS, URI, IP, email) from a cert.
  """
  @spec subject_alt_names(X509.Certificate.t()) :: [tuple()]
  def subject_alt_names(otp_cert) do
    case X509.Certificate.extension(otp_cert, :subject_alt_name) do
      nil ->
        []

      ext ->
        # Extension record { Extension, oid, critical, value }
        # value for SAN is the list of tuples already
        extract_san_value(ext)
    end
  end

  defp extract_san_value(ext) do
    # ext is the OTP record Extension with extnValue as a list of tuples
    # { :Extension, oid, critical, value }
    case ext do
      {:Extension, _oid, _critical, value} when is_list(value) -> value
      {:Extension, _oid, _critical, _other} -> []
      _ -> []
    end
  end

  @doc """
  Validity tuple as `{not_before :: DateTime.t(), not_after :: DateTime.t()}`.
  """
  @spec validity_window(X509.Certificate.t()) :: {DateTime.t(), DateTime.t()}
  def validity_window(otp_cert) do
    validity = X509.Certificate.validity(otp_cert)

    # Validity is the OTP record { :Validity, not_before, not_after }
    case validity do
      {:Validity, not_before, not_after} ->
        {parse_validity_time(not_before), parse_validity_time(not_after)}
    end
  end

  defp parse_validity_time({:utcTime, charlist}), do: from_asn1_time(charlist, :utc)
  defp parse_validity_time({:generalTime, charlist}), do: from_asn1_time(charlist, :general)
  defp parse_validity_time({:utcTime, charlist, _}), do: from_asn1_time(charlist, :utc)

  defp from_asn1_time(charlist, kind) do
    str = List.to_string(charlist)

    case kind do
      :utc ->
        # YYMMDDHHMMSSZ
        <<yy::binary-size(2), mm::binary-size(2), dd::binary-size(2), h::binary-size(2),
          mi::binary-size(2), s::binary-size(2), _::binary>> = str

        year =
          case String.to_integer(yy) do
            n when n >= 50 -> 1900 + n
            n -> 2000 + n
          end

        {:ok, dt, _} =
          DateTime.from_iso8601(
            "#{year}-#{mm}-#{dd}T#{h}:#{mi}:#{s}Z"
          )

        dt

      :general ->
        # YYYYMMDDHHMMSSZ
        <<yyyy::binary-size(4), mm::binary-size(2), dd::binary-size(2), h::binary-size(2),
          mi::binary-size(2), s::binary-size(2), _::binary>> = str

        {:ok, dt, _} =
          DateTime.from_iso8601(
            "#{yyyy}-#{mm}-#{dd}T#{h}:#{mi}:#{s}Z"
          )

        dt
    end
  end

  @doc """
  Verify a leaf cert against a list of trusted root OTPCertificates.

  Returns `{:ok, chain}` where `chain` is the verified chain (root last),
  or `{:error, reason}`.

  `intermediates` is a (possibly empty) list of OTPCertificate that the
  caller has reason to believe could appear between leaf and root.
  """
  @spec verify(X509.Certificate.t(), [X509.Certificate.t()], [X509.Certificate.t()]) ::
          {:ok, [X509.Certificate.t()]} | {:error, term()}
  def verify(leaf, trusted_roots, intermediates \\ [])

  def verify(_leaf, [], _intermediates), do: {:error, :no_trusted_roots}

  def verify(leaf, trusted_roots, intermediates) do
    leaf_der = X509.Certificate.to_der(leaf)
    intermediate_ders = Enum.map(intermediates, &X509.Certificate.to_der/1)
    chain_ders = intermediate_ders ++ [leaf_der]
    trusted_ders = Enum.map(trusted_roots, &X509.Certificate.to_der/1)

    case :public_key.pkix_path_validation(hd(trusted_ders), chain_ders, []) do
      {:ok, _} ->
        # Try with each trusted root if the first didn't sign anything in the chain.
        {:ok, [leaf | intermediates] ++ [hd(trusted_roots)]}

      {:error, _reason} ->
        try_each_root(leaf, leaf_der, trusted_roots, intermediate_ders)
    end
  end

  defp try_each_root(_leaf, _leaf_der, [], _intermediates),
    do: {:error, :path_validation_failed}

  defp try_each_root(leaf, leaf_der, [root | rest], intermediates) do
    root_der = X509.Certificate.to_der(root)

    case :public_key.pkix_path_validation(root_der, intermediates ++ [leaf_der], []) do
      {:ok, _} ->
        {:ok, build_chain(leaf, intermediates, root)}

      {:error, _} ->
        try_each_root(leaf, leaf_der, rest, intermediates)
    end
  end

  defp build_chain(leaf, intermediate_ders, root) do
    intermediates = Enum.map(intermediate_ders, &:public_key.pkix_decode_cert(&1, :otp))
    [leaf | intermediates] ++ [root]
  end
end
