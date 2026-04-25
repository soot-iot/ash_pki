defmodule AshPki.Changes.IssueCertificate do
  @moduledoc false
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      issuer_id = Ash.Changeset.get_argument(changeset, :issuer_id)
      csr_pem = Ash.Changeset.get_argument(changeset, :csr_pem)
      template_arg = Ash.Changeset.get_argument(changeset, :template) || :client
      template = resolve_template(template_arg)
      validity_days = Ash.Changeset.get_argument(changeset, :validity_days) || 90
      san_overrides = Ash.Changeset.get_argument(changeset, :subject_alt_names) || []

      with {:ok, issuer} <-
             Ash.get(AshPki.CertificateAuthority, issuer_id, authorize?: false),
           :ok <- ensure_active(issuer),
           {:ok, csr} <- decode_csr(csr_pem),
           true <- X509.CSR.valid?(csr) || {:error, :invalid_csr_signature},
           {:ok, issuer_cert} <- X509.Certificate.from_pem(issuer.certificate_pem),
           strategy <- AshPki.key_strategy(issuer.key_strategy),
           extensions <- build_extensions(san_overrides),
           {:ok, cert} <-
             strategy.sign_csr(issuer.key_descriptor, csr, issuer_cert,
               template: template,
               validity_days: validity_days,
               extensions: extensions
             ) do
        cert_pem = X509.Certificate.to_pem(cert)
        fingerprint = AshPki.PKI.fingerprint(cert)
        serial = AshPki.PKI.serial_string(cert)
        subject = AshPki.PKI.subject_string(cert)
        {not_before, not_after} = AshPki.PKI.validity_window(cert)

        changeset
        |> Ash.Changeset.force_change_attribute(:issuer_id, issuer_id)
        |> Ash.Changeset.force_change_attribute(:csr_pem, csr_pem)
        |> Ash.Changeset.force_change_attribute(:certificate_pem, cert_pem)
        |> Ash.Changeset.force_change_attribute(:fingerprint, fingerprint)
        |> Ash.Changeset.force_change_attribute(:serial, serial)
        |> Ash.Changeset.force_change_attribute(:subject_dn, subject)
        |> Ash.Changeset.force_change_attribute(:not_before, not_before)
        |> Ash.Changeset.force_change_attribute(:not_after, not_after)
        |> Ash.Changeset.force_change_attribute(:status, :active)
        |> Ash.Changeset.force_change_attribute(:key_strategy, :software)
      else
        {:error, reason} ->
          Ash.Changeset.add_error(changeset,
            field: :csr_pem,
            message: "failed to issue certificate: #{inspect(reason)}"
          )
      end
    end)
  end

  defp ensure_active(%AshPki.CertificateAuthority{status: :active}), do: :ok

  defp ensure_active(%AshPki.CertificateAuthority{status: status}),
    do: {:error, {:ca_not_active, status}}

  defp decode_csr(pem) when is_binary(pem) do
    case X509.CSR.from_pem(pem) do
      {:ok, csr} -> {:ok, csr}
      {:error, reason} -> {:error, {:invalid_csr_pem, reason}}
    end
  end

  defp decode_csr(_), do: {:error, :missing_csr_pem}

  defp build_extensions([]), do: []

  defp build_extensions(sans) do
    san_entries =
      Enum.map(sans, fn
        {:dns, dns} -> dns
        {:uri, uri} -> {:uniformResourceIdentifier, to_charlist(uri)}
        {:ip, ip} -> {:iPAddress, ip_to_charlist(ip)}
        bin when is_binary(bin) -> bin
      end)

    [subject_alt_name: X509.Certificate.Extension.subject_alt_name(san_entries)]
  end

  defp ip_to_charlist({a, b, c, d}), do: [a, b, c, d]
  defp ip_to_charlist(other), do: other

  # `:client` isn't a built-in template in the X509 library; build one that
  # produces a leaf cert with `clientAuth` (and `serverAuth` for devices that
  # also act as servers). For everything else, defer to the library defaults.
  defp resolve_template(:client) do
    %X509.Certificate.Template{
      validity: 90,
      hash: :sha256,
      extensions: [
        basic_constraints: X509.Certificate.Extension.basic_constraints(false),
        key_usage: X509.Certificate.Extension.key_usage([:digitalSignature, :keyEncipherment]),
        ext_key_usage: X509.Certificate.Extension.ext_key_usage([:clientAuth, :serverAuth]),
        subject_key_identifier: true,
        authority_key_identifier: true
      ]
    }
  end

  defp resolve_template(other), do: other
end
