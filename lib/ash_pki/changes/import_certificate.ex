defmodule AshPki.Changes.ImportCertificate do
  @moduledoc false
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      cert_pem = Ash.Changeset.get_argument(changeset, :certificate_pem)
      issuer_id = Ash.Changeset.get_argument(changeset, :issuer_id)

      ca_module =
        AshPki.Resource.Certificate.Info.pki_certificate_authority!(changeset.resource)

      with {:ok, cert} <- X509.Certificate.from_pem(cert_pem),
           {:ok, issuer} <- Ash.get(ca_module, issuer_id, authorize?: false),
           {:ok, issuer_cert} <- X509.Certificate.from_pem(issuer.certificate_pem),
           :ok <- verify_chain(cert, issuer_cert) do
        fingerprint = AshPki.PKI.fingerprint(cert)
        serial = AshPki.PKI.serial_string(cert)
        subject = AshPki.PKI.subject_string(cert)
        {not_before, not_after} = AshPki.PKI.validity_window(cert)

        changeset
        |> Ash.Changeset.force_change_attribute(:issuer_id, issuer_id)
        |> Ash.Changeset.force_change_attribute(:certificate_pem, cert_pem)
        |> Ash.Changeset.force_change_attribute(:fingerprint, fingerprint)
        |> Ash.Changeset.force_change_attribute(:serial, serial)
        |> Ash.Changeset.force_change_attribute(:subject_dn, subject)
        |> Ash.Changeset.force_change_attribute(:not_before, not_before)
        |> Ash.Changeset.force_change_attribute(:not_after, not_after)
        |> Ash.Changeset.force_change_attribute(:status, :active)
        |> Ash.Changeset.force_change_attribute(:provenance, :imported)
      else
        {:error, reason} ->
          Ash.Changeset.add_error(changeset,
            field: :certificate_pem,
            message: "could not import certificate: #{inspect(reason)}"
          )
      end
    end)
  end

  defp verify_chain(leaf, issuer) do
    leaf_der = X509.Certificate.to_der(leaf)
    issuer_der = X509.Certificate.to_der(issuer)

    case :public_key.pkix_path_validation(issuer_der, [leaf_der], []) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, {:chain_invalid, reason}}
    end
  end
end
