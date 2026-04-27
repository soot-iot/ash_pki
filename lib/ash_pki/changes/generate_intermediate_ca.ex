defmodule AshPki.Changes.GenerateIntermediateCA do
  @moduledoc false
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      strategy_name = Ash.Changeset.get_attribute(changeset, :key_strategy) || :software
      strategy = AshPki.key_strategy(strategy_name)

      parent_id = Ash.Changeset.get_argument(changeset, :parent_id)
      subject_dn = Ash.Changeset.get_argument(changeset, :subject_dn)
      validity_days = Ash.Changeset.get_argument(changeset, :validity_days) || 365 * 5

      key_opts = [
        type: Ash.Changeset.get_argument(changeset, :key_type) || :ec,
        curve: Ash.Changeset.get_argument(changeset, :curve) || :secp256r1,
        bits: Ash.Changeset.get_argument(changeset, :bits) || 2048
      ]

      with {:ok, parent} <- Ash.get(changeset.resource, parent_id, authorize?: false),
           {:ok, descriptor} <- strategy.generate(key_opts),
           {:ok, intermediate_private} <- private_key_from_descriptor(strategy, descriptor),
           {:ok, parent_cert} <- decode_cert(parent.certificate_pem),
           parent_strategy <- AshPki.key_strategy(parent.key_strategy),
           csr <- X509.CSR.new(intermediate_private, subject_dn),
           {:ok, cert} <-
             parent_strategy.sign_csr(parent.key_descriptor, csr, parent_cert,
               template: :ca,
               validity_days: validity_days
             ) do
        cert_pem = X509.Certificate.to_pem(cert)
        fingerprint = AshPki.PKI.fingerprint(cert)
        serial = AshPki.PKI.serial_string(cert)
        {not_before, not_after} = AshPki.PKI.validity_window(cert)

        changeset
        |> Ash.Changeset.force_change_attribute(:parent_id, parent_id)
        |> Ash.Changeset.force_change_attribute(:key_descriptor, descriptor)
        |> Ash.Changeset.force_change_attribute(:certificate_pem, cert_pem)
        |> Ash.Changeset.force_change_attribute(:fingerprint, fingerprint)
        |> Ash.Changeset.force_change_attribute(:serial, serial)
        |> Ash.Changeset.force_change_attribute(:subject_dn, subject_dn)
        |> Ash.Changeset.force_change_attribute(:not_before, not_before)
        |> Ash.Changeset.force_change_attribute(:not_after, not_after)
        |> Ash.Changeset.force_change_attribute(:role, :intermediate)
        |> Ash.Changeset.force_change_attribute(:status, :active)
      else
        {:error, reason} ->
          Ash.Changeset.add_error(changeset,
            field: :parent_id,
            message: "failed to generate intermediate CA: #{inspect(reason)}"
          )
      end
    end)
  end

  defp private_key_from_descriptor(AshPki.KeyStrategy.Software, descriptor),
    do: AshPki.KeyStrategy.Software.private_key(descriptor)

  defp private_key_from_descriptor(_strategy, _descriptor),
    do: {:error, :only_software_intermediates_supported_in_v1}

  defp decode_cert(pem), do: X509.Certificate.from_pem(pem)
end
