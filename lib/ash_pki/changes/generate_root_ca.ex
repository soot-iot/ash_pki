defmodule AshPki.Changes.GenerateRootCA do
  @moduledoc false
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      strategy_name = Ash.Changeset.get_attribute(changeset, :key_strategy) || :software
      strategy = AshPki.key_strategy(strategy_name)

      subject_dn = Ash.Changeset.get_argument(changeset, :subject_dn)
      validity_days = Ash.Changeset.get_argument(changeset, :validity_days) || 365 * 10

      key_opts = [
        type: Ash.Changeset.get_argument(changeset, :key_type) || :ec,
        curve: Ash.Changeset.get_argument(changeset, :curve) || :secp256r1,
        bits: Ash.Changeset.get_argument(changeset, :bits) || 2048
      ]

      with {:ok, descriptor} <- strategy.generate(key_opts),
           {:ok, cert} <-
             strategy.self_sign(descriptor, subject_dn,
               template: :root_ca,
               validity_days: validity_days
             ) do
        cert_pem = X509.Certificate.to_pem(cert)
        fingerprint = AshPki.PKI.fingerprint(cert)
        serial = AshPki.PKI.serial_string(cert)
        {not_before, not_after} = AshPki.PKI.validity_window(cert)

        changeset
        |> Ash.Changeset.force_change_attribute(:key_descriptor, descriptor)
        |> Ash.Changeset.force_change_attribute(:certificate_pem, cert_pem)
        |> Ash.Changeset.force_change_attribute(:fingerprint, fingerprint)
        |> Ash.Changeset.force_change_attribute(:serial, serial)
        |> Ash.Changeset.force_change_attribute(:subject_dn, subject_dn)
        |> Ash.Changeset.force_change_attribute(:not_before, not_before)
        |> Ash.Changeset.force_change_attribute(:not_after, not_after)
        |> Ash.Changeset.force_change_attribute(:role, :root)
        |> Ash.Changeset.force_change_attribute(:status, :active)
      else
        {:error, reason} ->
          Ash.Changeset.add_error(changeset,
            field: :key_strategy,
            message: "failed to generate root CA: #{inspect(reason)}"
          )
      end
    end)
  end
end
