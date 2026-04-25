defmodule AshPki.Changes.PublishCRL do
  @moduledoc false
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      ca_id = Ash.Changeset.get_argument(changeset, :ca_id)
      next_update_in_days = Ash.Changeset.get_argument(changeset, :next_update_in_days) || 7

      with {:ok, ca} <-
             Ash.get(AshPki.CertificateAuthority, ca_id, authorize?: false),
           {:ok, issuer_cert} <- X509.Certificate.from_pem(ca.certificate_pem),
           {:ok, revoked} <- AshPki.Certificate.revoked_for_issuer(ca_id, authorize?: false),
           strategy <- AshPki.key_strategy(ca.key_strategy),
           entries <- Enum.map(revoked, &build_entry/1),
           {:ok, crl} <-
             strategy.sign_crl(ca.key_descriptor, issuer_cert, entries,
               next_update_in_days: next_update_in_days
             ) do
        sequence = next_sequence(ca_id)

        changeset
        |> Ash.Changeset.force_change_attribute(:ca_id, ca_id)
        |> Ash.Changeset.force_change_attribute(:sequence, sequence)
        |> Ash.Changeset.force_change_attribute(:crl_pem, X509.CRL.to_pem(crl))
        |> Ash.Changeset.force_change_attribute(:this_update, X509.CRL.this_update(crl))
        |> Ash.Changeset.force_change_attribute(:next_update, X509.CRL.next_update(crl))
        |> Ash.Changeset.force_change_attribute(:status, :current)
        |> Ash.Changeset.after_action(fn _changeset, record ->
          supersede_previous(ca_id, record.id)
          {:ok, record}
        end)
      else
        {:error, reason} ->
          Ash.Changeset.add_error(changeset,
            field: :ca_id,
            message: "failed to publish CRL: #{inspect(reason)}"
          )
      end
    end)
  end

  defp build_entry(%AshPki.Certificate{
         serial: serial,
         revoked_at: revoked_at,
         revocation_reason: reason
       }) do
    revoked_at = revoked_at || DateTime.utc_now()
    serial_int = String.to_integer(serial)

    extensions =
      case to_x509_reason(reason) do
        nil -> []
        atom -> [X509.CRL.Extension.reason_code(atom)]
      end

    X509.CRL.Entry.new(serial_int, revoked_at, extensions)
  end

  # AshPki uses snake_case reason atoms; X509 / RFC 5280 enum identifiers are camelCase.
  defp to_x509_reason(nil), do: nil
  defp to_x509_reason(:unspecified), do: nil
  defp to_x509_reason(:key_compromise), do: :keyCompromise
  defp to_x509_reason(:ca_compromise), do: :cACompromise
  defp to_x509_reason(:affiliation_changed), do: :affiliationChanged
  defp to_x509_reason(:superseded), do: :superseded
  defp to_x509_reason(:cessation_of_operation), do: :cessationOfOperation
  defp to_x509_reason(:certificate_hold), do: :certificateHold
  defp to_x509_reason(:privilege_withdrawn), do: :privilegeWithdrawn
  defp to_x509_reason(:aa_compromise), do: :aACompromise

  defp next_sequence(ca_id) do
    {:ok, all} = AshPki.RevocationList.for_ca(ca_id, authorize?: false)

    case Enum.map(all, & &1.sequence) do
      [] -> 1
      seqs -> Enum.max(seqs) + 1
    end
  end

  defp supersede_previous(ca_id, current_id) do
    {:ok, all} = AshPki.RevocationList.for_ca(ca_id, authorize?: false)

    Enum.each(all, fn rl ->
      if rl.id != current_id and rl.status == :current do
        AshPki.RevocationList.supersede!(rl, authorize?: false)
      end
    end)
  end
end
