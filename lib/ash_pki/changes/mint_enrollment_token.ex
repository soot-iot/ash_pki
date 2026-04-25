defmodule AshPki.Changes.MintEnrollmentToken do
  @moduledoc false
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    plaintext = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    hash = :crypto.hash(:sha256, plaintext) |> Base.encode16(case: :lower)

    changeset
    |> Ash.Changeset.force_change_attribute(:token_hash, hash)
    |> Ash.Changeset.after_action(fn _changeset, record ->
      {:ok, Ash.Resource.put_metadata(record, :plaintext_token, plaintext)}
    end)
  end
end
