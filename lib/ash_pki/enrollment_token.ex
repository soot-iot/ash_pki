defmodule AshPki.EnrollmentToken do
  @moduledoc """
  Short-lived bootstrap credential.

  This resource ships the storage shape only. The device-side enrollment
  flow that consumes the token (verifying it, issuing an operational
  certificate, transitioning a device into service) lives in whatever
  IoT/application layer wraps `ash_pki`.

  The token is stored hashed. The plaintext is returned exactly once on
  the result of `mint/3` via Ash resource metadata:

      {:ok, token} = AshPki.EnrollmentToken.mint(:device, "serial-001", at)
      Ash.Resource.get_metadata(token, :plaintext_token)
      # => "..."  (URL-safe base64, 32 random bytes)

  The plaintext is never persisted; once the result is dropped it cannot
  be recovered.
  """

  use Ash.Resource,
    otp_app: :ash_pki,
    domain: AshPki.Domain,
    data_layer: Ash.DataLayer.Ets

  require Ash.Query

  ets do
    private? false
  end

  attributes do
    uuid_primary_key :id

    attribute :token_hash, :string do
      allow_nil? false
      public? false
      sensitive? true
    end

    attribute :scope, :atom do
      constraints one_of: [:device, :batch]
      default :device
      allow_nil? false
      public? true
    end

    attribute :scope_ref, :string do
      description "device serial or batch identifier"
      public? true
    end

    attribute :valid_until, :utc_datetime_usec do
      allow_nil? false
      public? true
    end

    attribute :used_at, :utc_datetime_usec, public?: true

    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  identities do
    identity :unique_token_hash, [:token_hash], pre_check_with: AshPki.Domain
  end

  actions do
    defaults [:read, :destroy]

    create :mint do
      description "Mint a new enrollment token. The plaintext is returned via Ash.Resource.get_metadata(record, :plaintext_token)."
      accept [:scope, :scope_ref, :valid_until]

      change AshPki.Changes.MintEnrollmentToken
    end

    update :consume do
      accept []
      require_atomic? false
      change set_attribute(:used_at, &DateTime.utc_now/0)
    end

    read :find_by_plaintext do
      argument :token, :string, allow_nil?: false
      get? true

      prepare fn query, _ ->
        plaintext = Ash.Query.get_argument(query, :token)
        hash = :crypto.hash(:sha256, plaintext) |> Base.encode16(case: :lower)
        Ash.Query.filter(query, token_hash == ^hash)
      end
    end
  end

  code_interface do
    define :mint, args: [:scope, :scope_ref, :valid_until]
    define :consume
    define :find_by_plaintext, args: [:token]
  end
end
