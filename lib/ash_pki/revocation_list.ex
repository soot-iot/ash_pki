defmodule AshPki.RevocationList do
  @moduledoc """
  A signed CRL artifact for a CA.

  Each call to `publish/1` writes a new row with a fresh sequence number,
  marking earlier rows for the same CA as `:superseded`. The current row
  is what gets served at the CRL distribution point.
  """

  use Ash.Resource,
    otp_app: :ash_pki,
    domain: AshPki.Domain,
    data_layer: Ash.DataLayer.Ets

  ets do
    private? false
  end

  attributes do
    uuid_primary_key :id

    attribute :ca_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :sequence, :integer do
      allow_nil? false
      public? true
    end

    attribute :crl_pem, :string, public?: true
    attribute :this_update, :utc_datetime_usec, public?: true
    attribute :next_update, :utc_datetime_usec, public?: true

    attribute :status, :atom do
      constraints one_of: [:current, :superseded]
      default :current
      allow_nil? false
      public? true
    end

    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  relationships do
    belongs_to :ca, AshPki.CertificateAuthority do
      public? true
      destination_attribute :id
      source_attribute :ca_id
      attribute_writable? false
    end
  end

  actions do
    defaults [:read, :destroy]

    read :for_ca do
      argument :ca_id, :uuid, allow_nil?: false
      filter expr(ca_id == ^arg(:ca_id))
    end

    read :current_for_ca do
      argument :ca_id, :uuid, allow_nil?: false
      get? true
      filter expr(ca_id == ^arg(:ca_id) and status == :current)
      prepare build(sort: [sequence: :desc])
    end

    create :publish do
      description "Compute and sign a fresh CRL for a CA."
      accept []

      argument :ca_id, :uuid, allow_nil?: false
      argument :next_update_in_days, :integer, default: 7

      change AshPki.Changes.PublishCRL
    end

    update :supersede do
      accept []
      change set_attribute(:status, :superseded)
    end
  end

  code_interface do
    define :publish, args: [:ca_id]
    define :for_ca, args: [:ca_id]
    define :current_for_ca, args: [:ca_id]
    define :supersede
  end
end
