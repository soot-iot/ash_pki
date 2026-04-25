defmodule AshPki.CertificateAuthority do
  @moduledoc """
  An issuing authority (root or intermediate).
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

    attribute :name, :string do
      allow_nil? false
      public? true
    end

    attribute :role, :atom do
      constraints one_of: [:root, :intermediate]
      allow_nil? false
      default :root
      public? true
    end

    attribute :parent_id, :uuid, public?: true

    attribute :key_strategy, :atom do
      constraints one_of: [:software, :pkcs11, :kms, :imported]
      default :software
      allow_nil? false
      public? true
    end

    attribute :key_descriptor, :map do
      sensitive? true
      public? false
      default %{}
    end

    attribute :certificate_pem, :string do
      allow_nil? true
      public? true
    end

    attribute :subject_dn, :string, public?: true
    attribute :serial, :string, public?: true
    attribute :fingerprint, :string, public?: true

    attribute :not_before, :utc_datetime_usec, public?: true
    attribute :not_after, :utc_datetime_usec, public?: true

    attribute :status, :atom do
      constraints one_of: [:active, :rotated, :revoked]
      default :active
      allow_nil? false
      public? true
    end

    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  relationships do
    belongs_to :parent, __MODULE__ do
      public? true
      attribute_writable? false
      destination_attribute :id
      source_attribute :parent_id
    end

    has_many :issued_certificates, AshPki.Certificate do
      destination_attribute :issuer_id
    end

    has_many :revocation_lists, AshPki.RevocationList do
      destination_attribute :ca_id
    end
  end

  actions do
    defaults [:read, :destroy]

    read :get_by_name do
      argument :name, :string, allow_nil?: false
      get? true
      filter expr(name == ^arg(:name))
    end

    create :create_root do
      description "Generate a fresh self-signed root CA."

      accept [:name, :key_strategy]

      argument :subject_dn, :string, allow_nil?: false
      argument :validity_days, :integer, default: 365 * 10
      argument :key_type, :atom, constraints: [one_of: [:ec, :rsa]], default: :ec
      argument :curve, :atom, default: :secp256r1
      argument :bits, :integer, default: 2048

      change AshPki.Changes.GenerateRootCA
    end

    create :create_intermediate do
      description "Generate an intermediate CA signed by an existing CA."

      accept [:name, :key_strategy]

      argument :parent_id, :uuid, allow_nil?: false
      argument :subject_dn, :string, allow_nil?: false
      argument :validity_days, :integer, default: 365 * 5
      argument :key_type, :atom, constraints: [one_of: [:ec, :rsa]], default: :ec
      argument :curve, :atom, default: :secp256r1
      argument :bits, :integer, default: 2048

      change AshPki.Changes.GenerateIntermediateCA
    end

    update :rotate do
      description "Mark this CA as rotated. Cross-signing is a follow-up step."
      accept []
      change set_attribute(:status, :rotated)
    end
  end

  code_interface do
    define :create_root, args: [:name, :subject_dn]
    define :create_intermediate, args: [:name, :parent_id, :subject_dn]
    define :get_by_name, args: [:name]
    define :rotate
  end
end
