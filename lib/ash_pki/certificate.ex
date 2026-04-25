defmodule AshPki.Certificate do
  @moduledoc """
  An issued or imported leaf certificate.
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

    attribute :issuer_id, :uuid, public?: true

    attribute :csr_pem, :string do
      public? false
      sensitive? true
    end

    attribute :certificate_pem, :string do
      public? true
    end

    attribute :subject_dn, :string, public?: true
    attribute :serial, :string, public?: true
    attribute :fingerprint, :string, public?: true

    attribute :not_before, :utc_datetime_usec, public?: true
    attribute :not_after, :utc_datetime_usec, public?: true

    attribute :status, :atom do
      constraints one_of: [:active, :revoked, :expired]
      default :active
      allow_nil? false
      public? true
    end

    attribute :revocation_reason, :atom do
      constraints one_of: [
                    :unspecified,
                    :key_compromise,
                    :ca_compromise,
                    :affiliation_changed,
                    :superseded,
                    :cessation_of_operation,
                    :certificate_hold,
                    :privilege_withdrawn,
                    :aa_compromise
                  ]

      public? true
    end

    attribute :revoked_at, :utc_datetime_usec, public?: true

    attribute :key_strategy, :atom do
      constraints one_of: [:software, :pkcs11, :kms, :imported]
      default :software
      public? true
    end

    attribute :metadata, :map, public?: true, default: %{}

    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  identities do
    identity :unique_fingerprint, [:fingerprint], pre_check_with: AshPki.Domain
    identity :unique_serial_per_issuer, [:issuer_id, :serial], pre_check_with: AshPki.Domain
  end

  relationships do
    belongs_to :issuer, AshPki.CertificateAuthority do
      public? true
      attribute_writable? false
      destination_attribute :id
      source_attribute :issuer_id
    end
  end

  actions do
    defaults [:read, :destroy]

    read :get_by_fingerprint do
      argument :fingerprint, :string, allow_nil?: false
      get? true
      filter expr(fingerprint == ^arg(:fingerprint))
    end

    read :get_by_serial do
      argument :serial, :string, allow_nil?: false
      argument :issuer_id, :uuid, allow_nil?: false
      get? true
      filter expr(serial == ^arg(:serial) and issuer_id == ^arg(:issuer_id))
    end

    read :active_for_issuer do
      argument :issuer_id, :uuid, allow_nil?: false
      filter expr(issuer_id == ^arg(:issuer_id) and status == :active)
    end

    read :revoked_for_issuer do
      argument :issuer_id, :uuid, allow_nil?: false
      filter expr(issuer_id == ^arg(:issuer_id) and status == :revoked)
    end

    create :issue do
      description "Issue a certificate by signing a CSR with a CA's key."

      accept [:metadata]
      argument :issuer_id, :uuid, allow_nil?: false
      argument :csr_pem, :string, allow_nil?: false
      argument :template, :atom, default: :client
      argument :validity_days, :integer, default: 90
      argument :subject_alt_names, {:array, :term}, default: []

      change AshPki.Changes.IssueCertificate
    end

    create :import_certificate do
      description "Import a pre-issued certificate (e.g. from a pre-provisioned device)."

      accept [:metadata]
      argument :issuer_id, :uuid, allow_nil?: false
      argument :certificate_pem, :string, allow_nil?: false

      change AshPki.Changes.ImportCertificate
    end

    update :revoke do
      description "Mark a certificate revoked. CRL regeneration is a separate step."
      accept []
      require_atomic? false

      argument :reason, :atom do
        constraints one_of: [
                      :unspecified,
                      :key_compromise,
                      :ca_compromise,
                      :affiliation_changed,
                      :superseded,
                      :cessation_of_operation,
                      :certificate_hold,
                      :privilege_withdrawn,
                      :aa_compromise
                    ]

        default :unspecified
      end

      change set_attribute(:status, :revoked)
      change set_attribute(:revocation_reason, arg(:reason))
      change set_attribute(:revoked_at, &DateTime.utc_now/0)
    end
  end

  code_interface do
    define :issue, args: [:issuer_id, :csr_pem]
    define :import_certificate, args: [:issuer_id, :certificate_pem]
    define :revoke
    define :get_by_fingerprint, args: [:fingerprint]
    define :get_by_serial, args: [:serial, :issuer_id]
    define :active_for_issuer, args: [:issuer_id]
    define :revoked_for_issuer, args: [:issuer_id]
  end
end
