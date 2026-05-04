defmodule AshPki.Resource.Certificate.Transformers.Inject do
  @moduledoc false
  use Spark.Dsl.Transformer

  alias Ash.Resource.Builder
  alias AshPki.Resource.Certificate.Preparations
  alias Spark.Dsl.Transformer

  @revocation_reasons [
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

  # Run before the belongs_to attribute synthesizer; we declare
  # `:issuer_id` ourselves and pass `define_attribute?: false`.
  @impl true
  def before?(Ash.Resource.Transformers.BelongsToAttribute), do: true
  def before?(_), do: false

  @impl true
  def transform(dsl_state) do
    issuer_module =
      Spark.Dsl.Extension.get_opt(
        dsl_state,
        [:pki],
        :certificate_authority,
        AshPki.CertificateAuthority
      )

    domain = Transformer.get_persisted(dsl_state, :domain) || domain_from_dsl(dsl_state)

    with {:ok, dsl_state} <- add_attributes(dsl_state),
         {:ok, dsl_state} <- add_identities(dsl_state, domain),
         {:ok, dsl_state} <- add_relationships(dsl_state, issuer_module),
         {:ok, dsl_state} <- add_actions(dsl_state) do
      add_code_interface(dsl_state)
    end
  end

  defp domain_from_dsl(dsl_state) do
    Transformer.get_option(dsl_state, [:resource], :domain)
  end

  defp add_attributes(dsl_state) do
    with {:ok, dsl_state} <- ensure_uuid_primary_key(dsl_state),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :issuer_id, :uuid, public?: true),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :csr_pem, :string,
             public?: false,
             sensitive?: true
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :certificate_pem, :string, public?: true),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :subject_dn, :string, public?: true),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :serial, :string, public?: true),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :fingerprint, :string, public?: true),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :not_before, :utc_datetime_usec, public?: true),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :not_after, :utc_datetime_usec, public?: true),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :status, :atom,
             constraints: [one_of: [:active, :revoked, :expired]],
             default: :active,
             allow_nil?: false,
             public?: true
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :revocation_reason, :atom,
             constraints: [one_of: @revocation_reasons],
             public?: true
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :revoked_at, :utc_datetime_usec, public?: true),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :provenance, :atom,
             constraints: [one_of: [:issued, :imported]],
             default: :issued,
             allow_nil?: false,
             public?: true,
             description: "Whether this row was minted by `issue` or by `import_certificate`."
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :metadata, :map, public?: true, default: %{}),
         {:ok, dsl_state} <- Builder.add_new_create_timestamp(dsl_state, :inserted_at) do
      Builder.add_new_update_timestamp(dsl_state, :updated_at)
    end
  end

  defp ensure_uuid_primary_key(dsl_state) do
    if Ash.Resource.Info.attribute(dsl_state, :id) do
      {:ok, dsl_state}
    else
      Builder.add_new_attribute(dsl_state, :id, :uuid,
        primary_key?: true,
        allow_nil?: false,
        public?: true,
        default: &Ash.UUID.generate/0,
        match_other_defaults?: true
      )
    end
  end

  defp add_identities(dsl_state, domain) do
    with {:ok, dsl_state} <-
           Builder.add_new_identity(dsl_state, :unique_fingerprint, [:fingerprint],
             pre_check_with: domain
           ) do
      Builder.add_new_identity(
        dsl_state,
        :unique_serial_per_issuer,
        [:issuer_id, :serial],
        pre_check_with: domain
      )
    end
  end

  defp add_relationships(dsl_state, issuer_module) do
    Builder.add_new_relationship(dsl_state, :belongs_to, :issuer, issuer_module,
      public?: true,
      attribute_writable?: false,
      destination_attribute: :id,
      source_attribute: :issuer_id,
      define_attribute?: false
    )
  end

  defp add_actions(dsl_state) do
    with {:ok, dsl_state} <- Builder.add_new_action(dsl_state, :read, :read, primary?: true),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :destroy, :destroy, primary?: true),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :read, :get_by_fingerprint,
             arguments: [
               Builder.build_action_argument(:fingerprint, :string, allow_nil?: false)
             ],
             get?: true,
             preparations: [Builder.build_preparation(Preparations.ByFingerprint)]
           ),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :read, :get_by_serial,
             arguments: [
               Builder.build_action_argument(:serial, :string, allow_nil?: false),
               Builder.build_action_argument(:issuer_id, :uuid, allow_nil?: false)
             ],
             get?: true,
             preparations: [Builder.build_preparation(Preparations.BySerial)]
           ),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :read, :active_for_issuer,
             arguments: [
               Builder.build_action_argument(:issuer_id, :uuid, allow_nil?: false)
             ],
             preparations: [Builder.build_preparation(Preparations.ActiveForIssuer)]
           ),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :read, :revoked_for_issuer,
             arguments: [
               Builder.build_action_argument(:issuer_id, :uuid, allow_nil?: false)
             ],
             preparations: [Builder.build_preparation(Preparations.RevokedForIssuer)]
           ),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :create, :issue,
             description: "Issue a certificate by signing a CSR with a CA's key.",
             accept: [:metadata],
             arguments: [
               Builder.build_action_argument(:issuer_id, :uuid, allow_nil?: false),
               Builder.build_action_argument(:csr_pem, :string, allow_nil?: false),
               Builder.build_action_argument(:template, :atom, default: :client),
               Builder.build_action_argument(:validity_days, :integer, default: 90),
               Builder.build_action_argument(:subject_alt_names, {:array, :term}, default: [])
             ],
             changes: [
               Builder.build_action_change(AshPki.Changes.IssueCertificate)
             ]
           ),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :create, :import_certificate,
             description: "Import a pre-issued certificate (e.g. from a pre-provisioned device).",
             accept: [:metadata],
             arguments: [
               Builder.build_action_argument(:issuer_id, :uuid, allow_nil?: false),
               Builder.build_action_argument(:certificate_pem, :string, allow_nil?: false)
             ],
             changes: [
               Builder.build_action_change(AshPki.Changes.ImportCertificate)
             ]
           ) do
      Builder.add_new_action(dsl_state, :update, :revoke,
        description: "Mark a certificate revoked. CRL regeneration is a separate step.",
        accept: [],
        # require_atomic?: false because:
        #   1. the revoked_at SetAttribute uses a function closure
        #      (&DateTime.utc_now/0), and
        #   2. the policy authorizer injects a :before_action hook,
        #      which independently disqualifies atomic execution.
        require_atomic?: false,
        arguments: [
          Builder.build_action_argument(:reason, :atom,
            constraints: [one_of: @revocation_reasons],
            default: :unspecified
          )
        ],
        changes: [
          Builder.build_action_change(
            {Ash.Resource.Change.SetAttribute, attribute: :status, value: :revoked}
          ),
          Builder.build_action_change(
            {Ash.Resource.Change.SetAttribute,
             attribute: :revocation_reason, value: {:_arg, :reason}}
          ),
          Builder.build_action_change(
            {Ash.Resource.Change.SetAttribute, attribute: :revoked_at, value: &DateTime.utc_now/0}
          )
        ]
      )
    end
  end

  defp add_code_interface(dsl_state) do
    with {:ok, dsl_state} <-
           Builder.add_new_interface(dsl_state, :issue, args: [:issuer_id, :csr_pem]),
         {:ok, dsl_state} <-
           Builder.add_new_interface(dsl_state, :import_certificate,
             args: [:issuer_id, :certificate_pem]
           ),
         {:ok, dsl_state} <- Builder.add_new_interface(dsl_state, :revoke),
         {:ok, dsl_state} <-
           Builder.add_new_interface(dsl_state, :get_by_fingerprint, args: [:fingerprint]),
         {:ok, dsl_state} <-
           Builder.add_new_interface(dsl_state, :get_by_serial, args: [:serial, :issuer_id]),
         {:ok, dsl_state} <-
           Builder.add_new_interface(dsl_state, :active_for_issuer, args: [:issuer_id]) do
      Builder.add_new_interface(dsl_state, :revoked_for_issuer, args: [:issuer_id])
    end
  end
end
