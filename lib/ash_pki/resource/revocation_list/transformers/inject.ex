defmodule AshPki.Resource.RevocationList.Transformers.Inject do
  @moduledoc false
  use Spark.Dsl.Transformer

  alias Ash.Resource.Builder
  alias AshPki.Resource.RevocationList.Preparations
  alias Spark.Dsl.Transformer

  @impl true
  def before?(Ash.Resource.Transformers.BelongsToAttribute), do: true
  def before?(_), do: false

  @impl true
  def transform(dsl_state) do
    ca_module =
      Spark.Dsl.Extension.get_opt(
        dsl_state,
        [:pki],
        :certificate_authority,
        AshPki.CertificateAuthority
      )

    domain = Transformer.get_persisted(dsl_state, :domain) || domain_from_dsl(dsl_state)

    with {:ok, dsl_state} <- add_attributes(dsl_state),
         {:ok, dsl_state} <- add_identities(dsl_state, domain),
         {:ok, dsl_state} <- add_relationships(dsl_state, ca_module),
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
           Builder.add_new_attribute(dsl_state, :ca_id, :uuid,
             allow_nil?: false,
             public?: true
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :sequence, :integer,
             allow_nil?: false,
             public?: true
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :crl_pem, :string, public?: true),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :this_update, :utc_datetime_usec, public?: true),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :next_update, :utc_datetime_usec, public?: true),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :status, :atom,
             constraints: [one_of: [:current, :superseded]],
             default: :current,
             allow_nil?: false,
             public?: true
           ),
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
    Builder.add_new_identity(dsl_state, :unique_ca_sequence, [:ca_id, :sequence],
      pre_check_with: domain
    )
  end

  defp add_relationships(dsl_state, ca_module) do
    Builder.add_new_relationship(dsl_state, :belongs_to, :ca, ca_module,
      public?: true,
      destination_attribute: :id,
      source_attribute: :ca_id,
      attribute_writable?: false,
      define_attribute?: false
    )
  end

  defp add_actions(dsl_state) do
    with {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :read, :read, primary?: true),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :destroy, :destroy, primary?: true),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :read, :for_ca,
             arguments: [
               Builder.build_action_argument(:ca_id, :uuid, allow_nil?: false)
             ],
             preparations: [Builder.build_preparation(Preparations.ForCa)]
           ),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :read, :current_for_ca,
             arguments: [
               Builder.build_action_argument(:ca_id, :uuid, allow_nil?: false)
             ],
             get?: true,
             preparations: [Builder.build_preparation(Preparations.CurrentForCa)]
           ),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :create, :publish,
             description: "Compute and sign a fresh CRL for a CA.",
             accept: [],
             arguments: [
               Builder.build_action_argument(:ca_id, :uuid, allow_nil?: false),
               Builder.build_action_argument(:next_update_in_days, :integer, default: 7)
             ],
             changes: [Builder.build_action_change(AshPki.Changes.PublishCRL)]
           ) do
      Builder.add_new_action(dsl_state, :update, :supersede,
        accept: [],
        require_atomic?: false,
        changes: [
          Builder.build_action_change(
            {Ash.Resource.Change.SetAttribute, attribute: :status, value: :superseded}
          )
        ]
      )
    end
  end

  defp add_code_interface(dsl_state) do
    with {:ok, dsl_state} <-
           Builder.add_new_interface(dsl_state, :publish, args: [:ca_id]),
         {:ok, dsl_state} <-
           Builder.add_new_interface(dsl_state, :for_ca, args: [:ca_id]),
         {:ok, dsl_state} <-
           Builder.add_new_interface(dsl_state, :current_for_ca, args: [:ca_id]) do
      Builder.add_new_interface(dsl_state, :supersede)
    end
  end
end
