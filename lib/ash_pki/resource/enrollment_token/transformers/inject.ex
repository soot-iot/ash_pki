defmodule AshPki.Resource.EnrollmentToken.Transformers.Inject do
  @moduledoc false
  use Spark.Dsl.Transformer

  alias Ash.Resource.Builder
  alias AshPki.Resource.EnrollmentToken.Preparations
  alias Spark.Dsl.Transformer

  @impl true
  def before?(Ash.Resource.Transformers.CachePrimaryKey), do: true
  def before?(_), do: false

  @impl true
  def transform(dsl_state) do
    domain = Transformer.get_persisted(dsl_state, :domain) || domain_from_dsl(dsl_state)

    with {:ok, dsl_state} <- add_attributes(dsl_state),
         {:ok, dsl_state} <- add_identities(dsl_state, domain),
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
           Builder.add_new_attribute(dsl_state, :token_hash, :string,
             allow_nil?: false,
             public?: false,
             sensitive?: true
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :scope, :atom,
             constraints: [one_of: [:device, :batch]],
             default: :device,
             allow_nil?: false,
             public?: true
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :scope_ref, :string,
             description: "device serial or batch identifier",
             public?: true
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :valid_until, :utc_datetime_usec,
             allow_nil?: false,
             public?: true
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :used_at, :utc_datetime_usec, public?: true),
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
    Builder.add_new_identity(dsl_state, :unique_token_hash, [:token_hash], pre_check_with: domain)
  end

  defp add_actions(dsl_state) do
    with {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :read, :read, primary?: true),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :destroy, :destroy, primary?: true),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :create, :mint,
             description:
               "Mint a new enrollment token. The plaintext is returned via Ash.Resource.get_metadata(record, :plaintext_token).",
             accept: [:scope, :scope_ref, :valid_until],
             changes: [Builder.build_action_change(AshPki.Changes.MintEnrollmentToken)]
           ),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :update, :consume,
             accept: [],
             require_atomic?: false,
             changes: [
               Builder.build_action_change(
                 {Ash.Resource.Change.SetAttribute,
                  attribute: :used_at, value: &DateTime.utc_now/0}
               )
             ]
           ) do
      Builder.add_new_action(dsl_state, :read, :find_by_plaintext,
        arguments: [
          Builder.build_action_argument(:token, :string, allow_nil?: false)
        ],
        get?: true,
        preparations: [Builder.build_preparation(Preparations.FindByPlaintext)]
      )
    end
  end

  defp add_code_interface(dsl_state) do
    with {:ok, dsl_state} <-
           Builder.add_new_interface(dsl_state, :mint, args: [:scope, :scope_ref, :valid_until]),
         {:ok, dsl_state} <- Builder.add_new_interface(dsl_state, :consume) do
      Builder.add_new_interface(dsl_state, :find_by_plaintext, args: [:token])
    end
  end
end
