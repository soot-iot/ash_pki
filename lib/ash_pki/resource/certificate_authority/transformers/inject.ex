defmodule AshPki.Resource.CertificateAuthority.Transformers.Inject do
  @moduledoc false
  use Spark.Dsl.Transformer

  alias Ash.Resource.Builder
  alias AshPki.Resource.CertificateAuthority.Preparations
  alias Spark.Dsl.Transformer

  @impl true
  def before?(Ash.Resource.Transformers.BelongsToAttribute), do: true
  def before?(_), do: false

  @impl true
  def transform(dsl_state) do
    cert_module =
      Spark.Dsl.Extension.get_opt(dsl_state, [:pki], :certificate, AshPki.Certificate)

    crl_module =
      Spark.Dsl.Extension.get_opt(dsl_state, [:pki], :revocation_list, AshPki.RevocationList)

    domain = Transformer.get_persisted(dsl_state, :domain) || domain_from_dsl(dsl_state)

    with {:ok, dsl_state} <- add_attributes(dsl_state),
         {:ok, dsl_state} <- add_identities(dsl_state, domain),
         {:ok, dsl_state} <- add_relationships(dsl_state, cert_module, crl_module),
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
           Builder.add_new_attribute(dsl_state, :name, :string,
             allow_nil?: false,
             public?: true
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :role, :atom,
             constraints: [one_of: [:root, :intermediate]],
             allow_nil?: false,
             default: :root,
             public?: true
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :parent_id, :uuid, public?: true),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :key_strategy, :atom,
             constraints: [one_of: [:software, :pkcs11, :kms, :imported]],
             default: :software,
             allow_nil?: false,
             public?: true
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :key_descriptor, :map,
             sensitive?: true,
             public?: false,
             default: %{}
           ),
         {:ok, dsl_state} <-
           Builder.add_new_attribute(dsl_state, :certificate_pem, :string,
             allow_nil?: true,
             public?: true
           ),
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
             constraints: [one_of: [:active, :rotated, :revoked]],
             default: :active,
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
    with {:ok, dsl_state} <-
           Builder.add_new_identity(dsl_state, :unique_name, [:name], pre_check_with: domain) do
      Builder.add_new_identity(dsl_state, :unique_fingerprint, [:fingerprint],
        pre_check_with: domain
      )
    end
  end

  defp add_relationships(dsl_state, cert_module, crl_module) do
    self_module = Transformer.get_persisted(dsl_state, :module)

    with {:ok, dsl_state} <-
           Builder.add_new_relationship(dsl_state, :belongs_to, :parent, self_module,
             public?: true,
             attribute_writable?: false,
             destination_attribute: :id,
             source_attribute: :parent_id,
             define_attribute?: false
           ),
         {:ok, dsl_state} <-
           Builder.add_new_relationship(
             dsl_state,
             :has_many,
             :issued_certificates,
             cert_module,
             destination_attribute: :issuer_id
           ) do
      Builder.add_new_relationship(
        dsl_state,
        :has_many,
        :revocation_lists,
        crl_module,
        destination_attribute: :ca_id
      )
    end
  end

  defp add_actions(dsl_state) do
    with {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :read, :read, primary?: true),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :destroy, :destroy, primary?: true),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :read, :get_by_name,
             arguments: [
               Builder.build_action_argument(:name, :string, allow_nil?: false)
             ],
             get?: true,
             preparations: [Builder.build_preparation(Preparations.ByName)]
           ),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :create, :create_root,
             description: "Generate a fresh self-signed root CA.",
             accept: [:name, :key_strategy],
             arguments: [
               Builder.build_action_argument(:subject_dn, :string, allow_nil?: false),
               Builder.build_action_argument(:validity_days, :integer, default: 365 * 10),
               Builder.build_action_argument(:key_type, :atom,
                 constraints: [one_of: [:ec, :rsa]],
                 default: :ec
               ),
               Builder.build_action_argument(:curve, :atom, default: :secp256r1),
               Builder.build_action_argument(:bits, :integer, default: 2048)
             ],
             changes: [
               Builder.build_action_change(AshPki.Changes.GenerateRootCA)
             ]
           ),
         {:ok, dsl_state} <-
           Builder.add_new_action(dsl_state, :create, :create_intermediate,
             description: "Generate an intermediate CA signed by an existing CA.",
             accept: [:name, :key_strategy],
             arguments: [
               Builder.build_action_argument(:parent_id, :uuid, allow_nil?: false),
               Builder.build_action_argument(:subject_dn, :string, allow_nil?: false),
               Builder.build_action_argument(:validity_days, :integer, default: 365 * 5),
               Builder.build_action_argument(:key_type, :atom,
                 constraints: [one_of: [:ec, :rsa]],
                 default: :ec
               ),
               Builder.build_action_argument(:curve, :atom, default: :secp256r1),
               Builder.build_action_argument(:bits, :integer, default: 2048)
             ],
             changes: [
               Builder.build_action_change(AshPki.Changes.GenerateIntermediateCA)
             ]
           ) do
      Builder.add_new_action(dsl_state, :update, :rotate,
        description: "Mark this CA as rotated. Cross-signing is a follow-up step.",
        accept: [],
        require_atomic?: false,
        changes: [
          Builder.build_action_change(
            {Ash.Resource.Change.SetAttribute, attribute: :status, value: :rotated}
          )
        ]
      )
    end
  end

  defp add_code_interface(dsl_state) do
    with {:ok, dsl_state} <-
           Builder.add_new_interface(dsl_state, :create_root, args: [:name, :subject_dn]),
         {:ok, dsl_state} <-
           Builder.add_new_interface(dsl_state, :create_intermediate,
             args: [:name, :parent_id, :subject_dn]
           ),
         {:ok, dsl_state} <-
           Builder.add_new_interface(dsl_state, :get_by_name, args: [:name]) do
      Builder.add_new_interface(dsl_state, :rotate)
    end
  end
end
