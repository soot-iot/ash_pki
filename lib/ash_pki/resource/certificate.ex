defmodule AshPki.Resource.Certificate do
  @moduledoc """
  `Ash.Resource` extension that injects the AshPki leaf-certificate schema
  (attributes, identities, the issuer relationship, the `issue` /
  `import_certificate` / `revoke` actions, and the standard code interface)
  into a consumer-owned resource module.

  ## Usage

      defmodule MyApp.Certificate do
        use Ash.Resource,
          domain: MyApp.PKI,
          data_layer: AshPostgres.DataLayer,
          extensions: [AshPki.Resource.Certificate]

        postgres do
          table "certificates"
          repo MyApp.Repo
        end

        # Add app-specific fields, identities, policies, etc.
        attributes do
          attribute :tenant_id, :uuid, public?: true
          attribute :hardware_attestation, :map
        end
      end

  Then register the module so the rest of AshPki resolves through it:

      config :ash_pki, certificate: MyApp.Certificate

  Anything the consumer defines themselves (an attribute, an action, an
  identity, the `:issuer` relationship) takes precedence — the extension
  uses `add_new_*` builders that no-op when the entity already exists.

  ## Wiring siblings

  The internal changes (`issue`, `import_certificate`) need to know which
  `CertificateAuthority` resource to load the issuer from. Declare it in
  the `pki do ... end` block:

      pki do
        certificate_authority MyApp.CertificateAuthority
      end

  Defaults to `AshPki.CertificateAuthority` (the shipped default) when
  the section is omitted.
  """

  @pki %Spark.Dsl.Section{
    name: :pki,
    describe: """
    Sibling-resource references for this Certificate resource. Used at
    compile time to wire the `:issuer` relationship and at runtime by
    the `issue` / `import_certificate` actions to load the CA.
    """,
    schema: [
      certificate_authority: [
        type: :atom,
        default: AshPki.CertificateAuthority,
        doc: "The `CertificateAuthority` resource module that issues these certs."
      ]
    ]
  }

  use Spark.Dsl.Extension,
    sections: [@pki],
    transformers: [AshPki.Resource.Certificate.Transformers.Inject]
end
