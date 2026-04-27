defmodule AshPki.Resource.CertificateAuthority do
  @moduledoc """
  `Ash.Resource` extension that injects the AshPki `CertificateAuthority`
  schema (root + intermediate CAs, key descriptor, the `create_root` /
  `create_intermediate` / `rotate` actions, the standard code interface,
  and the `:issued_certificates` / `:revocation_lists` has_many
  relationships) into a consumer-owned resource module.

  Usage and override semantics mirror `AshPki.Resource.Certificate`.
  The `:issued_certificates` and `:revocation_lists` has_many
  relationships are wired from the `pki do ... end` block:

      pki do
        certificate MyApp.Certificate
        revocation_list MyApp.RevocationList
      end

  Each option defaults to the shipped `AshPki.*` module when omitted.
  """

  @pki %Spark.Dsl.Section{
    name: :pki,
    describe: """
    Sibling-resource references for this CertificateAuthority resource.
    Used at compile time to wire the `:issued_certificates` and
    `:revocation_lists` has_many relationships.
    """,
    schema: [
      certificate: [
        type: :atom,
        default: AshPki.Certificate,
        doc: "The `Certificate` resource module these CAs issue against."
      ],
      revocation_list: [
        type: :atom,
        default: AshPki.RevocationList,
        doc: "The `RevocationList` resource module these CAs publish CRLs through."
      ]
    ]
  }

  use Spark.Dsl.Extension,
    sections: [@pki],
    transformers: [AshPki.Resource.CertificateAuthority.Transformers.Inject]
end
