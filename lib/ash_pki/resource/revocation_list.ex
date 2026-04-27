defmodule AshPki.Resource.RevocationList do
  @moduledoc """
  `Ash.Resource` extension that injects the AshPki `RevocationList`
  schema (per-CA CRL rows with sequencing + supersede semantics) into a
  consumer-owned resource module.

  Usage and override semantics mirror `AshPki.Resource.Certificate`.
  Wire the `:ca` relationship and the `publish` action through the
  `pki do ... end` block:

      pki do
        certificate_authority MyApp.CertificateAuthority
        certificate MyApp.Certificate
      end

  Each option defaults to the shipped `AshPki.*` module when omitted.
  """

  @pki %Spark.Dsl.Section{
    name: :pki,
    describe: """
    Sibling-resource references for this RevocationList resource. Used
    at compile time to wire the `:ca` relationship and at runtime by
    the `publish` action to load the CA and the revoked certificates.
    """,
    schema: [
      certificate_authority: [
        type: :atom,
        default: AshPki.CertificateAuthority,
        doc: "The `CertificateAuthority` resource module these CRLs belong to."
      ],
      certificate: [
        type: :atom,
        default: AshPki.Certificate,
        doc: "The `Certificate` resource module to scan for revoked entries when publishing."
      ]
    ]
  }

  use Spark.Dsl.Extension,
    sections: [@pki],
    transformers: [AshPki.Resource.RevocationList.Transformers.Inject]
end
