defmodule AshPki.Resource.EnrollmentToken do
  @moduledoc """
  `Ash.Resource` extension that injects the AshPki enrollment-token
  schema into a consumer-owned resource module.

  Tokens are stored hashed; the plaintext is returned exactly once on
  the result of `mint/3` via Ash resource metadata. The device-side
  enrollment flow that consumes the token (verifying it, issuing an
  operational certificate, transitioning a device into service) lives
  in whatever IoT/application layer wraps `ash_pki`.

  Usage and override semantics mirror `AshPki.Resource.Certificate`.
  """

  use Spark.Dsl.Extension,
    transformers: [AshPki.Resource.EnrollmentToken.Transformers.Inject]
end
