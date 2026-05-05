defmodule AshPki.LibraryDomainInclusionTest do
  @moduledoc """
  Regression: a consumer-namespaced resource declaring
  `domain: AshPki.Domain` must compile.

  Without `allow_unregistered? true` on `AshPki.Domain`, Ash's
  `VerifyAcceptedByDomain` verifier raises at module-load time:

      ** (RuntimeError) Resource AshPki.LibraryDomainInclusionTest.
      ConsumerEnrollmentToken declared that its domain is
      AshPki.Domain, but that domain does not accept this resource.

  If the verifier fires, this file fails to compile and the whole
  test suite errors out — that is the intended failure mode.
  """
  use ExUnit.Case, async: true

  defmodule ConsumerEnrollmentToken do
    @moduledoc false

    use Ash.Resource,
      otp_app: :ash_pki,
      domain: AshPki.Domain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshPki.Resource.EnrollmentToken]

    ets do
      private? false
    end

    attributes do
      attribute :tenant_id, :uuid, public?: true
    end
  end

  test "consumer-namespaced module pointing at AshPki.Domain compiles" do
    assert Code.ensure_loaded?(ConsumerEnrollmentToken)
    assert is_list(Spark.Dsl.Extension.get_entities(ConsumerEnrollmentToken, [:attributes]))
  end
end
