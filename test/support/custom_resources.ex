defmodule AshPki.Test.Custom do
  @moduledoc """
  Consumer-style resources that prove the AshPki resource extensions can
  be applied to operator-owned modules with extra app-specific fields and
  cross-references resolved through the per-resource `pki do ... end`
  block (no application-global config required).
  """
end

defmodule AshPki.Test.Custom.Domain do
  @moduledoc false
  use Ash.Domain, otp_app: :ash_pki, validate_config_inclusion?: false

  resources do
    resource AshPki.Test.Custom.Certificate
    resource AshPki.Test.Custom.CertificateAuthority
    resource AshPki.Test.Custom.RevocationList
    resource AshPki.Test.Custom.EnrollmentToken
  end
end

defmodule AshPki.Test.Custom.CertificateAuthority do
  @moduledoc false

  use Ash.Resource,
    otp_app: :ash_pki,
    domain: AshPki.Test.Custom.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshPki.Resource.CertificateAuthority]

  ets do
    private? false
  end

  pki do
    certificate AshPki.Test.Custom.Certificate
    revocation_list AshPki.Test.Custom.RevocationList
  end

  attributes do
    attribute :tenant_id, :uuid, public?: true
  end
end

defmodule AshPki.Test.Custom.Certificate do
  @moduledoc false

  use Ash.Resource,
    otp_app: :ash_pki,
    domain: AshPki.Test.Custom.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshPki.Resource.Certificate]

  ets do
    private? false
  end

  pki do
    certificate_authority AshPki.Test.Custom.CertificateAuthority
  end

  attributes do
    attribute :tenant_id, :uuid, public?: true
    attribute :hardware_attestation, :map, public?: true
  end
end

defmodule AshPki.Test.Custom.RevocationList do
  @moduledoc false

  use Ash.Resource,
    otp_app: :ash_pki,
    domain: AshPki.Test.Custom.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshPki.Resource.RevocationList]

  ets do
    private? false
  end

  pki do
    certificate_authority AshPki.Test.Custom.CertificateAuthority
    certificate AshPki.Test.Custom.Certificate
  end

  attributes do
    attribute :tenant_id, :uuid, public?: true
  end
end

defmodule AshPki.Test.Custom.EnrollmentToken do
  @moduledoc false

  use Ash.Resource,
    otp_app: :ash_pki,
    domain: AshPki.Test.Custom.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshPki.Resource.EnrollmentToken]

  ets do
    private? false
  end

  attributes do
    attribute :tenant_id, :uuid, public?: true
  end
end
