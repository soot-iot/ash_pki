defmodule AshPki.Resource.Certificate.Preparations do
  @moduledoc false

  defmodule ByFingerprint do
    @moduledoc false
    use Ash.Resource.Preparation
    require Ash.Query

    @impl true
    def prepare(query, _opts, _context) do
      fingerprint = Ash.Query.get_argument(query, :fingerprint)
      Ash.Query.filter(query, fingerprint == ^fingerprint)
    end
  end

  defmodule BySerial do
    @moduledoc false
    use Ash.Resource.Preparation
    require Ash.Query

    @impl true
    def prepare(query, _opts, _context) do
      serial = Ash.Query.get_argument(query, :serial)
      issuer_id = Ash.Query.get_argument(query, :issuer_id)
      Ash.Query.filter(query, serial == ^serial and issuer_id == ^issuer_id)
    end
  end

  defmodule ActiveForIssuer do
    @moduledoc false
    use Ash.Resource.Preparation
    require Ash.Query

    @impl true
    def prepare(query, _opts, _context) do
      issuer_id = Ash.Query.get_argument(query, :issuer_id)
      Ash.Query.filter(query, issuer_id == ^issuer_id and status == :active)
    end
  end

  defmodule RevokedForIssuer do
    @moduledoc false
    use Ash.Resource.Preparation
    require Ash.Query

    @impl true
    def prepare(query, _opts, _context) do
      issuer_id = Ash.Query.get_argument(query, :issuer_id)
      Ash.Query.filter(query, issuer_id == ^issuer_id and status == :revoked)
    end
  end
end
