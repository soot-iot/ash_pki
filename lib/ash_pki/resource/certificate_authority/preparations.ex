defmodule AshPki.Resource.CertificateAuthority.Preparations do
  @moduledoc false

  defmodule ByName do
    @moduledoc false
    use Ash.Resource.Preparation
    require Ash.Query

    @impl true
    def prepare(query, _opts, _context) do
      name = Ash.Query.get_argument(query, :name)
      Ash.Query.filter(query, name == ^name)
    end
  end
end
