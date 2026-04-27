defmodule AshPki.Resource.RevocationList.Preparations do
  @moduledoc false

  defmodule ForCa do
    @moduledoc false
    use Ash.Resource.Preparation
    require Ash.Query

    @impl true
    def prepare(query, _opts, _context) do
      ca_id = Ash.Query.get_argument(query, :ca_id)
      Ash.Query.filter(query, ca_id == ^ca_id)
    end
  end

  defmodule CurrentForCa do
    @moduledoc false
    use Ash.Resource.Preparation
    require Ash.Query

    @impl true
    def prepare(query, _opts, _context) do
      ca_id = Ash.Query.get_argument(query, :ca_id)

      query
      |> Ash.Query.filter(ca_id == ^ca_id and status == :current)
      |> Ash.Query.sort(sequence: :desc)
    end
  end
end
