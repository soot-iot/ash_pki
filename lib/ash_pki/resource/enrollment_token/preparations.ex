defmodule AshPki.Resource.EnrollmentToken.Preparations do
  @moduledoc false

  defmodule FindByPlaintext do
    @moduledoc false
    use Ash.Resource.Preparation
    require Ash.Query

    @impl true
    def prepare(query, _opts, _context) do
      plaintext = Ash.Query.get_argument(query, :token)
      hash = :crypto.hash(:sha256, plaintext) |> Base.encode16(case: :lower)
      Ash.Query.filter(query, token_hash == ^hash)
    end
  end
end
