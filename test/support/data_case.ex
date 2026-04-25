defmodule AshPki.DataCase do
  @moduledoc """
  Test case template for tests that touch AshPki resources.

  ETS tables are process-shared, so tests that exercise the resources
  cannot run concurrently with each other; this case sets `async: false`
  and clears the tables in `setup`. A future move to per-process ETS
  tables (or AshPostgres in CI) is what would unlock concurrency.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      import AshPki.DataCase
      alias AshPki.Test.Factories
    end
  end

  setup _tags do
    AshPki.Test.Factories.reset_ets!()
    :ok
  end
end
