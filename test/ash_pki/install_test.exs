defmodule Mix.Tasks.AshPki.InstallTest do
  use ExUnit.Case, async: false

  import Igniter.Test

  defp setup_project do
    test_project(files: %{})
  end

  describe "info/2" do
    test "exposes the documented option schema" do
      info = Mix.Tasks.AshPki.Install.info([], nil)
      assert info.group == :ash_pki
      assert info.schema == [example: :boolean, yes: :boolean]
      assert info.aliases == [y: :yes, e: :example]
    end
  end

  describe "domain registration" do
    test "registers AshPki.Domain in operator's :ash_domains" do
      result =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      diff = diff(result, only: "config/config.exs")
      assert diff =~ "AshPki.Domain"
      assert diff =~ "ash_domains:"
    end
  end

  describe "trust material directory" do
    test "creates priv/pki/.gitkeep placeholder" do
      setup_project()
      |> Igniter.compose_task("ash_pki.install", [])
      |> assert_creates("priv/pki/.gitkeep")
    end
  end

  describe "formatter" do
    test "imports the :ash_pki formatter rules" do
      setup_project()
      |> Igniter.compose_task("ash_pki.install", [])
      |> assert_has_patch(".formatter.exs", """
      + |  import_deps: [:ash_pki]
      """)
    end
  end

  describe "config" do
    test "configures the software key strategy in config.exs" do
      result =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      diff = diff(result, only: "config/config.exs")
      assert diff =~ ":ash_pki"
      assert diff =~ "key_strategy"
      assert diff =~ ":software"
    end
  end

  describe "idempotency" do
    test "running twice is a no-op on .formatter.exs" do
      setup_project()
      |> Igniter.compose_task("ash_pki.install", [])
      |> apply_igniter!()
      |> Igniter.compose_task("ash_pki.install", [])
      |> assert_unchanged(".formatter.exs")
    end

    test "running twice is a no-op on config/config.exs" do
      setup_project()
      |> Igniter.compose_task("ash_pki.install", [])
      |> apply_igniter!()
      |> Igniter.compose_task("ash_pki.install", [])
      |> assert_unchanged("config/config.exs")
    end
  end

  describe "next-steps notice" do
    test "always emits an ash_pki installed notice" do
      igniter =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      assert Enum.any?(igniter.notices, &(&1 =~ "ash_pki installed"))
    end

    test "notice mentions ash_pki.init for first-time CA bootstrap" do
      igniter =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      assert Enum.any?(igniter.notices, &(&1 =~ "ash_pki.init"))
    end
  end
end
