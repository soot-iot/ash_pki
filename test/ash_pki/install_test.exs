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

  describe "generated modules" do
    test "creates the Pki domain module" do
      setup_project()
      |> Igniter.compose_task("ash_pki.install", [])
      |> assert_creates("lib/test/pki.ex")
    end

    test "creates the CertificateAuthority resource stub" do
      setup_project()
      |> Igniter.compose_task("ash_pki.install", [])
      |> assert_creates("lib/test/pki/certificate_authority.ex")
    end

    test "creates the Certificate resource stub" do
      setup_project()
      |> Igniter.compose_task("ash_pki.install", [])
      |> assert_creates("lib/test/pki/certificate.ex")
    end

    test "creates the RevocationList resource stub" do
      setup_project()
      |> Igniter.compose_task("ash_pki.install", [])
      |> assert_creates("lib/test/pki/revocation_list.ex")
    end

    test "Certificate resource declares the Pki domain" do
      result =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      diff = diff(result, only: "lib/test/pki/certificate.ex")
      assert diff =~ "use Ash.Resource"
      assert diff =~ "Test.Pki"
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

    test "is idempotent" do
      setup_project()
      |> Igniter.compose_task("ash_pki.install", [])
      |> apply_igniter!()
      |> Igniter.compose_task("ash_pki.install", [])
      |> assert_unchanged(".formatter.exs")
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

  describe "next-steps notice" do
    test "always emits an ash_pki installed notice" do
      igniter =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      assert Enum.any?(igniter.notices, &(&1 =~ "ash_pki installed"))
    end
  end
end
