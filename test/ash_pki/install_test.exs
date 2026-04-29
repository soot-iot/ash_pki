defmodule Mix.Tasks.AshPki.InstallTest do
  use ExUnit.Case, async: false

  import Igniter.Test

  # Igniter evaluates the consumer project's `config/config.exs` into
  # the live `Application` env so installer steps can inspect it. That
  # means our "register the four modules" step leaks
  # `Test.Certificate`, `Test.EnrollmentToken`, etc. into the ash_pki
  # app env for the rest of this test run, which can break any
  # subsequent test that resolves `AshPki.<resource>()` via config.
  # Snapshot the relevant keys before each test and restore on exit.
  setup do
    keys = [
      :certificate,
      :certificate_authority,
      :revocation_list,
      :enrollment_token,
      :key_strategy,
      :trust_store
    ]

    snapshot =
      for key <- keys,
          {:ok, value} <- [Application.fetch_env(:ash_pki, key)],
          do: {key, value}

    on_exit(fn ->
      for key <- keys do
        Application.delete_env(:ash_pki, key)
      end

      for {key, value} <- snapshot do
        Application.put_env(:ash_pki, key, value)
      end
    end)

    :ok
  end

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

    test "notice mentions the generated AshPostgres-backed resources" do
      igniter =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      assert Enum.any?(igniter.notices, &(&1 =~ "AshPostgres-backed"))
    end

    test "notice mentions ash.codegen + ash.setup" do
      igniter =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      assert Enum.any?(igniter.notices, &(&1 =~ "mix ash.codegen --name install_ash_pki"))
      assert Enum.any?(igniter.notices, &(&1 =~ "mix ash.setup"))
    end
  end

  describe "info/2 composes" do
    test "composes ash_postgres.install" do
      info = Mix.Tasks.AshPki.Install.info([], nil)
      assert "ash_postgres.install" in info.composes
    end
  end

  describe "AshPostgres consumer resources" do
    @resource_files [
      "lib/test/certificate_authority.ex",
      "lib/test/certificate.ex",
      "lib/test/revocation_list.ex",
      "lib/test/enrollment_token.ex"
    ]

    defp generated_source(igniter, path) do
      source = igniter.rewrite.sources[path]

      assert source,
             "expected #{inspect(path)} to have been generated, but it was not. " <>
               "Created files: #{inspect(Map.keys(igniter.rewrite.sources))}"

      Rewrite.Source.get(source, :content)
    end

    test "generates the four consumer resource modules under lib/<app>/" do
      result =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      for path <- @resource_files do
        assert_creates(result, path)
      end
    end

    test "Certificate module wires AshPostgres + the AshPki.Resource.Certificate extension" do
      result =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      content = generated_source(result, "lib/test/certificate.ex")

      assert content =~ "defmodule Test.Certificate"
      assert content =~ "use Ash.Resource"
      assert content =~ "otp_app: :test"
      assert content =~ "domain: AshPki.Domain"
      assert content =~ "data_layer: AshPostgres.DataLayer"
      assert content =~ "extensions: [AshPki.Resource.Certificate]"
      assert content =~ ~s|table("certificates")|
      assert content =~ "repo(Test.Repo)"
    end

    test "Certificate module includes a pki block referencing Test.CertificateAuthority" do
      result =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      content = generated_source(result, "lib/test/certificate.ex")

      assert content =~ "pki do"
      assert content =~ "certificate_authority(Test.CertificateAuthority)"
    end

    test "CertificateAuthority module wires AshPostgres + the AshPki.Resource.CertificateAuthority extension" do
      result =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      content = generated_source(result, "lib/test/certificate_authority.ex")

      assert content =~ "defmodule Test.CertificateAuthority"
      assert content =~ "extensions: [AshPki.Resource.CertificateAuthority]"
      assert content =~ "data_layer: AshPostgres.DataLayer"
      assert content =~ ~s|table("certificate_authorities")|
      assert content =~ "repo(Test.Repo)"
    end

    test "CertificateAuthority module relates to certificate and revocation_list" do
      result =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      content = generated_source(result, "lib/test/certificate_authority.ex")

      assert content =~ "pki do"
      assert content =~ "certificate(Test.Certificate)"
      assert content =~ "revocation_list(Test.RevocationList)"
    end

    test "RevocationList module relates to certificate_authority and certificate" do
      result =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      content = generated_source(result, "lib/test/revocation_list.ex")

      assert content =~ "defmodule Test.RevocationList"
      assert content =~ "extensions: [AshPki.Resource.RevocationList]"
      assert content =~ "pki do"
      assert content =~ "certificate_authority(Test.CertificateAuthority)"
      assert content =~ "certificate(Test.Certificate)"
      assert content =~ ~s|table("revocation_lists")|
    end

    test "EnrollmentToken module is generated without a pki block" do
      result =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      content = generated_source(result, "lib/test/enrollment_token.ex")

      assert content =~ "defmodule Test.EnrollmentToken"
      assert content =~ "extensions: [AshPki.Resource.EnrollmentToken]"
      assert content =~ "data_layer: AshPostgres.DataLayer"
      assert content =~ ~s|table("enrollment_tokens")|
      assert content =~ "repo(Test.Repo)"
      refute content =~ "pki do"
    end

    test "registers all four modules in config/config.exs under :ash_pki" do
      result =
        setup_project()
        |> Igniter.compose_task("ash_pki.install", [])

      diff = diff(result, only: "config/config.exs")

      assert diff =~ "certificate_authority: Test.CertificateAuthority"
      assert diff =~ "certificate: Test.Certificate"
      assert diff =~ "revocation_list: Test.RevocationList"
      assert diff =~ "enrollment_token: Test.EnrollmentToken"
    end

    test "running the installer twice does not churn lib/test/certificate.ex" do
      setup_project()
      |> Igniter.compose_task("ash_pki.install", [])
      |> apply_igniter!()
      |> Igniter.compose_task("ash_pki.install", [])
      |> assert_unchanged("lib/test/certificate.ex")
    end

    test "running the installer twice does not churn lib/test/certificate_authority.ex" do
      setup_project()
      |> Igniter.compose_task("ash_pki.install", [])
      |> apply_igniter!()
      |> Igniter.compose_task("ash_pki.install", [])
      |> assert_unchanged("lib/test/certificate_authority.ex")
    end
  end
end
