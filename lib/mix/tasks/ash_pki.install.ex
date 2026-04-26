defmodule Mix.Tasks.AshPki.Install.Docs do
  @moduledoc false

  def short_doc do
    "Installs the AshPki PKI domain stub into a Phoenix/Ash project"
  end

  def example do
    "mix igniter.install ash_pki"
  end

  def long_doc do
    """
    #{short_doc()}

    Generates a `Pki` Ash domain plus `CertificateAuthority`, `Certificate`,
    and `RevocationList` resource stubs in the operator's project,
    creates a `priv/pki/` placeholder for trust material, configures the
    software key strategy in dev/test, and imports the `:ash_pki`
    formatter rules.

    Composed by `mix soot.install`; can also be run standalone.

    See the `UI-SPEC.md` in the `soot` package for the full design.

    ## Example

    ```bash
    #{example()}
    ```

    ## Options

      * `--example` — same shape as the rest of the Soot installers;
        currently a no-op for `ash_pki` since the resource stubs already
        compile against the framework's defaults.
      * `--yes` — answer yes to dependency-fetching prompts.
    """
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshPki.Install do
    @shortdoc "#{__MODULE__.Docs.short_doc()}"
    @moduledoc __MODULE__.Docs.long_doc()

    use Igniter.Mix.Task

    @resources [
      "CertificateAuthority",
      "Certificate",
      "RevocationList"
    ]

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash_pki,
        example: __MODULE__.Docs.example(),
        only: nil,
        composes: [],
        schema: [example: :boolean, yes: :boolean],
        defaults: [example: false, yes: false],
        aliases: [y: :yes, e: :example]
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      igniter
      |> Igniter.Project.Formatter.import_dep(:ash_pki)
      |> configure_key_strategy()
      |> create_pki_domain()
      |> create_resources()
      |> create_pki_dir_placeholder()
      |> note_next_steps()
    end

    defp configure_key_strategy(igniter) do
      Igniter.Project.Config.configure(
        igniter,
        "config.exs",
        :ash_pki,
        [:key_strategy],
        :software
      )
    end

    defp pki_domain_module(igniter) do
      Igniter.Project.Module.module_name(igniter, "Pki")
    end

    defp resource_module(igniter, resource_name) do
      Igniter.Project.Module.module_name(igniter, "Pki.#{resource_name}")
    end

    defp create_pki_domain(igniter) do
      module = pki_domain_module(igniter)

      Igniter.Project.Module.create_module(
        igniter,
        module,
        """
        @moduledoc \"\"\"
        PKI domain — owns the certificate authorities, certificates, and
        revocation lists used for device mTLS.

        Generated stub. Operators can extend with their own resources or
        replace the framework-shipped ones; the installer does not
        re-touch this file once generated.
        \"\"\"

        use Ash.Domain

        resources do
        end
        """
      )
    end

    defp create_resources(igniter) do
      domain = pki_domain_module(igniter)

      Enum.reduce(@resources, igniter, fn resource_name, igniter ->
        module = resource_module(igniter, resource_name)

        Igniter.Project.Module.create_module(
          igniter,
          module,
          """
          @moduledoc \"\"\"
          #{resource_name} resource stub for the PKI domain.

          Generated stub. Extend with attributes, actions, and policies.
          The installer does not re-touch this file once generated.
          \"\"\"

          use Ash.Resource, domain: #{inspect(domain)}

          actions do
          end
          """
        )
      end)
    end

    defp create_pki_dir_placeholder(igniter) do
      Igniter.create_new_file(
        igniter,
        "priv/pki/.gitkeep",
        "",
        on_exists: :skip
      )
    end

    defp note_next_steps(igniter) do
      Igniter.add_notice(igniter, """
      ash_pki installed.

      Generated:

        lib/<app>/pki.ex                             PKI domain stub
        lib/<app>/pki/certificate_authority.ex       CA resource stub
        lib/<app>/pki/certificate.ex                 Certificate resource stub
        lib/<app>/pki/revocation_list.ex             Revocation list stub
        priv/pki/.gitkeep                            Trust material output dir

      Dev/test config sets `:ash_pki, :key_strategy` to `:software`.
      Switch to `:pkcs11` in `config/runtime.exs` for production HSMs.

      Next:

        mix ash_pki.init       # bootstrap a CA hierarchy under priv/pki
        mix ash.codegen        # if you added persistence to the resources
      """)
    end
  end
else
  defmodule Mix.Tasks.AshPki.Install do
    @shortdoc "#{__MODULE__.Docs.short_doc()} | Install `igniter` to use"
    @moduledoc __MODULE__.Docs.long_doc()

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task `ash_pki.install` requires igniter. Add
      `{:igniter, "~> 0.6"}` to your project deps and try again, or
      invoke via:

          mix igniter.install ash_pki

      For more information, see https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
