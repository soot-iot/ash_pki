defmodule Mix.Tasks.AshPki.Install.Docs do
  @moduledoc false

  def short_doc do
    "Installs ash_pki: registers AshPki.Domain, seeds priv/pki and software key strategy"
  end

  def example do
    "mix igniter.install ash_pki"
  end

  def long_doc do
    """
    #{short_doc()}

    `AshPki.Domain` ships its `CertificateAuthority`, `Certificate`,
    `RevocationList`, and `EnrollmentToken` resources as concrete
    library modules. The installer registers that domain in the
    operator's `:ash_domains` config rather than generating empty
    copies.

    The installer also creates `priv/pki/.gitkeep` (the on-disk trust
    material output dir), configures the `:software` key strategy in
    `config/config.exs`, and imports the `:ash_pki` formatter rules.

    Composed by `mix soot.install`; can also be run standalone.

    See `GENERATOR-SPEC.md` in the `soot` package for the full design.

    ## Example

    ```bash
    #{example()}
    ```

    ## Options

      * `--example` — same shape as the rest of the Soot installers;
        currently a no-op for `ash_pki` since the framework's resources
        compile against the shipped defaults.
      * `--yes` — answer yes to dependency-fetching prompts.
    """
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshPki.Install do
    @shortdoc "#{__MODULE__.Docs.short_doc()}"
    @moduledoc __MODULE__.Docs.long_doc()

    use Igniter.Mix.Task

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
      |> register_domain()
      |> configure_key_strategy()
      |> create_pki_dir_placeholder()
      |> note_next_steps()
    end

    defp register_domain(igniter) do
      app = Igniter.Project.Application.app_name(igniter)

      Igniter.Project.Config.configure(
        igniter,
        "config.exs",
        app,
        [:ash_domains],
        [AshPki.Domain],
        updater: fn list ->
          Igniter.Code.List.prepend_new_to_list(list, AshPki.Domain)
        end
      )
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

      `AshPki.Domain` is registered in `:ash_domains`. Its
      `CertificateAuthority`, `Certificate`, `RevocationList`, and
      `EnrollmentToken` resources ship with the library — no operator
      stubs are generated.

      Created:

        priv/pki/.gitkeep                            Trust material output dir

      Dev/test config sets `:ash_pki, :key_strategy` to `:software`.
      Switch to `:pkcs11` in `config/runtime.exs` for production HSMs.

      Next:

        mix ash_pki.init       # bootstrap a CA hierarchy under priv/pki
        mix ash.codegen        # if you've extended persistence locally
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
