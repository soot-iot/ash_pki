defmodule Mix.Tasks.AshPki.Install.Docs do
  @moduledoc false

  def short_doc do
    "Installs ash_pki: registers AshPki.Domain, generates AshPostgres-backed resources, seeds priv/pki and software key strategy"
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
    operator's `:ash_domains` config rather than generating empty stub
    copies of the library defaults.

    The library defaults run on `Ash.DataLayer.Ets` so the ash_pki
    test suite can run with zero infra, but Postgres is mandatory in
    the soot stack. The installer therefore composes
    `ash_postgres.install` (wiring the consumer's Repo + the
    `:ash_postgres` dep) and generates four AshPostgres-backed
    consumer resource modules under `lib/<app>/`:

      * `<App>.CertificateAuthority` — table `certificate_authorities`
      * `<App>.Certificate`          — table `certificates`
      * `<App>.RevocationList`       — table `revocation_lists`
      * `<App>.EnrollmentToken`      — table `enrollment_tokens`

    Each generated module applies the matching
    `AshPki.Resource.<Name>` extension and (for the three resources
    with sibling references) declares the relationship targets via the
    `pki do … end` block. The four modules are then registered in
    `config/config.exs` under `:ash_pki, <key>:` so the rest of
    ash_pki picks them up at boot. Operators own the generated files
    post-install — edit `postgres do … end` blocks, add custom
    actions, etc. as needed.

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

    @resource_keys [
      :certificate_authority,
      :certificate,
      :revocation_list,
      :enrollment_token
    ]

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash_pki,
        example: __MODULE__.Docs.example(),
        only: nil,
        composes: ["ash_postgres.install"],
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
      |> compose_ash_postgres()
      |> generate_consumer_resources()
      |> register_consumer_resources()
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

    # `ash_postgres.install` handles the `:ash_postgres` dep, the Repo
    # module, the `:ecto_repos` config, and dev/test/runtime DB URLs.
    # Threading `--yes` through keeps the install non-interactive when
    # the parent installer is running with `-y`. The third-arg fallback
    # is a no-op so the installer's own test suite (which runs without
    # ash_postgres in deps) can still exercise the rest of the
    # pipeline; in real consumer projects `ash_postgres.install` is
    # available because the parent `mix igniter.install` resolves it.
    defp compose_ash_postgres(igniter) do
      argv = if igniter.args.options[:yes], do: ["--yes"], else: []
      Igniter.compose_task(igniter, "ash_postgres.install", argv, & &1)
    end

    defp generate_consumer_resources(igniter) do
      Enum.reduce(@resource_keys, igniter, fn key, acc ->
        generate_resource_module(acc, key)
      end)
    end

    defp generate_resource_module(igniter, key) do
      module = consumer_module_name(igniter, key)
      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, module)

      if exists? do
        igniter
      else
        repo = Igniter.Project.Module.module_name(igniter, "Repo")
        body = consumer_module_body(igniter, key, repo)
        Igniter.Project.Module.create_module(igniter, module, body)
      end
    end

    defp register_consumer_resources(igniter) do
      Enum.reduce(@resource_keys, igniter, fn key, acc ->
        module = consumer_module_name(acc, key)

        Igniter.Project.Config.configure(
          acc,
          "config.exs",
          :ash_pki,
          [key],
          module
        )
      end)
    end

    defp consumer_module_name(igniter, key) do
      Igniter.Project.Module.module_name(igniter, camelize(key))
    end

    defp camelize(key), do: key |> Atom.to_string() |> Macro.camelize()

    defp consumer_module_body(igniter, :certificate_authority, repo) do
      module = consumer_module_name(igniter, :certificate_authority)
      certificate = consumer_module_name(igniter, :certificate)
      revocation_list = consumer_module_name(igniter, :revocation_list)

      """
      @moduledoc \"\"\"
      AshPostgres-backed `CertificateAuthority` resource generated by
      `mix ash_pki.install`. Operators own this file — edit the
      `postgres do … end` block, add domain-specific actions, etc. as
      needed. The schema (attributes, identities, lifecycle actions)
      comes from the `AshPki.Resource.CertificateAuthority` extension;
      sibling relationships are wired via the `pki do … end` block.
      Registered via `config :ash_pki, certificate_authority: #{inspect(module)}`.
      \"\"\"

      use Ash.Resource,
        otp_app: :#{otp_app(igniter)},
        domain: AshPki.Domain,
        data_layer: AshPostgres.DataLayer,
        authorizers: [Ash.Policy.Authorizer],
        extensions: [AshPki.Resource.CertificateAuthority]

      postgres do
        table "certificate_authorities"
        repo #{inspect(repo)}
      end

      pki do
        certificate #{inspect(certificate)}
        revocation_list #{inspect(revocation_list)}
      end

      # Mirrors `AshPki.CertificateAuthority`'s default policies (POLICY-SPEC §4.1).
      policies do
        bypass actor_attribute_equals(:role, :admin) do
          authorize_if always()
        end

        policy always() do
          access_type :strict
          authorize_if actor_attribute_equals(:part, :trust_loader)
          authorize_if actor_attribute_equals(:part, :issuer)
          authorize_if actor_attribute_equals(:part, :crl_publisher)
        end
      end
      """
    end

    defp consumer_module_body(igniter, :certificate, repo) do
      module = consumer_module_name(igniter, :certificate)
      certificate_authority = consumer_module_name(igniter, :certificate_authority)

      """
      @moduledoc \"\"\"
      AshPostgres-backed `Certificate` resource generated by
      `mix ash_pki.install`. Operators own this file — edit the
      `postgres do … end` block, add domain-specific actions, etc. as
      needed. The schema (attributes, identities, lifecycle actions)
      comes from the `AshPki.Resource.Certificate` extension; the
      `:issuer` relationship is wired via the `pki do … end` block.
      Registered via `config :ash_pki, certificate: #{inspect(module)}`.
      \"\"\"

      use Ash.Resource,
        otp_app: :#{otp_app(igniter)},
        domain: AshPki.Domain,
        data_layer: AshPostgres.DataLayer,
        authorizers: [Ash.Policy.Authorizer],
        extensions: [AshPki.Resource.Certificate]

      postgres do
        table "certificates"
        repo #{inspect(repo)}
      end

      pki do
        certificate_authority #{inspect(certificate_authority)}
      end

      # Mirrors `AshPki.Certificate`'s default policies (POLICY-SPEC §4.1).
      policies do
        bypass actor_attribute_equals(:role, :admin) do
          authorize_if always()
        end

        policy always() do
          access_type :strict
          authorize_if actor_attribute_equals(:part, :issuer)
          authorize_if actor_attribute_equals(:part, :mtls_resolver)
          authorize_if actor_attribute_equals(:part, :crl_publisher)
        end
      end
      """
    end

    defp consumer_module_body(igniter, :revocation_list, repo) do
      module = consumer_module_name(igniter, :revocation_list)
      certificate_authority = consumer_module_name(igniter, :certificate_authority)
      certificate = consumer_module_name(igniter, :certificate)

      """
      @moduledoc \"\"\"
      AshPostgres-backed `RevocationList` resource generated by
      `mix ash_pki.install`. Operators own this file — edit the
      `postgres do … end` block, add domain-specific actions, etc. as
      needed. The schema (attributes, identities, lifecycle actions)
      comes from the `AshPki.Resource.RevocationList` extension;
      sibling relationships are wired via the `pki do … end` block.
      Registered via `config :ash_pki, revocation_list: #{inspect(module)}`.
      \"\"\"

      use Ash.Resource,
        otp_app: :#{otp_app(igniter)},
        domain: AshPki.Domain,
        data_layer: AshPostgres.DataLayer,
        authorizers: [Ash.Policy.Authorizer],
        extensions: [AshPki.Resource.RevocationList]

      postgres do
        table "revocation_lists"
        repo #{inspect(repo)}
      end

      pki do
        certificate_authority #{inspect(certificate_authority)}
        certificate #{inspect(certificate)}
      end

      # Mirrors `AshPki.RevocationList`'s default policies (POLICY-SPEC §4.1).
      policies do
        bypass actor_attribute_equals(:role, :admin) do
          authorize_if always()
        end

        policy always() do
          access_type :strict
          authorize_if actor_attribute_equals(:part, :crl_publisher)
          authorize_if actor_attribute_equals(:part, :trust_loader)
        end
      end
      """
    end

    defp consumer_module_body(igniter, :enrollment_token, repo) do
      module = consumer_module_name(igniter, :enrollment_token)

      """
      @moduledoc \"\"\"
      AshPostgres-backed `EnrollmentToken` resource generated by
      `mix ash_pki.install`. Operators own this file — edit the
      `postgres do … end` block, add domain-specific actions, etc. as
      needed. The schema comes from the
      `AshPki.Resource.EnrollmentToken` extension. Registered via
      `config :ash_pki, enrollment_token: #{inspect(module)}`.
      \"\"\"

      use Ash.Resource,
        otp_app: :#{otp_app(igniter)},
        domain: AshPki.Domain,
        data_layer: AshPostgres.DataLayer,
        extensions: [AshPki.Resource.EnrollmentToken]

      postgres do
        table "enrollment_tokens"
        repo #{inspect(repo)}
      end
      """
    end

    defp otp_app(igniter), do: Igniter.Project.Application.app_name(igniter)

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

      `AshPki.Domain` is registered in `:ash_domains`. The four
      AshPostgres-backed consumer resources have been generated under
      `lib/<app>/` (CertificateAuthority, Certificate, RevocationList,
      EnrollmentToken) and registered in `config/config.exs` under
      their respective `:ash_pki, <key>:` keys. The Repo module and
      `:ash_postgres` dep were wired by the composed
      `ash_postgres.install`.

      Operators own the generated resource files — edit
      `postgres do … end` blocks, add custom actions, etc. as needed.

      Created:

        priv/pki/.gitkeep                            Trust material output dir

      Dev/test config sets `:ash_pki, :key_strategy` to `:software`.
      Switch to `:pkcs11` in `config/runtime.exs` for production HSMs.

      Next steps:

        mix ash.codegen --name install_ash_pki
        mix ash.setup
        mix ash_pki.init       # bootstrap a CA hierarchy under priv/pki
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
