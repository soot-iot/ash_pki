defmodule AshPki.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/lawik/ash_pki"

  def project do
    [
      app: :ash_pki,
      version: @version,
      elixir: "~> 1.16",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      consolidate_protocols: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: @source_url,
      docs: docs(),
      aliases: aliases()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :ssl],
      mod: {AshPki.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp description do
    "PKI primitives as an Ash extension: CAs, certificates, revocation, mTLS plug."
  end

  defp package do
    [
      licenses: ["MIT"],
      files: ~w(lib .formatter.exs mix.exs README* LICENSE* CHANGELOG*),
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extras: ["README.md", "CHANGELOG.md"]
    ]
  end

  defp aliases do
    [
      format: "format --migrate"
    ]
  end

  defp deps do
    [
      {:ash, "~> 3.24"},
      {:x509, "~> 0.9"},
      {:plug, "~> 1.19"},
      {:jason, "~> 1.4"}
    ]
  end
end
