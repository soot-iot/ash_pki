defmodule AshPki.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :ash_pki,
      version: @version,
      elixir: "~> 1.16",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      consolidate_protocols: Mix.env() != :test,
      deps: deps(),
      description: description(),
      package: package()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :public_key, :ssl],
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
      links: %{}
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
