defmodule Mix.Tasks.AshPki.Gen.Cert do
  @shortdoc "Issue a certificate signed by a named CA"

  @moduledoc """
  Generates a fresh keypair and CSR, then issues a certificate against the
  named CA. Writes `<name>.key.pem`, `<name>.csr.pem`, and `<name>.cert.pem`
  to the output directory.

      mix ash_pki.gen.cert --issuer intermediate \\
                          --subject "/CN=client-001/O=Example" \\
                          --name client-001 \\
                          [--out priv/pki] \\
                          [--template client|server] \\
                          [--validity-days 365] \\
                          [--san dns:client-001.local --san uri:spiffe://example/client-001]

  Note: this task writes private key material to disk. Use only for
  bootstrap and one-off operator-issued certs. Production clients should
  generate their own keypair locally and submit a CSR rather than receiving
  a key from the issuer.
  """

  use Mix.Task

  @switches [
    issuer: :string,
    subject: :string,
    name: :string,
    out: :string,
    template: :string,
    validity_days: :integer,
    san: [:string, :keep]
  ]

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")

    {opts, _} = OptionParser.parse!(args, strict: @switches)

    issuer_name = Keyword.fetch!(opts, :issuer)
    subject = Keyword.fetch!(opts, :subject)
    name = Keyword.fetch!(opts, :name)
    out = Keyword.get(opts, :out, "priv/pki")
    template = opts |> Keyword.get(:template, "client") |> String.to_atom()
    validity_days = Keyword.get(opts, :validity_days, 365)
    sans = opts |> Keyword.get_values(:san) |> Enum.map(&parse_san/1)

    _ = AshPki.Persistence.load!(out)

    {:ok, ca} = AshPki.CertificateAuthority.get_by_name(issuer_name)

    File.mkdir_p!(out)

    private = X509.PrivateKey.new_ec(:secp256r1)
    csr = X509.CSR.new(private, subject)
    csr_pem = X509.CSR.to_pem(csr)

    {:ok, cert} =
      AshPki.Certificate.issue(ca.id, csr_pem, %{
        template: template,
        validity_days: validity_days,
        subject_alt_names: sans
      })

    write!(out, "#{name}.key.pem", X509.PrivateKey.to_pem(private))
    write!(out, "#{name}.csr.pem", csr_pem)
    write!(out, "#{name}.cert.pem", cert.certificate_pem)

    Mix.shell().info(
      "==> issued cert for #{subject} (serial #{cert.serial}, fp #{cert.fingerprint})"
    )
  end

  defp parse_san("dns:" <> name), do: name
  defp parse_san("uri:" <> uri), do: {:uri, uri}

  defp parse_san("ip:" <> ip) do
    {:ok, parsed} = :inet.parse_address(String.to_charlist(ip))
    {:ip, parsed}
  end

  defp parse_san(other), do: other

  defp write!(out, name, contents) do
    path = Path.join(out, name)
    File.write!(path, contents)
    Mix.shell().info("    wrote #{path}")
  end
end
