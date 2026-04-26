defmodule Mix.Tasks.AshPki.ImportCerts do
  @shortdoc "Bulk-import pre-provisioned device certificates"

  @moduledoc """
  Bulk-import pre-provisioned device certificates from a vendor
  manifest. Three input shapes are supported:

      # CSV with header `serial,certificate_pem,vendor[,vendor_meta]`
      mix ash_pki.import_certs --issuer intermediate --csv vendor_manifest.csv

      # Concatenated PEM bundle
      mix ash_pki.import_certs --issuer intermediate --bundle device_certs.pem \\
                              [--vendor atecc608]

      # A single cert PEM
      mix ash_pki.import_certs --issuer intermediate --cert device_001.pem \\
                              [--vendor optiga_trust_m]

  Reports the number of inserted rows and any rows that were skipped
  with their (line / cert index) and reason.
  """

  use Mix.Task

  alias AshPki.Certificate.Bulk

  @switches [
    issuer: :string,
    csv: :string,
    bundle: :string,
    cert: :string,
    vendor: :string,
    default_vendor: :string
  ]

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")
    {opts, _} = OptionParser.parse!(args, strict: @switches)

    issuer_name = Keyword.fetch!(opts, :issuer)
    {:ok, issuer} = AshPki.CertificateAuthority.get_by_name(issuer_name)

    sources =
      [
        Keyword.get(opts, :csv) && {:csv, Keyword.fetch!(opts, :csv)},
        Keyword.get(opts, :bundle) && {:bundle, Keyword.fetch!(opts, :bundle)},
        Keyword.get(opts, :cert) && {:cert, Keyword.fetch!(opts, :cert)}
      ]
      |> Enum.reject(&is_nil/1)

    case sources do
      [] -> Mix.raise("provide one of --csv, --bundle, or --cert")
      [{kind, path}] -> do_import(issuer, kind, path, opts)
      _ -> Mix.raise("--csv, --bundle, and --cert are mutually exclusive; pick one")
    end
  end

  defp do_import(issuer, :csv, path, opts) do
    csv = File.read!(path)

    {:ok, %{inserted: n, errors: errors}} =
      Bulk.import_csv(issuer.id, csv, default_vendor: Keyword.get(opts, :default_vendor))

    report(n, errors)
  end

  defp do_import(issuer, :bundle, path, opts) do
    bundle = File.read!(path)

    {:ok, %{inserted: n, errors: errors}} =
      Bulk.import_pem_bundle(issuer.id, bundle, vendor: Keyword.get(opts, :vendor, "custom"))

    report(n, errors)
  end

  defp do_import(issuer, :cert, path, opts) do
    pem = File.read!(path)
    metadata = %{"vendor" => Keyword.get(opts, :vendor, "custom")}

    case AshPki.Certificate.import_certificate(issuer.id, pem, %{metadata: metadata}) do
      {:ok, cert} ->
        Mix.shell().info("==> imported cert (serial #{cert.serial}, fp #{cert.fingerprint})")

      {:error, reason} ->
        Mix.raise("import failed: #{inspect(reason)}")
    end
  end

  defp report(inserted, errors) do
    Mix.shell().info("==> imported #{inserted} cert(s)")

    case errors do
      [] ->
        :ok

      _ ->
        Mix.shell().info("    skipped #{length(errors)} row(s):")

        Enum.each(errors, fn {line, reason} ->
          Mix.shell().info("      line #{line}: #{inspect(reason)}")
        end)
    end
  end
end
