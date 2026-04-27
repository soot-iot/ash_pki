defmodule AshPki.Certificate.Bulk do
  @moduledoc """
  Bulk import for pre-provisioned device certificates.

  Manufacturing-line use: a silicon vendor (ATECC, OPTIGA, EdgeLock, …)
  hands over a manifest listing the certs that have been burned into a
  batch of devices. The operator runs this through `import_csv/3` or
  `import_pem_bundle/3` to create the matching `Certificate` rows in
  `:imported` state.

  Two manifest shapes are supported:

  * **CSV** with a header row. Recognised columns:

        serial,certificate_pem,vendor[,vendor_meta]

    Vendor-specific manifests almost always need a one-time conversion
    to this shape; that conversion is the operator's job (or the silicon
    vendor's tooling).

  * **PEM bundle** — a concatenation of `BEGIN CERTIFICATE` blocks. Each
    cert is imported with the configured `vendor` and no extra metadata.

  Every imported cert must chain to `issuer_id` (an existing
  `CertificateAuthority`). Rows that fail validation are skipped with a
  `{line_or_index, reason}` entry in the result's `:errors` list — the
  rest of the manifest is *not* aborted.

  By default the importer targets `AshPki.Certificate` /
  `AshPki.CertificateAuthority`. Operators with their own resources pass
  `:certificate` in opts; the matching CA is looked up automatically
  through the resource's `pki` block via
  `AshPki.Resource.Certificate.Info`:

      Bulk.import_csv(issuer_id, csv, certificate: MyApp.Certificate)
  """

  NimbleCSV.define(__MODULE__.CSV, separator: ",", escape: "\"")

  @default_certificate AshPki.Certificate

  @doc """
  Bulk-create certs from a CSV blob.

  Returns `{:ok, %{inserted: count, errors: [{line, reason}]}}` or
  `{:error, reason}` when the issuer doesn't exist.

  Options:

    * `:certificate` — the `Certificate` resource module to create rows
      in. Defaults to `AshPki.Certificate`. The matching
      `CertificateAuthority` is read from that module's `pki` section.
    * `:default_vendor` — vendor string used when the row's `vendor`
      column is missing or empty.
  """
  @spec import_csv(Ash.UUID.t(), String.t(), keyword()) ::
          {:ok, %{inserted: non_neg_integer(), errors: [{integer(), term()}]}}
          | {:error, term()}
  def import_csv(issuer_id, csv_blob, opts \\ []) when is_binary(csv_blob) do
    cert_module = Keyword.get(opts, :certificate, @default_certificate)
    ca_module = AshPki.Resource.Certificate.Info.pki_certificate_authority!(cert_module)

    with {:ok, _issuer} <- Ash.get(ca_module, issuer_id, authorize?: false) do
      [header | rows] = __MODULE__.CSV.parse_string(csv_blob, skip_headers: false)
      header = Enum.map(header, &String.trim/1)

      result =
        rows
        |> Stream.with_index(2)
        |> Enum.reduce(
          %{inserted: 0, errors: []},
          &accumulate_csv_row(&1, &2, header, cert_module, issuer_id, opts)
        )

      {:ok, %{result | errors: Enum.reverse(result.errors)}}
    end
  end

  defp accumulate_csv_row({row, line_no}, acc, header, cert_module, issuer_id, opts) do
    row_map = header |> Enum.zip(row) |> Map.new()

    case import_row(cert_module, issuer_id, row_map, opts) do
      :ok -> %{acc | inserted: acc.inserted + 1}
      {:error, reason} -> %{acc | errors: [{line_no, reason} | acc.errors]}
    end
  end

  @doc """
  Bulk-create certs from a PEM bundle (a single string with one or more
  `BEGIN CERTIFICATE … END CERTIFICATE` blocks concatenated).

  Same return shape as `import_csv/3`. The "line" in the error tuple
  is replaced with the cert's 1-based position in the bundle.

  Options:

    * `:certificate` — the `Certificate` resource module to create rows
      in. Defaults to `AshPki.Certificate`.
    * `:vendor` — vendor string applied to every imported cert.
      Default `"custom"`.
  """
  @spec import_pem_bundle(Ash.UUID.t(), String.t(), keyword()) ::
          {:ok, %{inserted: non_neg_integer(), errors: [{integer(), term()}]}}
          | {:error, term()}
  def import_pem_bundle(issuer_id, bundle_pem, opts \\ []) when is_binary(bundle_pem) do
    cert_module = Keyword.get(opts, :certificate, @default_certificate)
    ca_module = AshPki.Resource.Certificate.Info.pki_certificate_authority!(cert_module)

    with {:ok, _issuer} <- Ash.get(ca_module, issuer_id, authorize?: false) do
      cert_pems =
        bundle_pem
        |> String.split("-----BEGIN CERTIFICATE-----", trim: true)
        |> Enum.map(&("-----BEGIN CERTIFICATE-----" <> &1))
        |> Enum.filter(&String.contains?(&1, "-----END CERTIFICATE-----"))
        |> Enum.map(&extract_first_cert/1)

      vendor = Keyword.get(opts, :vendor, "custom")

      result =
        cert_pems
        |> Stream.with_index(1)
        |> Enum.reduce(
          %{inserted: 0, errors: []},
          &accumulate_pem(&1, &2, cert_module, issuer_id, vendor)
        )

      {:ok, %{result | errors: Enum.reverse(result.errors)}}
    end
  end

  defp accumulate_pem({pem, idx}, acc, cert_module, issuer_id, vendor) do
    metadata = %{"vendor" => vendor}

    case cert_module.import_certificate(
           issuer_id,
           pem,
           %{metadata: metadata},
           authorize?: false
         ) do
      {:ok, _cert} -> %{acc | inserted: acc.inserted + 1}
      {:error, reason} -> %{acc | errors: [{idx, summarise_error(reason)} | acc.errors]}
    end
  end

  # ─── helpers ──────────────────────────────────────────────────────────

  defp import_row(cert_module, issuer_id, row_map, opts) do
    with {:ok, pem} <- fetch_required(row_map, "certificate_pem"),
         vendor <- pick_vendor(row_map, opts),
         vendor_meta <- decode_vendor_meta(Map.get(row_map, "vendor_meta")),
         metadata <- build_metadata(row_map, vendor, vendor_meta),
         {:ok, _cert} <-
           cert_module.import_certificate(
             issuer_id,
             pem,
             %{metadata: metadata},
             authorize?: false
           ) do
      :ok
    else
      {:error, reason} -> {:error, summarise_error(reason)}
    end
  end

  defp pick_vendor(row, opts) do
    case Map.get(row, "vendor") do
      nil -> Keyword.get(opts, :default_vendor, "custom")
      "" -> Keyword.get(opts, :default_vendor, "custom")
      v -> v
    end
  end

  defp fetch_required(map, key) do
    case Map.get(map, key) do
      nil -> {:error, {:missing_column, key}}
      "" -> {:error, {:empty_column, key}}
      value -> {:ok, value}
    end
  end

  defp decode_vendor_meta(nil), do: %{}
  defp decode_vendor_meta(""), do: %{}

  defp decode_vendor_meta(json) do
    case Jason.decode(json) do
      {:ok, map} when is_map(map) -> map
      _ -> %{}
    end
  end

  defp build_metadata(row, vendor, vendor_meta) do
    base = %{"vendor" => vendor, "vendor_meta" => vendor_meta}

    case Map.get(row, "serial") do
      nil -> base
      "" -> base
      serial -> Map.put(base, "manifest_serial", serial)
    end
  end

  defp summarise_error(%{__exception__: true} = err), do: Exception.message(err)
  defp summarise_error(reason), do: reason

  defp extract_first_cert(blob) do
    case String.split(blob, "-----END CERTIFICATE-----", parts: 2) do
      [head, _] -> head <> "-----END CERTIFICATE-----\n"
      [head] -> head
    end
  end
end
