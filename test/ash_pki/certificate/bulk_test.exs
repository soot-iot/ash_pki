defmodule AshPki.Certificate.BulkTest do
  use AshPki.DataCase, async: false

  alias AshPki.Certificate.Bulk

  # Build a chain-valid cert without going through AshPki.Certificate —
  # the bulk import is what's under test, so we can't pre-create the rows.
  defp issue_pem(intermediate, subject) do
    private = X509.PrivateKey.new_ec(:secp256r1)
    public = X509.PublicKey.derive(private)

    {:ok, issuer_cert} = X509.Certificate.from_pem(intermediate.certificate_pem)
    {:ok, issuer_key} = AshPki.KeyStrategy.Software.private_key(intermediate.key_descriptor)

    cert =
      X509.Certificate.new(public, subject, issuer_cert, issuer_key,
        template: :server,
        validity: 30,
        serial: {:random, 20}
      )

    X509.Certificate.to_pem(cert)
  end

  setup do
    root = Factories.fresh_root!()
    inter = Factories.fresh_intermediate!(root.id)
    {:ok, root: root, intermediate: inter}
  end

  describe "import_csv/3" do
    test "creates one row per valid line", %{intermediate: inter} do
      pem_a = issue_pem(inter, "/CN=device-001")
      pem_b = issue_pem(inter, "/CN=device-002")
      pem_c = issue_pem(inter, "/CN=device-003")

      csv =
        "serial,certificate_pem,vendor\n" <>
          ~s(SN001,"#{escape(pem_a)}",atecc608) <>
          "\n" <>
          ~s(SN002,"#{escape(pem_b)}",atecc608) <>
          "\n" <>
          ~s(SN003,"#{escape(pem_c)}",atecc608) <>
          "\n"

      assert {:ok, %{inserted: 3, errors: []}} = Bulk.import_csv(inter.id, csv)

      {:ok, certs} = AshPki.Certificate.active_for_issuer(inter.id, authorize?: false)
      assert length(certs) == 3
      assert Enum.all?(certs, &(&1.metadata["vendor"] == "atecc608"))
    end

    test "stamps manifest_serial when the CSV has a serial column", %{intermediate: inter} do
      pem = issue_pem(inter, "/CN=device-X")

      csv =
        "serial,certificate_pem,vendor\n" <>
          ~s(VENDOR-SERIAL-1,"#{escape(pem)}",custom) <>
          "\n"

      {:ok, %{inserted: 1}} = Bulk.import_csv(inter.id, csv)

      {:ok, [cert]} = AshPki.Certificate.active_for_issuer(inter.id, authorize?: false)
      assert cert.metadata["manifest_serial"] == "VENDOR-SERIAL-1"
    end

    test "decodes vendor_meta JSON column", %{intermediate: inter} do
      pem = issue_pem(inter, "/CN=device-Y")

      csv =
        "serial,certificate_pem,vendor,vendor_meta\n" <>
          ~s(SN-Y,"#{escape(pem)}",custom,"{""line"":""A"",""rev"":3}") <>
          "\n"

      {:ok, %{inserted: 1}} = Bulk.import_csv(inter.id, csv)

      {:ok, [cert]} = AshPki.Certificate.active_for_issuer(inter.id, authorize?: false)
      assert cert.metadata["vendor_meta"] == %{"line" => "A", "rev" => 3}
    end

    test "skips invalid rows and reports them with line numbers", %{intermediate: inter} do
      pem_ok = issue_pem(inter, "/CN=device-good")

      csv =
        "serial,certificate_pem,vendor\n" <>
          ~s(SN001,"#{escape(pem_ok)}",custom) <>
          "\n" <>
          ~s(SN002,"-----BEGIN CERTIFICATE-----\\nGARBAGE\\n-----END CERTIFICATE-----",custom) <>
          "\n"

      {:ok, %{inserted: 1, errors: errors}} = Bulk.import_csv(inter.id, csv)
      assert length(errors) == 1
      assert {3, _reason} = hd(errors)
    end

    test "default_vendor opt fills the column when vendor is empty", %{intermediate: inter} do
      pem = issue_pem(inter, "/CN=device-default-vendor")

      csv =
        "serial,certificate_pem,vendor\n" <>
          ~s(SN-EMPTY,"#{escape(pem)}",) <>
          "\n"

      {:ok, %{inserted: 1}} =
        Bulk.import_csv(inter.id, csv, default_vendor: "fallback")

      {:ok, [cert]} = AshPki.Certificate.active_for_issuer(inter.id, authorize?: false)
      assert cert.metadata["vendor"] == "fallback"
    end

    test "errors out when issuer doesn't exist" do
      assert {:error, _} = Bulk.import_csv(Ecto.UUID.generate(), "serial,certificate_pem\n")
    end
  end

  describe "import_pem_bundle/3" do
    test "creates one row per cert in the bundle", %{intermediate: inter} do
      bundle =
        Enum.map_join(1..3, "", fn n ->
          issue_pem(inter, "/CN=bundle-device-#{n}")
        end)

      assert {:ok, %{inserted: 3, errors: []}} =
               Bulk.import_pem_bundle(inter.id, bundle, vendor: "edgelock_se05x")

      {:ok, certs} = AshPki.Certificate.active_for_issuer(inter.id, authorize?: false)
      assert length(certs) == 3
      assert Enum.all?(certs, &(&1.metadata["vendor"] == "edgelock_se05x"))
    end

    test "skips garbage between PEM blocks", %{intermediate: inter} do
      pem_a = issue_pem(inter, "/CN=bundle-A")
      pem_b = issue_pem(inter, "/CN=bundle-B")
      bundle = pem_a <> "\n# vendor commentary that isn't a cert\n" <> pem_b

      assert {:ok, %{inserted: 2}} = Bulk.import_pem_bundle(inter.id, bundle)
    end

    test "errors out when issuer doesn't exist" do
      assert {:error, _} =
               Bulk.import_pem_bundle(Ecto.UUID.generate(), "")
    end
  end

  defp escape(pem), do: String.replace(pem, ~s("), ~s(""))
end
