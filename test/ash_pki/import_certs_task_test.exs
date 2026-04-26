defmodule AshPki.ImportCertsTaskTest do
  use AshPki.DataCase, async: false

  @tmp Path.join(System.tmp_dir!(), "ash_pki_import_certs_test")

  setup do
    File.rm_rf!(@tmp)
    File.mkdir_p!(@tmp)
    on_exit(fn -> File.rm_rf!(@tmp) end)

    root = Factories.fresh_root!()
    intermediate = Factories.fresh_intermediate!(root.id)
    {:ok, root: root, intermediate: intermediate}
  end

  defp build_pem(intermediate, subject) do
    private = X509.PrivateKey.new_ec(:secp256r1)
    public = X509.PublicKey.derive(private)
    {:ok, issuer_cert} = X509.Certificate.from_pem(intermediate.certificate_pem)
    {:ok, issuer_key} = AshPki.KeyStrategy.Software.private_key(intermediate.key_descriptor)

    X509.Certificate.new(public, subject, issuer_cert, issuer_key,
      template: :server,
      validity: 30,
      serial: {:random, 20}
    )
    |> X509.Certificate.to_pem()
  end

  test "--cert imports a single PEM file", %{intermediate: inter} do
    pem = build_pem(inter, "/CN=lonely-device")
    path = Path.join(@tmp, "single.pem")
    File.write!(path, pem)

    ExUnit.CaptureIO.capture_io(fn ->
      Mix.Tasks.AshPki.ImportCerts.run([
        "--issuer",
        inter.name,
        "--cert",
        path,
        "--vendor",
        "atecc608"
      ])
    end)

    {:ok, [cert]} = AshPki.Certificate.active_for_issuer(inter.id, authorize?: false)
    assert cert.metadata["vendor"] == "atecc608"
  end

  test "--bundle imports a multi-cert PEM", %{intermediate: inter} do
    bundle =
      Enum.map_join(1..2, "", fn n -> build_pem(inter, "/CN=bundle-#{n}") end)

    path = Path.join(@tmp, "bundle.pem")
    File.write!(path, bundle)

    ExUnit.CaptureIO.capture_io(fn ->
      Mix.Tasks.AshPki.ImportCerts.run([
        "--issuer",
        inter.name,
        "--bundle",
        path,
        "--vendor",
        "edgelock_se05x"
      ])
    end)

    {:ok, certs} = AshPki.Certificate.active_for_issuer(inter.id, authorize?: false)
    assert length(certs) == 2
  end

  test "errors out when no input source is given", %{intermediate: inter} do
    assert_raise Mix.Error, fn ->
      Mix.Tasks.AshPki.ImportCerts.run(["--issuer", inter.name])
    end
  end

  test "errors out when --csv and --bundle are both given", %{intermediate: inter} do
    assert_raise Mix.Error, fn ->
      Mix.Tasks.AshPki.ImportCerts.run([
        "--issuer",
        inter.name,
        "--csv",
        "/tmp/x.csv",
        "--bundle",
        "/tmp/y.pem"
      ])
    end
  end
end
