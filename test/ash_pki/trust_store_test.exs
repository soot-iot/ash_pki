defmodule AshPki.TrustStoreTest do
  use AshPki.DataCase, async: false

  alias AshPki.TrustStore

  setup do
    on_exit(fn -> Application.delete_env(:ash_pki, :pinned_roots) end)
    :ok
  end

  test "active_cas/0 returns OTPCertificates for every active CA" do
    a = Factories.fresh_root!("active-a")
    b = Factories.fresh_root!("active-b")

    fps =
      TrustStore.active_cas()
      |> Enum.map(&AshPki.PKI.fingerprint/1)
      |> Enum.sort()

    assert Enum.sort([a.fingerprint, b.fingerprint]) == fps
  end

  test "active_cas/0 skips rotated CAs" do
    a = Factories.fresh_root!("still-active")
    rotated = Factories.fresh_root!("rotating")
    {:ok, _} = AshPki.CertificateAuthority.rotate(rotated, authorize?: false)

    fps = Enum.map(TrustStore.active_cas(), &AshPki.PKI.fingerprint/1)
    assert a.fingerprint in fps
    refute rotated.fingerprint in fps
  end

  test "pinned_roots/0 reads PEM certificates from configured files" do
    pinned = Factories.fresh_root!("pinned-only")

    path =
      Path.join(System.tmp_dir!(), "trust-store-test-#{:erlang.unique_integer([:positive])}.pem")

    File.write!(path, pinned.certificate_pem)

    Application.put_env(:ash_pki, :pinned_roots, [path])

    fps = Enum.map(TrustStore.pinned_roots(), &AshPki.PKI.fingerprint/1)
    assert pinned.fingerprint in fps
  after
    Application.delete_env(:ash_pki, :pinned_roots)
  end

  test "pinned_roots/0 silently skips missing files" do
    Application.put_env(:ash_pki, :pinned_roots, ["/nonexistent/path.pem"])
    assert TrustStore.pinned_roots() == []
  end

  test "trust_anchors/0 dedupes between active CAs and pinned roots" do
    ca = Factories.fresh_root!("dedupe")
    path = Path.join(System.tmp_dir!(), "trust-dedupe-#{:erlang.unique_integer([:positive])}.pem")
    File.write!(path, ca.certificate_pem)

    Application.put_env(:ash_pki, :pinned_roots, [path])

    anchors = TrustStore.trust_anchors()

    fps = Enum.map(anchors, &AshPki.PKI.fingerprint/1)
    assert Enum.count(fps, &(&1 == ca.fingerprint)) == 1
  after
    Application.delete_env(:ash_pki, :pinned_roots)
  end
end
