defmodule AshPki.CertificateAuthorityTest do
  use AshPki.DataCase, async: false

  test "create_root produces a self-signed CA cert" do
    ca = Factories.fresh_root!("acme-root")

    assert ca.role == :root
    assert ca.status == :active
    assert ca.fingerprint =~ ~r/^[0-9a-f]{64}$/
    assert {:ok, cert} = X509.Certificate.from_pem(ca.certificate_pem)

    assert cert |> X509.Certificate.subject() |> X509.RDNSequence.get_attr(:commonName) == [
             "acme-root"
           ]
  end

  test "create_intermediate is signed by the parent and chains to it" do
    root = Factories.fresh_root!("test-root")
    inter = Factories.fresh_intermediate!(root.id, "test-int")

    assert inter.role == :intermediate
    assert inter.parent_id == root.id

    {:ok, root_cert} = X509.Certificate.from_pem(root.certificate_pem)
    {:ok, inter_cert} = X509.Certificate.from_pem(inter.certificate_pem)

    root_der = X509.Certificate.to_der(root_cert)
    inter_der = X509.Certificate.to_der(inter_cert)
    assert {:ok, _} = :public_key.pkix_path_validation(root_der, [inter_der], [])
  end

  test "get_by_name finds an existing CA" do
    Factories.fresh_root!("findable")

    assert {:ok, ca} = AshPki.CertificateAuthority.get_by_name("findable", authorize?: false)
    assert ca.name == "findable"
  end
end
