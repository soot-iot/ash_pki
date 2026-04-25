defmodule AshPki.PKITest do
  use ExUnit.Case, async: true

  alias AshPki.PKI

  defp leaf_chain do
    root_priv = X509.PrivateKey.new_ec(:secp256r1)
    root = X509.Certificate.self_signed(root_priv, "/CN=test-root", template: :root_ca)

    inter_priv = X509.PrivateKey.new_ec(:secp256r1)
    inter_csr = X509.CSR.new(inter_priv, "/CN=test-int")

    inter =
      X509.Certificate.new(
        X509.CSR.public_key(inter_csr),
        X509.CSR.subject(inter_csr),
        root,
        root_priv,
        template: :ca,
        validity: 365
      )

    leaf_priv = X509.PrivateKey.new_ec(:secp256r1)
    leaf_csr = X509.CSR.new(leaf_priv, "/CN=leaf")

    leaf =
      X509.Certificate.new(
        X509.CSR.public_key(leaf_csr),
        X509.CSR.subject(leaf_csr),
        inter,
        inter_priv,
        template: :server,
        validity: 30
      )

    %{root: root, intermediate: inter, leaf: leaf}
  end

  test "fingerprint/1 returns a 64-char lowercase hex string" do
    %{leaf: leaf} = leaf_chain()
    fp = PKI.fingerprint(leaf)
    assert fp =~ ~r/^[0-9a-f]{64}$/
  end

  test "fingerprint_pem/1 round-trips with fingerprint/1" do
    %{leaf: leaf} = leaf_chain()
    pem = X509.Certificate.to_pem(leaf)
    assert {:ok, fp} = PKI.fingerprint_pem(pem)
    assert fp == PKI.fingerprint(leaf)
  end

  test "serial_string/1 returns a decimal string" do
    %{leaf: leaf} = leaf_chain()
    serial = PKI.serial_string(leaf)
    assert {_, ""} = Integer.parse(serial)
  end

  test "subject_string/1 renders the RDN" do
    %{leaf: leaf} = leaf_chain()
    assert PKI.subject_string(leaf) =~ "CN=leaf"
  end

  test "validity_window/1 returns DateTime tuples in ascending order" do
    %{leaf: leaf} = leaf_chain()
    {nb, na} = PKI.validity_window(leaf)
    assert %DateTime{} = nb
    assert %DateTime{} = na
    assert DateTime.compare(nb, na) == :lt
  end

  test "parse_chain/1 returns leaf-first order from a bundle" do
    %{leaf: leaf, intermediate: inter} = leaf_chain()
    bundle = X509.Certificate.to_pem(leaf) <> X509.Certificate.to_pem(inter)

    assert {:ok, [a, b]} = PKI.parse_chain(bundle)
    assert PKI.fingerprint(a) == PKI.fingerprint(leaf)
    assert PKI.fingerprint(b) == PKI.fingerprint(inter)
  end

  test "parse_chain/1 errors when no certs in the PEM" do
    assert {:error, :no_certificates} = PKI.parse_chain("garbage")
  end

  test "verify/3 accepts a chain that anchors at any of multiple roots" do
    %{root: root1, leaf: leaf, intermediate: inter} = leaf_chain()
    %{root: root2} = leaf_chain()

    # Put root1 second to force the iterate-each-root branch.
    assert {:ok, chain} = PKI.verify(leaf, [root2, root1], [inter])
    assert List.last(chain) == root1
  end

  test "verify/3 rejects chains that don't anchor to any root" do
    %{root: rogue} = leaf_chain()
    %{leaf: leaf, intermediate: inter} = leaf_chain()
    assert {:error, :path_validation_failed} = PKI.verify(leaf, [rogue], [inter])
  end

  test "verify/3 returns :no_trusted_roots for empty trust list" do
    %{leaf: leaf} = leaf_chain()
    assert {:error, :no_trusted_roots} = PKI.verify(leaf, [], [])
  end
end
