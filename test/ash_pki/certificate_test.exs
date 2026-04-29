defmodule AshPki.CertificateTest do
  use AshPki.DataCase, async: false

  setup do
    root = Factories.fresh_root!()
    intermediate = Factories.fresh_intermediate!(root.id)
    {:ok, root: root, intermediate: intermediate}
  end

  test "issue/2 produces a leaf cert that chains to the intermediate", ctx do
    {_priv, leaf} = Factories.issue_cert!(ctx.intermediate.id, "/CN=device-001")

    assert leaf.status == :active
    assert leaf.issuer_id == ctx.intermediate.id

    {:ok, leaf_cert} = X509.Certificate.from_pem(leaf.certificate_pem)
    {:ok, root_cert} = X509.Certificate.from_pem(ctx.root.certificate_pem)
    {:ok, inter_cert} = X509.Certificate.from_pem(ctx.intermediate.certificate_pem)

    chain = [
      X509.Certificate.to_der(inter_cert),
      X509.Certificate.to_der(leaf_cert)
    ]

    assert {:ok, _} =
             :public_key.pkix_path_validation(X509.Certificate.to_der(root_cert), chain, [])
  end

  test "revoke transitions status and stamps revoked_at", ctx do
    {_priv, leaf} = Factories.issue_cert!(ctx.intermediate.id, "/CN=device-002")

    {:ok, revoked} =
      AshPki.Certificate.revoke(leaf, %{reason: :key_compromise}, authorize?: false)

    assert revoked.status == :revoked
    assert revoked.revocation_reason == :key_compromise
    assert %DateTime{} = revoked.revoked_at
  end

  test "get_by_fingerprint finds known cert", ctx do
    {_priv, leaf} = Factories.issue_cert!(ctx.intermediate.id, "/CN=device-003")

    assert {:ok, found} =
             AshPki.Certificate.get_by_fingerprint(leaf.fingerprint, authorize?: false)

    assert found.id == leaf.id
    assert found.fingerprint == leaf.fingerprint
  end

  test "duplicate fingerprint when issuing same CSR twice yields two distinct rows", ctx do
    {_priv, _csr, csr_pem} = Factories.fresh_keypair_and_csr("/CN=device-dup")

    {:ok, a} = AshPki.Certificate.issue(ctx.intermediate.id, csr_pem, %{}, authorize?: false)
    {:ok, b} = AshPki.Certificate.issue(ctx.intermediate.id, csr_pem, %{}, authorize?: false)

    assert a.id != b.id
    assert a.serial != b.serial
  end
end
