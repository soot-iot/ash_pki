defmodule AshPki.RevocationListTest do
  use AshPki.DataCase, async: false

  setup do
    root = Factories.fresh_root!()
    intermediate = Factories.fresh_intermediate!(root.id)
    {:ok, root: root, intermediate: intermediate}
  end

  test "publish/1 produces a CRL containing every revoked cert for the CA", ctx do
    {_p1, leaf1} = Factories.issue_cert!(ctx.intermediate.id, "/CN=d1")
    {_p2, leaf2} = Factories.issue_cert!(ctx.intermediate.id, "/CN=d2")
    {_p3, _leaf3} = Factories.issue_cert!(ctx.intermediate.id, "/CN=d3")

    {:ok, _} = AshPki.Certificate.revoke(leaf1, %{reason: :superseded}, authorize?: false)
    {:ok, _} = AshPki.Certificate.revoke(leaf2, %{reason: :key_compromise}, authorize?: false)

    {:ok, crl_row} = AshPki.RevocationList.publish(ctx.intermediate.id, authorize?: false)

    assert crl_row.sequence == 1
    assert crl_row.status == :current

    [{:CertificateList, _, _, _} = crl_record | _] =
      :public_key.pem_decode(crl_row.crl_pem)
      |> Enum.map(fn entry -> :public_key.pem_entry_decode(entry) end)
      |> List.wrap()

    {:ok, intermediate_cert} = X509.Certificate.from_pem(ctx.intermediate.certificate_pem)
    assert :public_key.pkix_crl_verify(crl_record, intermediate_cert)
  end

  test "publish/1 supersedes the previous current CRL", ctx do
    {_p, leaf} = Factories.issue_cert!(ctx.intermediate.id, "/CN=d1")
    {:ok, _} = AshPki.Certificate.revoke(leaf, %{reason: :superseded}, authorize?: false)

    {:ok, first} = AshPki.RevocationList.publish(ctx.intermediate.id, authorize?: false)
    {:ok, second} = AshPki.RevocationList.publish(ctx.intermediate.id, authorize?: false)

    {:ok, all} = AshPki.RevocationList.for_ca(ctx.intermediate.id, authorize?: false)
    statuses = Map.new(all, &{&1.id, &1.status})

    assert statuses[first.id] == :superseded
    assert statuses[second.id] == :current
    assert second.sequence == first.sequence + 1
  end
end
