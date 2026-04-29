defmodule AshPki.Plug.MTLSTest do
  use AshPki.DataCase, async: false
  import Plug.Test
  import Plug.Conn

  alias AshPki.Plug.MTLS

  setup do
    root = Factories.fresh_root!("mtls-root")
    intermediate = Factories.fresh_intermediate!(root.id, "mtls-int")
    {private, leaf} = Factories.issue_cert!(intermediate.id, "/CN=mtls-test-client")

    {:ok, root: root, intermediate: intermediate, private: private, leaf: leaf}
  end

  defp call_with_header(pem, opts) do
    :get
    |> conn("/")
    |> put_req_header("x-client-cert", URI.encode(pem, &URI.char_unreserved?/1))
    |> MTLS.call(MTLS.init(opts))
  end

  test "valid known cert assigns the actor", ctx do
    conn =
      call_with_header(ctx.leaf.certificate_pem,
        header_mode: {:enabled, "x-client-cert"},
        require_known_certificate: true
      )

    refute conn.halted
    actor = conn.assigns[:ash_pki_actor]
    assert %MTLS.Actor{} = actor
    assert actor.fingerprint == ctx.leaf.fingerprint
    assert actor.certificate_id == ctx.leaf.id
    assert actor.issuer_id == ctx.intermediate.id
  end

  test "revoked cert is rejected when require_known_certificate is true", ctx do
    {:ok, _} = AshPki.Certificate.revoke(ctx.leaf, %{reason: :key_compromise}, authorize?: false)

    conn =
      call_with_header(ctx.leaf.certificate_pem,
        header_mode: {:enabled, "x-client-cert"},
        require_known_certificate: true
      )

    assert conn.halted
    assert conn.status == 403
  end

  test "unknown but chain-valid cert allowed when require_known? is false" do
    other_root = Factories.fresh_root!("other-root")
    other_inter = Factories.fresh_intermediate!(other_root.id, "other-int")
    {_priv, other_cert} = Factories.issue_cert!(other_inter.id, "/CN=stranger")
    cert_pem = other_cert.certificate_pem

    # Wipe the cert row so it's not on file, but keep the CAs (so chain is valid)
    :ets.delete_all_objects(AshPki.Certificate)

    conn =
      call_with_header(cert_pem,
        header_mode: {:enabled, "x-client-cert"},
        require_known_certificate: false
      )

    refute conn.halted
    actor = conn.assigns[:ash_pki_actor]
    assert actor.fingerprint != nil
    assert actor.certificate_id == nil
  end

  test "rejects when no trust anchor matches" do
    rogue_priv = X509.PrivateKey.new_ec(:secp256r1)
    rogue = X509.Certificate.self_signed(rogue_priv, "/CN=rogue", template: :root_ca)
    rogue_pem = X509.Certificate.to_pem(rogue)

    conn =
      call_with_header(rogue_pem,
        header_mode: {:enabled, "x-client-cert"},
        require_known_certificate: false
      )

    assert conn.halted
    assert conn.status == 403
  end

  test "halt mode :assign_only sets ash_pki_mtls_error and continues" do
    rogue_priv = X509.PrivateKey.new_ec(:secp256r1)
    rogue = X509.Certificate.self_signed(rogue_priv, "/CN=rogue", template: :root_ca)
    rogue_pem = X509.Certificate.to_pem(rogue)

    conn =
      call_with_header(rogue_pem,
        header_mode: {:enabled, "x-client-cert"},
        require_known_certificate: false,
        on_failure: :assign_only
      )

    refute conn.halted
    assert conn.assigns[:ash_pki_mtls_error] != nil
  end
end
