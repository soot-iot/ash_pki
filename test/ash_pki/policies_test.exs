defmodule AshPki.PoliciesTest do
  @moduledoc """
  Boundary tests for the default `policies` blocks shipped with
  `AshPki.CertificateAuthority`, `AshPki.Certificate`, and
  `AshPki.RevocationList`.

  Each test exercises the System-actor allow list and confirms a
  non-allowed actor is forbidden.
  """

  use ExUnit.Case, async: false

  alias AshPki.Actors

  setup do
    AshPki.Test.Factories.reset_ets!()
    root = AshPki.Test.Factories.fresh_root!("policy-root")
    intermediate = AshPki.Test.Factories.fresh_intermediate!(root.id, "policy-int")
    {:ok, root: root, intermediate: intermediate}
  end

  describe "AshPki.CertificateAuthority" do
    test ":issuer can read", %{intermediate: int} do
      assert {:ok, ^int} =
               Ash.get(AshPki.CertificateAuthority, int.id, actor: Actors.system(:issuer))
    end

    test ":trust_loader can read all active CAs" do
      require Ash.Query

      assert {:ok, [_ | _]} =
               AshPki.CertificateAuthority
               |> Ash.Query.filter(status == :active)
               |> Ash.read(actor: Actors.system(:trust_loader))
    end

    test ":crl_publisher can read", %{intermediate: int} do
      assert {:ok, ^int} =
               Ash.get(AshPki.CertificateAuthority, int.id, actor: Actors.system(:crl_publisher))
    end

    test "no actor is forbidden", %{intermediate: int} do
      assert {:error, %Ash.Error.Forbidden{}} = Ash.get(AshPki.CertificateAuthority, int.id)
    end

    test "non-System actor is forbidden", %{intermediate: int} do
      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.get(AshPki.CertificateAuthority, int.id, actor: %{type: :user})
    end

    test "System actor with an unknown :part is forbidden", %{intermediate: int} do
      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.get(AshPki.CertificateAuthority, int.id,
                 actor: %AshPki.Actors.System{part: :stranger}
               )
    end

    test "admin can read", %{intermediate: int} do
      assert {:ok, ^int} =
               Ash.get(AshPki.CertificateAuthority, int.id, actor: Actors.admin())
    end
  end

  describe "AshPki.Certificate" do
    setup ctx do
      {_, leaf} =
        AshPki.Test.Factories.issue_cert!(ctx.intermediate.id, "/CN=policy-leaf")

      Map.put(ctx, :leaf, leaf)
    end

    test ":issuer can read", %{leaf: leaf} do
      assert {:ok, ^leaf} = Ash.get(AshPki.Certificate, leaf.id, actor: Actors.system(:issuer))
    end

    test ":mtls_resolver can read", %{leaf: leaf} do
      assert {:ok, ^leaf} =
               Ash.get(AshPki.Certificate, leaf.id, actor: Actors.system(:mtls_resolver))
    end

    test ":crl_publisher can read", %{leaf: leaf} do
      assert {:ok, ^leaf} =
               Ash.get(AshPki.Certificate, leaf.id, actor: Actors.system(:crl_publisher))
    end

    test ":trust_loader is forbidden (not in cert allow list)", %{leaf: leaf} do
      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.get(AshPki.Certificate, leaf.id, actor: Actors.system(:trust_loader))
    end

    test "no actor is forbidden", %{leaf: leaf} do
      assert {:error, %Ash.Error.Forbidden{}} = Ash.get(AshPki.Certificate, leaf.id)
    end

    test "admin can read", %{leaf: leaf} do
      assert {:ok, ^leaf} =
               Ash.get(AshPki.Certificate, leaf.id, actor: Actors.admin())
    end
  end

  describe "AshPki.RevocationList" do
    setup ctx do
      {:ok, crl} = AshPki.RevocationList.publish(ctx.intermediate.id, authorize?: false)
      Map.put(ctx, :crl, crl)
    end

    test ":crl_publisher can read", %{crl: crl} do
      assert {:ok, ^crl} =
               Ash.get(AshPki.RevocationList, crl.id, actor: Actors.system(:crl_publisher))
    end

    test ":trust_loader can read", %{crl: crl} do
      assert {:ok, ^crl} =
               Ash.get(AshPki.RevocationList, crl.id, actor: Actors.system(:trust_loader))
    end

    test ":issuer is forbidden (not in CRL allow list)", %{crl: crl} do
      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.get(AshPki.RevocationList, crl.id, actor: Actors.system(:issuer))
    end

    test "no actor is forbidden", %{crl: crl} do
      assert {:error, %Ash.Error.Forbidden{}} = Ash.get(AshPki.RevocationList, crl.id)
    end

    test "admin can read", %{crl: crl} do
      assert {:ok, ^crl} =
               Ash.get(AshPki.RevocationList, crl.id, actor: Actors.admin())
    end
  end
end
