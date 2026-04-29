defmodule AshPki.ActorsTest do
  use ExUnit.Case, async: true

  alias AshPki.Actors
  alias AshPki.Actors.System

  describe "system/1" do
    test "builds a System actor" do
      assert %System{part: :issuer, tenant_id: nil} = Actors.system(:issuer)
    end

    for part <- [:issuer, :crl_publisher, :trust_loader, :mtls_resolver] do
      test "accepts :#{part}" do
        part = unquote(part)
        assert %System{part: ^part} = Actors.system(part)
      end
    end
  end

  describe "system/2" do
    test "accepts a tenant_id binary" do
      assert %System{part: :issuer, tenant_id: "t-1"} = Actors.system(:issuer, "t-1")
    end

    test "accepts nil tenant" do
      assert %System{part: :issuer, tenant_id: nil} = Actors.system(:issuer, nil)
    end

    test "accepts keyword opts" do
      assert %System{part: :crl_publisher, tenant_id: "t-x"} =
               Actors.system(:crl_publisher, tenant_id: "t-x")
    end
  end

  describe "%System{}" do
    test "enforces :part" do
      assert_raise ArgumentError, fn -> struct!(System, []) end
    end
  end
end
