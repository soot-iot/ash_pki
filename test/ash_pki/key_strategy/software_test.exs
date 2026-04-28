defmodule AshPki.KeyStrategy.SoftwareTest do
  use ExUnit.Case, async: true

  alias AshPki.KeyStrategy.Software

  describe "sign/3" do
    test "produces a signature that verifies against the descriptor's public key" do
      assert {:ok, descriptor} = Software.generate(type: :ec)
      body = "the contents of a contract bundle manifest"

      assert {:ok, signature} = Software.sign(descriptor, body)
      assert is_binary(signature)
      assert byte_size(signature) > 0

      {:ok, public} = Software.public_key(descriptor)
      assert :public_key.verify(body, :sha256, signature, public)
    end

    test "honours :digest_alg" do
      assert {:ok, descriptor} = Software.generate(type: :ec)
      body = "stuff"

      assert {:ok, sig_default} = Software.sign(descriptor, body)
      assert {:ok, sig_sha512} = Software.sign(descriptor, body, digest_alg: :sha512)

      {:ok, public} = Software.public_key(descriptor)
      assert :public_key.verify(body, :sha256, sig_default, public)
      assert :public_key.verify(body, :sha512, sig_sha512, public)
    end

    test "missing private key surfaces a clean error" do
      descriptor = %{"type" => "software"}
      assert {:error, :missing_private_key} = Software.sign(descriptor, "x")
    end
  end
end
