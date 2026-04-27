defmodule AshPki.KeyStrategy.PKCS11Test do
  use ExUnit.Case, async: true

  alias AshPki.KeyStrategy.PKCS11

  describe "name/0 and can_sign?/0" do
    test "the strategy advertises itself as :pkcs11" do
      assert PKCS11.name() == :pkcs11
    end

    test "can sign (in principle)" do
      assert PKCS11.can_sign?()
    end
  end

  describe "generate/1" do
    test "refuses; the operator provisions the HSM externally" do
      assert {:error, {:external_provisioning_required, msg}} = PKCS11.generate([])
      assert msg =~ "pkcs11-tool"
    end
  end

  describe "public_key/1" do
    test "returns the cached PEM when present" do
      private = X509.PrivateKey.new_ec(:secp256r1)
      pub_pem = X509.PublicKey.derive(private) |> X509.PublicKey.to_pem()

      assert {:ok, pub} = PKCS11.public_key(%{"public_key_pem" => pub_pem})
      assert match?({:ECPoint, _}, pub) or is_tuple(pub)
    end

    test "missing PEM is reported" do
      assert {:error, :missing_public_key} = PKCS11.public_key(%{})
    end

    test "garbage PEM is reported" do
      assert {:error, {:invalid_public_key, _}} =
               PKCS11.public_key(%{"public_key_pem" => "not a pem"})
    end
  end

  describe "engine_key/1 — descriptor validation" do
    @valid_descriptor %{
      "type" => "pkcs11",
      "module_path" => "/nonexistent/libsofthsm2.so",
      "key_id" => "pkcs11:object=ca;type=private",
      "algorithm" => "ecdsa",
      "public_key_pem" => "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n",
      "pin_env" => "ASH_PKI_PKCS11_PIN_TEST"
    }

    test "missing module_path is rejected" do
      desc = Map.delete(@valid_descriptor, "module_path")
      assert {:error, {:missing, :module_path}} = PKCS11.engine_key(desc)
    end

    test "missing key_id is rejected" do
      desc = Map.delete(@valid_descriptor, "key_id")
      assert {:error, {:missing, :key_id}} = PKCS11.engine_key(desc)
    end

    test "missing algorithm is rejected" do
      desc = Map.delete(@valid_descriptor, "algorithm")
      assert {:error, {:missing, :algorithm}} = PKCS11.engine_key(desc)
    end

    test "unknown algorithm is rejected" do
      desc = Map.put(@valid_descriptor, "algorithm", "schnorr")
      assert {:error, {:unknown_algorithm, "schnorr"}} = PKCS11.engine_key(desc)
    end

    test "missing pin_env is rejected" do
      desc = Map.delete(@valid_descriptor, "pin_env")
      assert {:error, {:missing, :pin_env}} = PKCS11.engine_key(desc)
    end

    test "unset pin_env env var is rejected" do
      System.delete_env(@valid_descriptor["pin_env"])
      assert {:error, {:pin_env_unset, _}} = PKCS11.engine_key(@valid_descriptor)
    end

    test "missing module is reported as a load failure" do
      System.put_env(@valid_descriptor["pin_env"], "1234")

      try do
        # The valid descriptor points at a non-existent module; engine load
        # surfaces an error rather than crashing.
        assert {:error, _} = PKCS11.engine_key(@valid_descriptor)
      after
        System.delete_env(@valid_descriptor["pin_env"])
      end
    end
  end

  describe "available?/1" do
    test "returns false when the configured module doesn't exist" do
      refute PKCS11.available?(%{
               "module_path" => "/nonexistent/libsofthsm2.so",
               "key_id" => "x",
               "algorithm" => "ecdsa",
               "pin_env" => "X"
             })
    end
  end

  describe "integration (SoftHSM2)" do
    @describetag :pkcs11
    # Regression guard against Erlang `:crypto` / OpenSSL pkcs11-engine
    # behavior changing under us. Runs only when SoftHSM2 + the engine
    # are installed and the env vars below are set; otherwise the test
    # silently passes so the suite stays green on dev machines without a
    # real HSM. Skip explicitly with `mix test --exclude pkcs11`.

    setup do
      module_path = System.get_env("ASH_PKI_PKCS11_MODULE")
      key_id = System.get_env("ASH_PKI_PKCS11_KEY_ID")
      pub_pem = System.get_env("ASH_PKI_PKCS11_PUBLIC_KEY_PEM")
      pin = System.get_env("ASH_PKI_PKCS11_PIN_TEST")

      with false <- is_nil(module_path) or is_nil(key_id) or is_nil(pub_pem) or is_nil(pin),
           descriptor <- %{
             "type" => "pkcs11",
             "module_path" => module_path,
             "key_id" => key_id,
             "algorithm" => System.get_env("ASH_PKI_PKCS11_ALGORITHM", "ecdsa"),
             "public_key_pem" => pub_pem,
             "pin_env" => "ASH_PKI_PKCS11_PIN_TEST"
           },
           true <- PKCS11.available?(descriptor) do
        {:ok, descriptor: descriptor}
      else
        _ -> :ok
      end
    end

    test "self_sign produces a valid root cert", context do
      case context do
        %{descriptor: descriptor} ->
          assert {:ok, cert} =
                   PKCS11.self_sign(descriptor, "/CN=PKCS#11 Root", validity_days: 30)

          pem = X509.Certificate.to_pem(cert)
          assert String.starts_with?(pem, "-----BEGIN CERTIFICATE-----")

        _ ->
          # SoftHSM2 not configured — silently pass.
          :ok
      end
    end
  end
end
