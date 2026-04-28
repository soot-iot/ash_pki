defmodule AshPki.KeyStrategy.ImportedTest do
  use ExUnit.Case, async: true

  alias AshPki.KeyStrategy.Imported

  defp self_signed_pem do
    priv = X509.PrivateKey.new_ec(:secp256r1)
    cert = X509.Certificate.self_signed(priv, "/CN=imported-test", template: :root_ca)
    X509.Certificate.to_pem(cert)
  end

  test "name and can_sign?" do
    assert Imported.name() == :imported
    refute Imported.can_sign?()
  end

  test "all signing callbacks return :no_signing_capability" do
    assert {:error, :no_signing_capability} = Imported.generate([])
    assert {:error, :no_signing_capability} = Imported.sign_csr(%{}, nil, nil, [])
    assert {:error, :no_signing_capability} = Imported.self_sign(%{}, "/CN=x", [])
    assert {:error, :no_signing_capability} = Imported.sign_crl(%{}, nil, [], [])
    assert {:error, :no_signing_capability} = Imported.sign(%{}, "body", [])
  end

  test "import_public extracts the public key and stores vendor metadata" do
    pem = self_signed_pem()

    assert {:ok, descriptor} = Imported.import_public(pem, vendor: :atecc608)

    assert descriptor["type"] == "imported"
    assert descriptor["vendor"] == "atecc608"
    assert is_binary(descriptor["public_key_pem"])
    assert descriptor["public_key_pem"] =~ "-----BEGIN PUBLIC KEY-----"
  end

  test "import_public defaults vendor to \"custom\" and round-trips through public_key/1" do
    pem = self_signed_pem()
    assert {:ok, descriptor} = Imported.import_public(pem, [])

    assert descriptor["vendor"] == "custom"
    assert {:ok, _key} = Imported.public_key(descriptor)
  end

  test "import_public returns an error for malformed PEM" do
    assert {:error, _} = Imported.import_public("not a pem", [])
  end

  test "public_key without descriptor field returns :missing_public_key" do
    assert {:error, :missing_public_key} = Imported.public_key(%{})
  end
end
