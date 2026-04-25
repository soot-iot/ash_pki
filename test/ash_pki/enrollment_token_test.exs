defmodule AshPki.EnrollmentTokenTest do
  use AshPki.DataCase, async: false

  alias AshPki.EnrollmentToken

  defp valid_until, do: DateTime.utc_now() |> DateTime.add(3600, :second)

  test "mint stores only a hash and returns the plaintext via metadata" do
    {:ok, token} = EnrollmentToken.mint(:device, "serial-001", valid_until())

    plaintext = Ash.Resource.get_metadata(token, :plaintext_token)
    assert is_binary(plaintext)
    assert byte_size(plaintext) > 32
    refute plaintext == token.token_hash

    expected_hash =
      :crypto.hash(:sha256, plaintext) |> Base.encode16(case: :lower)

    assert token.token_hash == expected_hash
  end

  test "mint produces unique plaintext on each call" do
    {:ok, a} = EnrollmentToken.mint(:device, "a", valid_until())
    {:ok, b} = EnrollmentToken.mint(:device, "b", valid_until())

    assert Ash.Resource.get_metadata(a, :plaintext_token) !=
             Ash.Resource.get_metadata(b, :plaintext_token)

    assert a.token_hash != b.token_hash
  end

  test "find_by_plaintext locates the token by its hash" do
    {:ok, token} = EnrollmentToken.mint(:device, "serial-002", valid_until())
    plaintext = Ash.Resource.get_metadata(token, :plaintext_token)

    assert {:ok, found} = EnrollmentToken.find_by_plaintext(plaintext)
    assert found.id == token.id
  end

  test "find_by_plaintext returns error for an unknown token" do
    assert {:error, _} = EnrollmentToken.find_by_plaintext("nope")
  end

  test "consume stamps used_at" do
    {:ok, token} = EnrollmentToken.mint(:device, "serial-003", valid_until())
    refute token.used_at

    {:ok, consumed} = EnrollmentToken.consume(token)
    assert %DateTime{} = consumed.used_at
  end
end
