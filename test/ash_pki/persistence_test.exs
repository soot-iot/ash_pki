defmodule AshPki.PersistenceTest do
  use AshPki.DataCase, async: false

  alias AshPki.Persistence

  setup do
    dir =
      Path.join(
        System.tmp_dir!(),
        "ash_pki_persistence_#{:erlang.unique_integer([:positive])}"
      )

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    {:ok, dir: dir}
  end

  test "dump! writes a manifest containing every active CA", %{dir: dir} do
    root = Factories.fresh_root!("dump-root")
    intermediate = Factories.fresh_intermediate!(root.id, "dump-int")

    :ok = Persistence.dump!(dir)

    payload =
      dir
      |> Path.join("ash_pki.json")
      |> File.read!()
      |> Jason.decode!()

    assert payload["version"] == 1
    ids = payload["cas"] |> Enum.map(& &1["id"])
    assert root.id in ids
    assert intermediate.id in ids
  end

  test "dump! omits non-active CAs", %{dir: dir} do
    keep = Factories.fresh_root!("kept")
    rotating = Factories.fresh_root!("rotating-out")
    {:ok, _} = AshPki.CertificateAuthority.rotate(rotating, authorize?: false)

    :ok = Persistence.dump!(dir)

    payload =
      dir
      |> Path.join("ash_pki.json")
      |> File.read!()
      |> Jason.decode!()

    ids = payload["cas"] |> Enum.map(& &1["id"])
    assert keep.id in ids
    refute rotating.id in ids
  end

  test "load! restores rows into the data layer", %{dir: dir} do
    original = Factories.fresh_root!("round-trip")
    :ok = Persistence.dump!(dir)

    Factories.reset_ets!()
    assert {:ok, []} = Ash.read(AshPki.CertificateAuthority, authorize?: false)

    :ok = Persistence.load!(dir)
    {:ok, restored} = AshPki.CertificateAuthority.get_by_name("round-trip", authorize?: false)

    assert restored.id == original.id
    assert restored.fingerprint == original.fingerprint
    assert restored.certificate_pem == original.certificate_pem
  end

  test "load! returns :not_found when the manifest is missing", %{dir: dir} do
    File.rm_rf!(dir)
    File.mkdir_p!(dir)
    assert {:error, :not_found} = Persistence.load!(dir)
  end
end
