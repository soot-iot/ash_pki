defmodule Mix.Tasks.AshPki.InitTest do
  use AshPki.DataCase, async: false

  setup do
    out =
      Path.join(
        System.tmp_dir!(),
        "ash_pki_init_#{:erlang.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf!(out) end)
    {:ok, out: out}
  end

  test "writes the expected trust material under --out", %{out: out} do
    Mix.shell(Mix.Shell.Quiet)
    Mix.Tasks.AshPki.Init.run(["--out", out, "--server-cn", "init-test.local"])

    assert File.exists?(Path.join(out, "root_ca.pem"))
    assert File.exists?(Path.join(out, "intermediate_ca.pem"))
    assert File.exists?(Path.join(out, "server_cert.pem"))
    assert File.exists?(Path.join(out, "server_chain.pem"))
    assert File.exists?(Path.join(out, "server_key.pem"))
    assert File.exists?(Path.join(out, "trust_bundle.pem"))
    assert File.exists?(Path.join(out, "ash_pki.json"))
  end

  test "the issued server cert chains through the intermediate to the root", %{out: out} do
    Mix.shell(Mix.Shell.Quiet)
    Mix.Tasks.AshPki.Init.run(["--out", out])

    {:ok, root} = X509.Certificate.from_pem(File.read!(Path.join(out, "root_ca.pem")))

    {:ok, inter} =
      X509.Certificate.from_pem(File.read!(Path.join(out, "intermediate_ca.pem")))

    {:ok, leaf} =
      X509.Certificate.from_pem(File.read!(Path.join(out, "server_cert.pem")))

    chain = [X509.Certificate.to_der(inter), X509.Certificate.to_der(leaf)]
    assert {:ok, _} = :public_key.pkix_path_validation(X509.Certificate.to_der(root), chain, [])
  end
end
