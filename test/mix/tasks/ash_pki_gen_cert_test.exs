defmodule Mix.Tasks.AshPki.Gen.CertTest do
  use AshPki.DataCase, async: false

  setup do
    out =
      Path.join(
        System.tmp_dir!(),
        "ash_pki_gen_#{:erlang.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf!(out) end)

    Mix.shell(Mix.Shell.Quiet)
    Mix.Tasks.AshPki.Init.run(["--out", out])

    {:ok, out: out}
  end

  test "issues a cert against the named intermediate", %{out: out} do
    args = [
      "--issuer",
      "intermediate",
      "--subject",
      "/CN=gen-cert-test",
      "--name",
      "gen-cert-test",
      "--out",
      out
    ]

    Mix.Tasks.AshPki.Gen.Cert.run(args)

    assert File.exists?(Path.join(out, "gen-cert-test.cert.pem"))
    assert File.exists?(Path.join(out, "gen-cert-test.csr.pem"))
    assert File.exists?(Path.join(out, "gen-cert-test.key.pem"))

    {:ok, cert} =
      X509.Certificate.from_pem(File.read!(Path.join(out, "gen-cert-test.cert.pem")))

    assert AshPki.PKI.subject_string(cert) =~ "CN=gen-cert-test"
  end

  test "parses dns/uri/ip SAN flags", %{out: out} do
    args = [
      "--issuer",
      "intermediate",
      "--subject",
      "/CN=san-test",
      "--name",
      "san-test",
      "--out",
      out,
      "--san",
      "dns:san-test.local",
      "--san",
      "ip:10.0.0.1"
    ]

    Mix.Tasks.AshPki.Gen.Cert.run(args)

    {:ok, cert} =
      X509.Certificate.from_pem(File.read!(Path.join(out, "san-test.cert.pem")))

    sans = AshPki.PKI.subject_alt_names(cert)
    assert Enum.any?(sans, &match?({:dNSName, ~c"san-test.local"}, &1))
    assert Enum.any?(sans, &match?({:iPAddress, _}, &1))
  end
end
