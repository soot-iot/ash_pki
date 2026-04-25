defmodule AshPki.Test.Factories do
  @moduledoc false

  def fresh_root!(name \\ "test-root") do
    {:ok, ca} =
      AshPki.CertificateAuthority.create_root(
        name,
        "/CN=#{name}/O=AshPki Test",
        %{validity_days: 365}
      )

    ca
  end

  def fresh_intermediate!(parent_id, name \\ "test-intermediate") do
    {:ok, ca} =
      AshPki.CertificateAuthority.create_intermediate(
        name,
        parent_id,
        "/CN=#{name}/O=AshPki Test",
        %{validity_days: 180}
      )

    ca
  end

  def fresh_keypair_and_csr(subject) do
    private = X509.PrivateKey.new_ec(:secp256r1)
    csr = X509.CSR.new(private, subject)
    {private, csr, X509.CSR.to_pem(csr)}
  end

  def issue_cert!(issuer_id, subject) do
    {private, _csr, csr_pem} = fresh_keypair_and_csr(subject)

    {:ok, cert} =
      AshPki.Certificate.issue(issuer_id, csr_pem, %{
        template: :client,
        validity_days: 30
      })

    {private, cert}
  end

  def reset_ets! do
    for resource <- [
          AshPki.Certificate,
          AshPki.CertificateAuthority,
          AshPki.RevocationList,
          AshPki.EnrollmentToken
        ] do
      try do
        :ets.delete_all_objects(resource)
      rescue
        _ -> :ok
      end
    end
  end
end
