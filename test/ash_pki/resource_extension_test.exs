defmodule AshPki.ResourceExtensionTest do
  @moduledoc """
  Proves that the AshPki resource extensions can be applied to
  consumer-owned resource modules: the extension injects the standard
  schema (attributes, identities, relationships, actions, code interface)
  and any operator additions (extra attributes) sit alongside it.

  The custom modules under `AshPki.Test.Custom.*` are not registered in
  `:ash_pki` config; the default `AshPki.Domain` still drives the rest of
  the test suite. This test only introspects the custom modules.
  """

  use ExUnit.Case, async: true

  alias AshPki.Test.Custom

  defp ensure_function_exported?(module, fun, arity) do
    Code.ensure_loaded!(module)
    function_exported?(module, fun, arity)
  end

  describe "AshPki.Resource.Certificate extension" do
    test "injects the standard attributes plus consumer additions" do
      attrs = Ash.Resource.Info.attributes(Custom.Certificate) |> Enum.map(& &1.name)

      for required <-
            [
              :id,
              :issuer_id,
              :csr_pem,
              :certificate_pem,
              :subject_dn,
              :serial,
              :fingerprint,
              :not_before,
              :not_after,
              :status,
              :revocation_reason,
              :revoked_at,
              :provenance,
              :metadata,
              :inserted_at,
              :updated_at
            ] do
        assert required in attrs, "missing injected attribute: #{required}"
      end

      assert :tenant_id in attrs
      assert :hardware_attestation in attrs
    end

    test "injects the standard identities" do
      names = Ash.Resource.Info.identities(Custom.Certificate) |> Enum.map(& &1.name)
      assert :unique_fingerprint in names
      assert :unique_serial_per_issuer in names
    end

    test "injects the issuer relationship pointing at the resource's declared CA module" do
      assert %{type: :belongs_to, destination: Custom.CertificateAuthority} =
               Ash.Resource.Info.relationship(Custom.Certificate, :issuer)
    end

    test "injects the standard actions" do
      names =
        Custom.Certificate
        |> Ash.Resource.Info.actions()
        |> Enum.map(& &1.name)
        |> MapSet.new()

      for required <-
            [
              :read,
              :destroy,
              :get_by_fingerprint,
              :get_by_serial,
              :active_for_issuer,
              :revoked_for_issuer,
              :issue,
              :import_certificate,
              :revoke
            ] do
        assert required in names, "missing injected action: #{required}"
      end
    end

    test "exposes the standard code interface" do
      assert ensure_function_exported?(Custom.Certificate, :issue, 2)
      assert ensure_function_exported?(Custom.Certificate, :import_certificate, 2)
      assert ensure_function_exported?(Custom.Certificate, :revoke, 1)
      assert ensure_function_exported?(Custom.Certificate, :get_by_fingerprint, 1)
    end
  end

  describe "AshPki.Resource.CertificateAuthority extension" do
    test "injects the standard schema and the consumer addition" do
      attrs = Ash.Resource.Info.attributes(Custom.CertificateAuthority) |> Enum.map(& &1.name)

      for required <-
            [
              :id,
              :name,
              :role,
              :parent_id,
              :key_strategy,
              :key_descriptor,
              :certificate_pem,
              :status
            ] do
        assert required in attrs, "missing injected attribute: #{required}"
      end

      assert :tenant_id in attrs
    end

    test "injects has_many relationships pointing at the resource's declared sibling modules" do
      issued = Ash.Resource.Info.relationship(Custom.CertificateAuthority, :issued_certificates)
      crls = Ash.Resource.Info.relationship(Custom.CertificateAuthority, :revocation_lists)

      assert issued.type == :has_many
      assert issued.destination == Custom.Certificate

      assert crls.type == :has_many
      assert crls.destination == Custom.RevocationList
    end

    test "exposes the standard code interface" do
      assert ensure_function_exported?(Custom.CertificateAuthority, :create_root, 2)
      assert ensure_function_exported?(Custom.CertificateAuthority, :create_intermediate, 3)
      assert ensure_function_exported?(Custom.CertificateAuthority, :get_by_name, 1)
      assert ensure_function_exported?(Custom.CertificateAuthority, :rotate, 1)
    end
  end

  describe "AshPki.Resource.RevocationList extension" do
    test "injects the standard schema and the consumer addition" do
      attrs = Ash.Resource.Info.attributes(Custom.RevocationList) |> Enum.map(& &1.name)

      for required <-
            [:id, :ca_id, :sequence, :crl_pem, :this_update, :next_update, :status] do
        assert required in attrs
      end

      assert :tenant_id in attrs
    end

    test "ca relationship points at the resource's declared CA module" do
      assert %{type: :belongs_to, destination: Custom.CertificateAuthority} =
               Ash.Resource.Info.relationship(Custom.RevocationList, :ca)
    end
  end

  describe "per-extension Info modules (Spark.InfoGenerator)" do
    alias AshPki.Resource.Certificate.Info, as: CertInfo
    alias AshPki.Resource.CertificateAuthority.Info, as: CAInfo
    alias AshPki.Resource.RevocationList.Info, as: CRLInfo

    test "Certificate.Info.pki_certificate_authority!/1 reads the resource's pki section" do
      assert CertInfo.pki_certificate_authority!(Custom.Certificate) ==
               Custom.CertificateAuthority

      # Default resource without a pki block falls back to the shipped default.
      assert CertInfo.pki_certificate_authority!(AshPki.Certificate) ==
               AshPki.CertificateAuthority
    end

    test "CertificateAuthority.Info exposes pki_certificate!/1 and pki_revocation_list!/1" do
      assert CAInfo.pki_certificate!(Custom.CertificateAuthority) == Custom.Certificate
      assert CAInfo.pki_revocation_list!(Custom.CertificateAuthority) == Custom.RevocationList

      assert CAInfo.pki_certificate!(AshPki.CertificateAuthority) == AshPki.Certificate
      assert CAInfo.pki_revocation_list!(AshPki.CertificateAuthority) == AshPki.RevocationList
    end

    test "RevocationList.Info exposes pki_certificate_authority!/1 and pki_certificate!/1" do
      assert CRLInfo.pki_certificate_authority!(Custom.RevocationList) ==
               Custom.CertificateAuthority

      assert CRLInfo.pki_certificate!(Custom.RevocationList) == Custom.Certificate

      assert CRLInfo.pki_certificate_authority!(AshPki.RevocationList) ==
               AshPki.CertificateAuthority

      assert CRLInfo.pki_certificate!(AshPki.RevocationList) == AshPki.Certificate
    end

    test "lenient variants return {:ok, value} with the default applied" do
      # Spark.InfoGenerator generates a `pki_<option>/1` lenient lookup
      # (returns `{:ok, value}` or `:error`) alongside the bang version.
      assert {:ok, Custom.CertificateAuthority} =
               CertInfo.pki_certificate_authority(Custom.Certificate)

      assert {:ok, AshPki.CertificateAuthority} =
               CertInfo.pki_certificate_authority(AshPki.Certificate)
    end
  end

  describe "AshPki.Resource.EnrollmentToken extension" do
    test "injects the standard schema and the consumer addition" do
      attrs = Ash.Resource.Info.attributes(Custom.EnrollmentToken) |> Enum.map(& &1.name)

      for required <- [:id, :token_hash, :scope, :scope_ref, :valid_until, :used_at] do
        assert required in attrs
      end

      assert :tenant_id in attrs
    end

    test "exposes the standard code interface" do
      assert ensure_function_exported?(Custom.EnrollmentToken, :mint, 3)
      assert ensure_function_exported?(Custom.EnrollmentToken, :consume, 1)
      assert ensure_function_exported?(Custom.EnrollmentToken, :find_by_plaintext, 1)
    end
  end

  describe "consumer-owned PKI hierarchy end-to-end" do
    # Exercises the full issue → revoke → publish CRL flow on the
    # Custom.* resources. Internal changes look up siblings via the
    # `pki do ... end` block, so this works without any application-global
    # config — multiple PKI hierarchies can coexist in one app.

    setup do
      for resource <- [
            Custom.CertificateAuthority,
            Custom.Certificate,
            Custom.RevocationList
          ] do
        try do
          :ets.delete_all_objects(resource)
        rescue
          ArgumentError -> :ok
        end
      end

      :ok
    end

    test "issue + revoke + publish CRL all run through the consumer modules" do
      {:ok, root} =
        Custom.CertificateAuthority.create_root(
          "custom-root",
          "/CN=custom-root/O=AshPki Test",
          %{validity_days: 90}
        )

      assert root.role == :root
      assert root.fingerprint =~ ~r/^[0-9a-f]{64}$/

      private = X509.PrivateKey.new_ec(:secp256r1)
      csr_pem = X509.CSR.new(private, "/CN=custom-leaf") |> X509.CSR.to_pem()

      {:ok, cert} =
        Custom.Certificate.issue(root.id, csr_pem, %{template: :client, validity_days: 30})

      assert cert.status == :active
      assert cert.issuer_id == root.id

      {:ok, revoked} = Custom.Certificate.revoke(cert, %{reason: :key_compromise})
      assert revoked.status == :revoked
      assert revoked.revocation_reason == :key_compromise

      {:ok, crl} = Custom.RevocationList.publish(root.id)
      assert crl.ca_id == root.id
      assert crl.status == :current
      assert is_binary(crl.crl_pem)
      assert {:ok, _} = X509.CRL.from_pem(crl.crl_pem)
    end

    test "two separate hierarchies coexist via per-resource sibling lookups" do
      # Run the same flow on the shipped defaults inside this test to
      # prove the Custom.* hierarchy and the AshPki.* hierarchy do not
      # share state.
      AshPki.Test.Factories.reset_ets!()

      default_root =
        AshPki.CertificateAuthority.create_root!(
          "shared-default-root",
          "/CN=shared-default-root",
          %{validity_days: 90},
          authorize?: false
        )

      {:ok, custom_root} =
        Custom.CertificateAuthority.create_root(
          "shared-custom-root",
          "/CN=shared-custom-root",
          %{validity_days: 90},
          authorize?: false
        )

      # Each hierarchy stores its CAs in its own ETS table; neither sees
      # the other.
      assert {:ok, _} =
               AshPki.CertificateAuthority.get_by_name("shared-default-root", authorize?: false)

      assert {:error, _} =
               AshPki.CertificateAuthority.get_by_name("shared-custom-root", authorize?: false)

      assert {:ok, _} = Custom.CertificateAuthority.get_by_name("shared-custom-root")
      assert {:error, _} = Custom.CertificateAuthority.get_by_name("shared-default-root")

      # And they don't share IDs either.
      refute default_root.id == custom_root.id
    end
  end
end
