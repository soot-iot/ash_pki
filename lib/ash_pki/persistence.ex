defmodule AshPki.Persistence do
  @moduledoc """
  Lightweight file-backed persistence for the ETS-backed demo.

  Real deployments should run `ash_pki` against AshPostgres (or another
  durable data layer); the resources are unchanged. This module exists so
  the in-repo `mix ash_pki.*` tasks can share state across BEAM invocations
  without forcing a Postgres dependency for a smoke-test demo.

  Layout: a single JSON file per directory, listing CAs and their
  descriptors. Certificates are not persisted here — the issuer cert+key is
  enough to re-sign anything later.
  """

  @manifest "ash_pki.json"

  require Ash.Query

  @doc "Dump every active CA to `<dir>/ash_pki.json`."
  @spec dump!(Path.t()) :: :ok
  def dump!(dir) do
    File.mkdir_p!(dir)

    {:ok, cas} =
      AshPki.CertificateAuthority
      |> Ash.Query.filter(status == :active)
      |> Ash.read(authorize?: false)

    payload = %{
      "version" => 1,
      "cas" =>
        Enum.map(cas, fn ca ->
          %{
            "id" => ca.id,
            "name" => ca.name,
            "role" => Atom.to_string(ca.role),
            "parent_id" => ca.parent_id,
            "key_strategy" => Atom.to_string(ca.key_strategy),
            "key_descriptor" => ca.key_descriptor,
            "certificate_pem" => ca.certificate_pem,
            "subject_dn" => ca.subject_dn,
            "serial" => ca.serial,
            "fingerprint" => ca.fingerprint,
            "not_before" => ca.not_before && DateTime.to_iso8601(ca.not_before),
            "not_after" => ca.not_after && DateTime.to_iso8601(ca.not_after)
          }
        end)
    }

    File.write!(Path.join(dir, @manifest), Jason.encode!(payload, pretty: true))
    :ok
  end

  @doc """
  Load the manifest from `<dir>` and re-insert rows into the ETS data
  layer. Idempotent: rows that already match an id are upserted.
  """
  @spec load!(Path.t()) :: :ok | {:error, :not_found}
  def load!(dir) do
    path = Path.join(dir, @manifest)

    case File.read(path) do
      {:ok, body} ->
        body
        |> Jason.decode!()
        |> Map.fetch!("cas")
        |> Enum.each(&insert_ca/1)

        :ok

      {:error, :enoent} ->
        {:error, :not_found}
    end
  end

  defp insert_ca(payload) do
    {:ok, _} =
      Ash.Seed.seed!(AshPki.CertificateAuthority, %{
        id: payload["id"],
        name: payload["name"],
        role: parse_role(payload["role"]),
        parent_id: payload["parent_id"],
        key_strategy: parse_strategy(payload["key_strategy"]),
        key_descriptor: payload["key_descriptor"],
        certificate_pem: payload["certificate_pem"],
        subject_dn: payload["subject_dn"],
        serial: payload["serial"],
        fingerprint: payload["fingerprint"],
        not_before: parse_dt(payload["not_before"]),
        not_after: parse_dt(payload["not_after"]),
        status: :active
      })
      |> wrap()
  end

  defp wrap(%AshPki.CertificateAuthority{} = ca), do: {:ok, ca}
  defp wrap(other), do: other

  defp parse_dt(nil), do: nil

  defp parse_dt(iso) do
    {:ok, dt, _} = DateTime.from_iso8601(iso)
    dt
  end

  defp parse_role("root"), do: :root
  defp parse_role("intermediate"), do: :intermediate

  defp parse_strategy("software"), do: :software
  defp parse_strategy("pkcs11"), do: :pkcs11
  defp parse_strategy("kms"), do: :kms
  defp parse_strategy("imported"), do: :imported
end
