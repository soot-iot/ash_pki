defmodule AshPki.Actors do
  @moduledoc """
  Actor factory for `ash_pki`.

  Two actor kinds flow into AshPki policy evaluation:

    * `System` — an internal subsystem with no end-user, scoped by a
      `:part` atom (`:issuer`, `:crl_publisher`, `:trust_loader`,
      `:mtls_resolver`). Library code that previously passed
      `authorize?: false` now passes a `System` actor so policies can
      reason about which subsystem is acting.

    * Caller-supplied actors (User, Device, etc.) — operator code
      passes its own actor for user-initiated operations like
      `Certificate.issue/3` from an admin UI.

  See the umbrella `soot/POLICY-SPEC.md` for the cross-library actor
  contract. Operator apps generate their own `MyApp.Actors` which
  re-exports the `system/1,2` and adds project-specific actors.
  """

  alias AshPki.Actors.System

  @type system_part :: System.part()

  @doc "Build a `System` actor for an internal subsystem."
  @spec system(system_part()) :: System.t()
  def system(part) when is_atom(part), do: %System{part: part}

  @spec system(system_part(), keyword() | binary() | nil) :: System.t()
  def system(part, tenant_id) when is_atom(part) and is_binary(tenant_id),
    do: %System{part: part, tenant_id: tenant_id}

  def system(part, nil) when is_atom(part), do: %System{part: part}

  def system(part, opts) when is_atom(part) and is_list(opts),
    do: %System{part: part, tenant_id: Keyword.get(opts, :tenant_id)}
end
