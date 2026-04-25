defmodule AshPki.KeyStrategy.PKCS11 do
  @moduledoc """
  Stub for PKCS#11 / HSM-backed keys.

  The interface is shaped so an HSM-backed implementation can drop in:
  the descriptor identifies a slot/object reference (e.g. `slot_id`,
  `key_label`, `pin_env_var`) and signing callbacks delegate to the HSM
  through a PKCS#11 binding.

  No implementation in v1; deferred to Phase 6.
  """
  @behaviour AshPki.KeyStrategy

  @impl true
  def name, do: :pkcs11

  @impl true
  def can_sign?, do: true

  @impl true
  def generate(_opts), do: {:error, :not_implemented}

  @impl true
  def public_key(_descriptor), do: {:error, :not_implemented}

  @impl true
  def sign_csr(_descriptor, _csr, _issuer, _opts), do: {:error, :not_implemented}

  @impl true
  def self_sign(_descriptor, _subject, _opts), do: {:error, :not_implemented}

  @impl true
  def sign_crl(_descriptor, _issuer, _entries, _opts), do: {:error, :not_implemented}
end
