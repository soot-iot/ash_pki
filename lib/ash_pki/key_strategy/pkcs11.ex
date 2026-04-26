defmodule AshPki.KeyStrategy.PKCS11 do
  @moduledoc """
  PKCS#11 / HSM-backed CA signing keys.

  Backed by Erlang's `:crypto` engine API: the OpenSSL pkcs11 engine
  bridges to a PKCS#11 module (SoftHSM2, AWS CloudHSM, YubiHSM, etc).
  No third-party Elixir/Erlang library is required — everything goes
  through `:crypto.engine_load/3` and `:public_key.pkix_sign/2` with
  an engine-key reference.

  ## Descriptor shape

      %{
        "type"           => "pkcs11",
        "module_path"    => "/usr/lib/softhsm/libsofthsm2.so",
        "engine_path"    => nil | "/usr/lib/.../engines-3/pkcs11.so",
        "key_id"         => "pkcs11:object=my-ca;type=private",
        "algorithm"      => "ecdsa" | "rsa",
        "public_key_pem" => "-----BEGIN PUBLIC KEY-----...",
        "pin_env"        => "ASH_PKI_HSM_PIN"
      }

  - `module_path` — the underlying PKCS#11 module's `.so`.
  - `engine_path` — optional override; defaults to whatever OpenSSL's
    `dynamic` engine resolves `pkcs11` to.
  - `key_id` — a PKCS#11 URI selecting the private key. Operators
    typically discover this with `pkcs11-tool --list-objects`.
  - `algorithm` — pinned to the key type so signature digests use the
    right signer.
  - `public_key_pem` — cached; read out at provisioning time with
    `pkcs11-tool --read-object`. Avoids a round trip on every
    `public_key/1` call.
  - `pin_env` — the OS env var the PIN lives in. The PIN itself is
    **never** stored in the descriptor.

  ## Provisioning

  Key generation is intentionally not supported through this strategy.
  Operators provision the HSM externally (via `pkcs11-tool --keypairgen`
  or vendor tooling) and import the descriptor. `generate/1` returns
  `{:error, :external_provisioning_required}` with a hint.
  """

  @behaviour AshPki.KeyStrategy

  @impl true
  def name, do: :pkcs11

  @impl true
  def can_sign?, do: true

  @impl true
  def generate(_opts) do
    {:error,
     {:external_provisioning_required,
      "Generate the keypair in the HSM with `pkcs11-tool --keypairgen` (or vendor tooling), " <>
        "then build a descriptor with module_path, key_id, algorithm, public_key_pem, pin_env."}}
  end

  @impl true
  def public_key(%{"public_key_pem" => pem}) when is_binary(pem) do
    case X509.PublicKey.from_pem(pem) do
      {:ok, key} -> {:ok, key}
      {:error, reason} -> {:error, {:invalid_public_key, reason}}
    end
  end

  def public_key(_), do: {:error, :missing_public_key}

  @impl true
  def sign_csr(descriptor, csr, issuer_cert, opts \\ []) do
    with {:ok, engine_key} <- engine_key(descriptor),
         true <- X509.CSR.valid?(csr) || {:error, :invalid_csr_signature} do
      subject = X509.CSR.subject(csr)
      public = X509.CSR.public_key(csr)

      cert =
        X509.Certificate.new(public, subject, issuer_cert, engine_key,
          template: Keyword.get(opts, :template, :server),
          validity: Keyword.get(opts, :validity_days, 90),
          extensions: Keyword.get(opts, :extensions, []),
          hash: Keyword.get(opts, :hash, :sha256),
          serial: Keyword.get(opts, :serial, {:random, 20})
        )

      {:ok, cert}
    end
  rescue
    error -> {:error, error}
  end

  @impl true
  def self_sign(descriptor, subject, opts \\ []) do
    with {:ok, engine_key} <- engine_key(descriptor) do
      cert =
        X509.Certificate.self_signed(engine_key, subject,
          template: Keyword.get(opts, :template, :root_ca),
          validity: Keyword.get(opts, :validity_days, 365 * 10),
          hash: Keyword.get(opts, :hash, :sha256),
          serial: Keyword.get(opts, :serial, {:random, 20}),
          extensions: Keyword.get(opts, :extensions, [])
        )

      {:ok, cert}
    end
  rescue
    error -> {:error, error}
  end

  @impl true
  def sign_crl(descriptor, issuer_cert, entries, opts \\ []) do
    with {:ok, engine_key} <- engine_key(descriptor) do
      crl =
        X509.CRL.new(entries, issuer_cert, engine_key,
          hash: Keyword.get(opts, :hash, :sha256),
          next_update_in_days: Keyword.get(opts, :next_update_in_days, 7)
        )

      {:ok, crl}
    end
  rescue
    error -> {:error, error}
  end

  # ─── descriptor + engine helpers ───────────────────────────────────────

  @doc """
  Build the engine-key reference Erlang's `:public_key` understands.

  The reference is shaped `%{algorithm:, engine:, key_id:, password:}`.
  This function returns it as `{:ok, ref}` or surfaces the configuration
  error.
  """
  @spec engine_key(map()) :: {:ok, map()} | {:error, term()}
  def engine_key(descriptor) do
    # Descriptor validation runs before the engine load so a misconfigured
    # operator gets `{:missing, …}` / `:pin_env_unset` rather than the
    # opaque `:bad_engine_id` from OpenSSL.
    with {:ok, algorithm} <- fetch_algorithm(descriptor),
         {:ok, key_id} <- fetch_key_id(descriptor),
         {:ok, _module} <- fetch_module_path(descriptor),
         {:ok, pin} <- fetch_pin(descriptor),
         {:ok, engine} <- ensure_engine_loaded(descriptor) do
      {:ok,
       %{
         algorithm: algorithm,
         engine: engine,
         key_id: key_id,
         password: pin
       }}
    end
  end

  @doc """
  Whether the configured PKCS#11 engine + module can actually be loaded
  on this host. Used by tests to skip integration paths.
  """
  @spec available?(map()) :: boolean()
  def available?(descriptor) do
    case ensure_engine_loaded(descriptor) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  defp fetch_algorithm(%{"algorithm" => "ecdsa"}), do: {:ok, :ecdsa}
  defp fetch_algorithm(%{"algorithm" => "rsa"}), do: {:ok, :rsa}

  defp fetch_algorithm(%{"algorithm" => other}),
    do: {:error, {:unknown_algorithm, other}}

  defp fetch_algorithm(_), do: {:error, {:missing, :algorithm}}

  defp fetch_key_id(%{"key_id" => key_id}) when is_binary(key_id), do: {:ok, key_id}
  defp fetch_key_id(_), do: {:error, {:missing, :key_id}}

  defp fetch_pin(%{"pin_env" => env_var}) when is_binary(env_var) do
    case System.get_env(env_var) do
      nil -> {:error, {:pin_env_unset, env_var}}
      "" -> {:error, {:pin_env_unset, env_var}}
      pin -> {:ok, pin}
    end
  end

  defp fetch_pin(_), do: {:error, {:missing, :pin_env}}

  defp fetch_module_path(%{"module_path" => path}) when is_binary(path) and path != "",
    do: {:ok, path}

  defp fetch_module_path(_), do: {:error, {:missing, :module_path}}

  defp ensure_engine_loaded(descriptor) do
    case Map.get(descriptor, "module_path") do
      nil ->
        {:error, {:missing, :module_path}}

      module_path ->
        engine_id = "pkcs11"

        post_cmds =
          case Map.get(descriptor, "engine_path") do
            nil -> [{"MODULE_PATH", module_path}]
            engine_path -> [{"SO_PATH", engine_path}, {"MODULE_PATH", module_path}]
          end

        case do_engine_load(engine_id, post_cmds) do
          {:ok, engine} -> {:ok, engine}
          {:error, _} = err -> err
        end
    end
  rescue
    error -> {:error, {:engine_load_failed, Exception.message(error)}}
  end

  defp do_engine_load(engine_id, post_cmds) do
    case :crypto.engine_load(engine_id, post_cmds, []) do
      {:ok, engine} -> {:ok, engine}
      {:error, _} = err -> err
    end
  rescue
    error -> {:error, {:engine_load_failed, Exception.message(error)}}
  end
end
