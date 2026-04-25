defmodule AshPki.KeyStrategy do
  @moduledoc """
  Behavior implemented by every key-storage and signing strategy.

  Each `CertificateAuthority` row carries an opaque `descriptor` map alongside
  a strategy name. The strategy decides what the descriptor contains and is
  the only code that knows how to use it. This is the boundary that lets
  software keys, HSM-backed keys, KMS-wrapped keys, and pre-provisioned
  device keys (`:imported`) share a single resource model.

  Mirror of the `ash_authentication` strategy pattern.

  ## Surface

  Implementations *must* provide `c:name/0` and `c:can_sign?/0`. The signing
  callbacks (`c:generate/1`, `c:self_sign/3`, `c:sign_csr/4`, `c:sign_crl/4`)
  may return `{:error, :no_signing_capability}` on read-only strategies like
  `:imported`.
  """

  @type descriptor :: map()
  @type opts :: keyword()

  @doc "The strategy's atom name; matches the `key_strategy` field on the resource."
  @callback name() :: atom()

  @doc """
  Whether this strategy can produce signatures.

  Pre-provisioned device strategies (`:imported`) only hold public material
  and return `false` here.
  """
  @callback can_sign?() :: boolean()

  @doc """
  Generate a fresh key pair and return a descriptor for storage.

  Options:
    * `:type`  — `:ec` (default) or `:rsa`
    * `:curve` — EC curve name, default `:secp256r1`
    * `:bits`  — RSA key size, default `2048`
  """
  @callback generate(opts()) :: {:ok, descriptor()} | {:error, term()}

  @doc "Return the public key encoded in the descriptor."
  @callback public_key(descriptor()) :: {:ok, X509.PublicKey.t()} | {:error, term()}

  @doc "Sign a CSR using the descriptor's key, producing an OTPCertificate."
  @callback sign_csr(
              descriptor(),
              csr :: X509.CSR.t(),
              issuer_cert :: X509.Certificate.t(),
              opts()
            ) :: {:ok, X509.Certificate.t()} | {:error, term()}

  @doc "Produce a self-signed certificate (root CA bootstrap)."
  @callback self_sign(descriptor(), subject :: String.t(), opts()) ::
              {:ok, X509.Certificate.t()} | {:error, term()}

  @doc "Sign a CRL TBS list."
  @callback sign_crl(
              descriptor(),
              issuer_cert :: X509.Certificate.t(),
              entries :: [X509.CRL.Entry.t()],
              opts()
            ) :: {:ok, X509.CRL.t()} | {:error, term()}

  @doc """
  Import an externally-generated public certificate (e.g. ATECC, OPTIGA).

  The strategy stores enough to identify and verify the key but never holds
  signing material.
  """
  @callback import_public(cert_pem :: binary(), opts()) ::
              {:ok, descriptor()} | {:error, term()}

  @optional_callbacks [import_public: 2]
end
