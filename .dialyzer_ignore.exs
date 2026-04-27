# Upstream `x509` library declares specs that reference types Erlang/OTP
# either renamed or stopped exporting (`:public_key.ec_public_key/0`) and a
# private record helper (`X509.ASN1.record/1`). Nothing we can fix from this
# repo; ignored so our own warnings stay visible.
#
# The pkcs11 strategy passes a crypto-engine key reference (a tuple
# returned by `:crypto.engine_load`) where `X509.{Certificate,CRL}` specs
# declare `X509.PrivateKey.t()`. OTP's `:public_key.sign/3` accepts the
# engine ref at runtime, but the type spec is too narrow for dialyzer to
# verify. Suppressing the call-site warnings keeps the rest of the suite
# meaningful.
[
  {"lib/x509/certificate.ex", :unknown_type},
  {"lib/x509/crl.ex", :unknown_type},
  {"lib/x509/crl/entry.ex", :unknown_type},
  {"lib/x509/csr.ex", :unknown_type},
  {"lib/x509/public_key.ex", :unknown_type},
  {"lib/ash_pki/key_strategy/pkcs11.ex", :call}
]
