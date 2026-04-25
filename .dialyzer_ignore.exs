# Upstream `x509` library declares specs that reference types Erlang/OTP
# either renamed or stopped exporting (`:public_key.ec_public_key/0`) and a
# private record helper (`X509.ASN1.record/1`). Nothing we can fix from this
# repo; ignored so our own warnings stay visible.
[
  {"lib/x509/certificate.ex", :unknown_type},
  {"lib/x509/crl.ex", :unknown_type},
  {"lib/x509/crl/entry.ex", :unknown_type},
  {"lib/x509/csr.ex", :unknown_type},
  {"lib/x509/public_key.ex", :unknown_type}
]
