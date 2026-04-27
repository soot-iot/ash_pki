spark_locals_without_parens = [certificate: 1, certificate_authority: 1, revocation_list: 1]

[
  import_deps: [:ash],
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"],
  locals_without_parens: spark_locals_without_parens
]
