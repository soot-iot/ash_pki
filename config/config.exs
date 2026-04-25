import Config

# Kept minimal: consumers compose AshPki.Domain alongside their own
# without this config dictating the full :ash_domains list.

config :ash_pki,
  ash_domains: [AshPki.Domain]

if File.exists?(Path.join([__DIR__, "#{config_env()}.exs"])) do
  import_config "#{config_env()}.exs"
end
