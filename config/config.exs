import Config

# Each app may extend or override this in its own config.
# In the umbrella we keep this minimal so each library remains usable
# standalone outside the workspace.

config :ash_pki,
  ash_domains: [AshPki.Domain]

if File.exists?(Path.join([__DIR__, "#{config_env()}.exs"])) do
  import_config "#{config_env()}.exs"
end
