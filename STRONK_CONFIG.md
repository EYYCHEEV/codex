# Shared and Stronk-private configuration

Keep `~/.codex/config.toml` valid for official Codex. Stronk also reads optional
`$CODEX_HOME/stronk.toml` (`~/.codex/stronk.toml` by default):

```toml
[agents]
configured_only = true
```

This file uses the existing Stronk config schema. Fork extensions include
`agents.configured_only`, legacy profile `model_context_window` and
`model_auto_compact_token_limit`, and command-hook `onFailure` (`on_failure` alias).
Standalone `hooks.json` continues to support the hook extension independently;
an existing Sentinel installation does not need to move its hooks.

Private settings are user defaults: shared `config.toml`, selected profiles,
project settings, and CLI overrides retain their normal precedence over them.
Managed configuration and requirements still apply. Relative paths are resolved
against the private file's directory. Both runtime and executor-local config
reads include this layer; ignoring user config also ignores the private file.
Missing or empty private config is a no-op. The existing strict parser validates
private settings even without `--strict-config`; malformed TOML and detected
unknown fields produce startup errors. This retains upstream parser limitations
for flattened hook fields, rather than introducing a second validator.

Ordinary config edits still target shared `config.toml`, not `stronk.toml`.
Maintain private settings in the private file, and remove their old shared copies
only after installing a Stronk binary that supports it. Official Codex ignores
this file. Pair upgrades do not replace it. The shared file's symlink-home opt-in
remains authoritative over the private layer.

For generated workstation configuration, change the authoritative base and
regenerate; do not patch the generated live file. Keep a backup before migration.
