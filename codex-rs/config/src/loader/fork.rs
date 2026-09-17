//! Fork-private defaults, kept out of the shared upstream config.toml.

use super::load_config_toml_for_required_layer_raw;
use super::local::LocalTomlLayer;
use crate::ConfigLayerSource;
use codex_file_system::ExecutorFileSystem;
use codex_utils_absolute_path::AbsolutePathBuf;
use std::io;
use std::path::Path;

/// Load optional fork defaults using the same schema and path base as user
/// config. Callers insert this before config.toml so shared config, profiles,
/// projects, and explicit overrides retain their existing precedence.
pub(super) async fn load_private_config(
    fs: &dyn ExecutorFileSystem,
    codex_home: &Path,
) -> io::Result<Option<LocalTomlLayer<ConfigLayerSource>>> {
    let file = AbsolutePathBuf::resolve_path_against_base("stronk.toml", codex_home);
    let loaded = load_config_toml_for_required_layer_raw(fs, &file, /*strict_config*/ true).await?;
    if loaded.toml.as_table().is_some_and(toml::map::Map::is_empty) {
        return Ok(None);
    }
    Ok(Some(LocalTomlLayer {
        source: ConfigLayerSource::User {
            file,
            profile: None,
        },
        base_dir: loaded.base_dir,
        toml: loaded.toml,
    }))
}
