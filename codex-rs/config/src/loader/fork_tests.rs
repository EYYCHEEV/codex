use super::tests::TestFileSystem;
use crate::ConfigLoadOptions;
use crate::LoaderOverrides;
use crate::NoopThreadConfigLoader;
use crate::config_toml::AgentsToml;
use crate::config_toml::ConfigToml;
use crate::loader::load_config_layers_state;
use codex_utils_absolute_path::AbsolutePathBuf;
use pretty_assertions::assert_eq;
use tempfile::tempdir;

async fn load_runtime(home: &std::path::Path) -> std::io::Result<crate::ConfigLayerStack> {
    load_config_layers_state(
        &TestFileSystem,
        home,
        /*cwd*/ None,
        &[],
        LoaderOverrides::without_managed_config_for_tests(),
        &NoopThreadConfigLoader,
    )
    .await
}

#[tokio::test]
async fn fork_private_config_missing_or_empty_is_a_noop() {
    let home = tempdir().unwrap();
    let absent = load_runtime(home.path()).await.unwrap();
    std::fs::write(home.path().join("stronk.toml"), "# no private defaults\n").unwrap();
    let empty = load_runtime(home.path()).await.unwrap();
    assert_eq!(
        absent.layers_low_to_high().collect::<Vec<_>>(),
        empty.layers_low_to_high().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn fork_private_config_invalid_is_rejected_by_both_loaders() {
    let home = tempdir().unwrap();
    let cwd = tempdir().unwrap();
    let cwd = AbsolutePathBuf::from_absolute_path(cwd.path()).unwrap();
    for contents in ["[broken", "unknown_private_setting = true"] {
        std::fs::write(home.path().join("stronk.toml"), contents).unwrap();
        let runtime = load_runtime(home.path()).await.unwrap_err();
        let local = super::local::load_local_config_layers_with_overrides(
            &TestFileSystem,
            home.path(),
            &cwd,
            &LoaderOverrides::without_managed_config_for_tests(),
        )
        .await
        .unwrap_err();
        for error in [runtime, local] {
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("stronk.toml"), "{error}");
        }
    }
}

#[tokio::test]
async fn fork_private_config_respects_ignore_user_config() {
    let home = tempdir().unwrap();
    std::fs::write(home.path().join("stronk.toml"), "[invalid").unwrap();
    let overrides = LoaderOverrides {
        ignore_user_config: true,
        ..LoaderOverrides::without_managed_config_for_tests()
    };
    let stack = load_config_layers_state(
        &TestFileSystem,
        home.path(),
        /*cwd*/ None,
        &[],
        overrides.clone(),
        &NoopThreadConfigLoader,
    )
    .await
    .unwrap();
    assert!(stack.effective_config().get("agents").is_none());
    let cwd = AbsolutePathBuf::from_absolute_path(home.path()).unwrap();
    super::local::load_local_config_layers_with_overrides(
        &TestFileSystem,
        home.path(),
        &cwd,
        &overrides,
    )
    .await
    .expect("ignored malformed private config");
}

#[tokio::test]
async fn fork_private_config_preserves_paths_extensions_and_override_precedence() {
    let home = tempdir().unwrap();
    std::fs::write(
        home.path().join("stronk.toml"),
        r#"
model = "private"
model_instructions_file = "private.md"
model_context_window = 200000
model_auto_compact_token_limit = 180000
[agents]
configured_only = true
[[hooks.PreToolUse]]
matcher = "Bash"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "false"
onFailure = "deny"
"#,
    )
    .unwrap();
    std::fs::write(home.path().join("config.toml"), "model = \"shared\"\n").unwrap();
    let stack = load_runtime(home.path()).await.unwrap();
    let effective = stack.effective_config();
    assert_eq!(effective["model"].as_str(), Some("shared"));
    assert_eq!(
        effective["model_instructions_file"].as_str(),
        home.path().join("private.md").to_str()
    );
    assert_eq!(effective["model_context_window"].as_integer(), Some(200000));
    assert_eq!(
        effective["model_auto_compact_token_limit"].as_integer(),
        Some(180000)
    );
    assert_eq!(
        effective["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"].as_str(),
        Some("deny")
    );
    let cli = load_config_layers_state(
        &TestFileSystem,
        home.path(),
        /*cwd*/ None,
        &[(
            "agents.configured_only".to_string(),
            toml::Value::Boolean(false),
        )],
        LoaderOverrides::without_managed_config_for_tests(),
        &NoopThreadConfigLoader,
    )
    .await
    .unwrap();
    assert_eq!(
        cli.effective_config()["agents"]["configured_only"].as_bool(),
        Some(false)
    );
}

#[tokio::test]
async fn fork_private_config_preserves_shared_symlink_home_opt_in() {
    let home = tempdir().expect("temp home");
    std::fs::write(
        home.path().join("stronk.toml"),
        "[agents]\nconfigured_only = true\n",
    )
    .unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        "allow_symlinked_codex_home = true\n",
    )
    .unwrap();
    let stack = load_config_layers_state(
        &TestFileSystem,
        home.path(),
        /*cwd*/ None,
        &[],
        ConfigLoadOptions::from(LoaderOverrides::without_managed_config_for_tests()),
        &NoopThreadConfigLoader,
    )
    .await
    .unwrap();
    let home = AbsolutePathBuf::from_absolute_path(home.path()).unwrap();
    assert_eq!(
        crate::allowed_symlinked_codex_home(&stack, &home),
        Some(home)
    );
}

#[tokio::test]
async fn fork_private_config_is_visible_to_executor_local_reads() {
    let home = tempdir().expect("temp home");
    let cwd = tempdir().expect("temp cwd");
    std::fs::write(
        home.path().join("stronk.toml"),
        "[agents]\nconfigured_only = true\n",
    )
    .expect("write private config");
    let layers = super::local::load_local_config_layers_with_overrides(
        &TestFileSystem,
        home.path(),
        &AbsolutePathBuf::from_absolute_path(cwd.path()).unwrap(),
        &LoaderOverrides::without_managed_config_for_tests(),
    )
    .await
    .expect("local config load");
    let private = layers
        .config
        .layers
        .iter()
        .find(|layer| {
            matches!(&layer.source, crate::ConfigLayerSource::User { file, .. }
            if file.as_path() == home.path().join("stronk.toml"))
        })
        .expect("private layer in local config");
    assert_eq!(
        private.toml["agents"]["configured_only"].as_bool(),
        Some(true)
    );
    assert_eq!(layers.config.cloud_insertion_index, 1);
}

#[tokio::test]
async fn fork_private_config_loads_without_polluting_shared_config() {
    let home = tempdir().expect("temp home");
    let shared = home.path().join("config.toml");
    let shared_text = "[agents]\nmax_depth = 2\n";
    std::fs::write(&shared, shared_text).expect("write shared config");
    std::fs::write(
        home.path().join("stronk.toml"),
        "[agents]\nconfigured_only = true\n",
    )
    .expect("write private config");

    let stack = load_config_layers_state(
        &TestFileSystem,
        home.path(),
        /*cwd*/ None,
        &[],
        ConfigLoadOptions {
            loader_overrides: LoaderOverrides::without_managed_config_for_tests(),
            strict_config: true,
            ..Default::default()
        },
        &NoopThreadConfigLoader,
    )
    .await
    .expect("strict config load");
    let config: ConfigToml = stack
        .effective_config()
        .try_into()
        .expect("effective config");
    assert_eq!(
        config.agents,
        Some(AgentsToml {
            configured_only: Some(true),
            max_depth: Some(2),
            ..Default::default()
        })
    );
    assert_eq!(
        stack.get_user_config_file(),
        Some(&AbsolutePathBuf::from_absolute_path(&shared).expect("shared path"))
    );
    assert_eq!(std::fs::read_to_string(shared).unwrap(), shared_text);
}
