//! Checks retained providers against managed policy without reloading session configuration.

use super::*;
use anyhow::Result;
use codex_config::CloudConfigBundleLoadError;
use codex_config::CloudConfigBundleLoadErrorCode;
use codex_config::ThreadConfigContext;
use codex_config::ThreadConfigLoadError;
use codex_config::ThreadConfigLoadErrorCode;
use codex_config::ThreadConfigLoaderFuture;
use codex_config::ThreadConfigSource;
use codex_config::test_support::CloudConfigBundleFixture;
use codex_http_client::NetworkPolicyDenied;
use pretty_assertions::assert_eq;
use tempfile::tempdir;
use test_case::test_case;

#[test_case(AMAZON_BEDROCK_PROVIDER_ID; "bedrock")]
#[test_case(AMAZON_BEDROCK_RUNTIME_PROVIDER_ID; "bedrock_runtime")]
#[tokio::test]
async fn provider_requirements_resolve_bedrock_overrides(provider_id: &str) -> Result<()> {
    let home = tempdir()?;
    let requirements = format!(
        "model_provider = '{provider_id}'\n[model_providers.{provider_id}.aws]\nregion = 'us-west-2'"
    );
    let manager = ConfigManager::new_for_tests(
        home.path().to_path_buf(),
        Vec::new(),
        LoaderOverrides::without_managed_config_for_tests(),
        CloudConfigBundleFixture::loader_with_enterprise_requirement(&requirements),
    );
    let current = manager.load_latest_config(/*fallback_cwd*/ None).await?;
    manager
        .check_thread_model_provider(&current, ProviderPolicyCheck::Current)
        .await?;

    let changed = ConfigManager::new_for_tests(
        home.path().to_path_buf(),
        Vec::new(),
        LoaderOverrides::without_managed_config_for_tests(),
        CloudConfigBundleFixture::loader_with_enterprise_requirement(
            requirements.replace("us-west-2", "us-east-1"),
        ),
    );
    assert_eq!(
        changed
            .check_thread_model_provider(&current, ProviderPolicyCheck::Current)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied,
    );
    Ok(())
}

struct UnavailableThreadConfig;

impl ThreadConfigLoader for UnavailableThreadConfig {
    fn load(
        &self,
        _context: ThreadConfigContext,
    ) -> ThreadConfigLoaderFuture<'_, Vec<ThreadConfigSource>> {
        Box::pin(async {
            Err(ThreadConfigLoadError::new(
                ThreadConfigLoadErrorCode::RequestFailed,
                /*status_code*/ None,
                "thread config service unavailable",
            ))
        })
    }
}

#[tokio::test]
async fn provider_requirements_do_not_reload_thread_config() -> Result<()> {
    let home = tempdir()?;
    let mut manager = ConfigManager::without_managed_config_for_tests(home.path().to_path_buf());
    manager.thread_config_loader = Arc::new(codex_config::StaticThreadConfigLoader::new(vec![
        ThreadConfigSource::Session(codex_config::SessionThreadConfig {
            model_provider: Some("retained".into()),
            model_providers: toml::from_str("[retained]\nname = 'Retained'")?,
            ..Default::default()
        }),
    ]));
    let current = manager.load_latest_config(/*fallback_cwd*/ None).await?;
    manager.thread_config_loader = Arc::new(UnavailableThreadConfig);
    assert!(
        manager
            .load_latest_config(/*fallback_cwd*/ None)
            .await
            .is_err()
    );
    manager
        .check_thread_model_provider(&current, ProviderPolicyCheck::Current)
        .await?;
    manager.cloud_config_bundle = Arc::new(RwLock::new(
        CloudConfigBundleFixture::loader_with_enterprise_requirement("model_provider = 'retained'"),
    ));
    let retained = manager
        .load_retained_session_config(&current.config_layer_stack, &current.cwd)
        .await?;
    assert_eq!(retained.model_provider, current.model_provider);
    let factory = current.http_client_factory();
    assert_eq!(retained.http_client_factory(), factory);

    manager.cloud_config_bundle = Arc::new(RwLock::new(
        CloudConfigBundleFixture::loader_with_enterprise_requirement("model_provider = 'other'"),
    ));
    assert_eq!(
        manager
            .check_thread_model_provider(&current, ProviderPolicyCheck::Current)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied,
    );
    Ok(())
}

#[tokio::test]
async fn provider_requirements_ignore_system_defaults_but_reject_requirement_changes() -> Result<()>
{
    let home = tempdir()?;
    let system_config_path = home.path().join("system-config.toml");
    let requirements_path = home.path().join("requirements.toml");
    let managed_config_path = home.path().join("managed-config.toml");
    let mut overrides = LoaderOverrides::without_managed_config_for_tests();
    overrides.system_config_path = Some(system_config_path.clone());
    overrides.system_requirements_path = Some(requirements_path.clone());
    overrides.managed_config_path = Some(managed_config_path.clone());
    let manager = ConfigManager::new_for_tests(
        home.path().to_path_buf(),
        Vec::new(),
        overrides,
        CloudConfigBundleLoader::default(),
    );
    let current = manager.load_latest_config(/*fallback_cwd*/ None).await?;

    std::fs::write(&system_config_path, "invalid toml !!!")?;
    manager
        .check_thread_model_provider(&current, ProviderPolicyCheck::Current)
        .await?;

    std::fs::write(&requirements_path, "model_provider = 'other'")?;
    assert_eq!(
        manager
            .check_thread_model_provider(&current, ProviderPolicyCheck::Current)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied,
    );

    std::fs::write(&requirements_path, "invalid toml !!!")?;
    assert_eq!(
        manager
            .check_thread_model_provider(&current, ProviderPolicyCheck::Current)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData,
    );

    std::fs::write(
        &requirements_path,
        "[model_providers.gateway]\nbase_url = 'https://example.test'",
    )?;
    assert_eq!(
        manager
            .check_thread_model_provider(&current, ProviderPolicyCheck::Current)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData,
    );
    std::fs::remove_file(requirements_path)?;

    std::fs::write(managed_config_path, "invalid toml !!!")?;
    assert_eq!(
        manager
            .check_thread_model_provider(&current, ProviderPolicyCheck::Current)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData,
    );
    Ok(())
}

#[tokio::test]
async fn provider_requirement_load_errors_reject_input() -> Result<()> {
    let home = tempdir()?;
    let previous = ConfigManager::without_managed_config_for_tests(home.path().to_path_buf())
        .load_latest_config(/*fallback_cwd*/ None)
        .await?;
    for loader in [
        CloudConfigBundleFixture::loader_with_enterprise_requirement("invalid toml !!!"),
        CloudConfigBundleLoader::new(async {
            Err(CloudConfigBundleLoadError::new(
                CloudConfigBundleLoadErrorCode::RequestFailed,
                /*status_code*/ None,
                "policy unavailable",
            ))
        }),
    ] {
        let manager = ConfigManager::new_for_tests(
            home.path().to_path_buf(),
            Vec::new(),
            LoaderOverrides::without_managed_config_for_tests(),
            loader,
        );
        assert!(
            manager
                .check_thread_model_provider(&previous, ProviderPolicyCheck::Current)
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn selected_admission_defers_global_cloud_but_preserves_local_requirements() -> Result<()> {
    let home = tempdir()?;
    let requirements_path = home.path().join("requirements.toml");
    let mut overrides = LoaderOverrides::without_managed_config_for_tests();
    overrides.system_requirements_path = Some(requirements_path.clone());
    let manager = ConfigManager::new_for_tests(
        home.path().to_path_buf(),
        Vec::new(),
        overrides,
        CloudConfigBundleLoader::default(),
    );
    let current = manager.load_latest_config(/*fallback_cwd*/ None).await?;
    let auth = AuthManager::from_auth_for_testing(
        codex_login::CodexAuth::create_dummy_chatgpt_auth_for_testing(),
    );
    for loader in [
        CloudConfigBundleFixture::loader_with_enterprise_requirement("model_provider = 'other'"),
        CloudConfigBundleLoader::new(async {
            Err(CloudConfigBundleLoadError::new(
                CloudConfigBundleLoadErrorCode::RequestFailed,
                /*status_code*/ None,
                "default account policy unavailable",
            ))
        }),
    ] {
        let global = manager.with_cloud_config_bundle(loader, Default::default());
        assert!(
            global
                .check_thread_model_provider(&current, ProviderPolicyCheck::Current)
                .await
                .is_err()
        );
        global
            .check_thread_model_provider(&current, ProviderPolicyCheck::RequestScoped(&auth))
            .await?;
        // Scoping the selected loader must not mutate the default account's loader.
        let selected =
            global.with_cloud_config_bundle(CloudConfigBundleLoader::default(), Default::default());
        selected
            .check_thread_model_provider(&current, ProviderPolicyCheck::Current)
            .await?;
        assert!(
            global
                .check_thread_model_provider(&current, ProviderPolicyCheck::Current)
                .await
                .is_err()
        );
        std::fs::write(&requirements_path, "model_provider = 'other'")?;
        assert_eq!(
            global
                .check_thread_model_provider(&current, ProviderPolicyCheck::RequestScoped(&auth))
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied,
        );
        std::fs::remove_file(&requirements_path)?;
    }
    Ok(())
}

#[tokio::test]
async fn derived_cloud_managers_isolate_effective_policy_and_share_local_restrictions() -> Result<()>
{
    let home = tempdir()?;
    let requirements_path = home.path().join("requirements.toml");
    std::fs::write(
        &requirements_path,
        "[application.network.domains]\n'local.example' = 'allow'\n'blocked.example' = 'deny'",
    )?;
    let overrides = LoaderOverrides {
        system_requirements_path: Some(requirements_path.clone()),
        ..LoaderOverrides::without_managed_config_for_tests()
    };
    let manager = ConfigManager::new_for_tests(
        home.path().to_path_buf(),
        Vec::new(),
        overrides,
        CloudConfigBundleFixture::loader_with_enterprise_requirement(
            "[application.network.domains]\n'global.example' = 'allow'",
        ),
    );
    let global_load = manager.refresh_application_network_policy().await?;
    let global_policy = manager.network_policy.policy();
    let global_url = "https://global.example".parse()?;
    let selected_url = "https://selected.example".parse()?;
    let local_url = "https://local.example".parse()?;
    let blocked_url = "https://blocked.example".parse()?;
    let global_permit = global_policy.acquire(&global_url)?;

    let bootstrap =
        manager.with_cloud_config_bundle(CloudConfigBundleLoader::default(), Default::default());
    let bootstrap_config = bootstrap.load_latest_config(/*fallback_cwd*/ None).await?;
    assert_eq!(
        bootstrap_config
            .application_network_policy
            .acquire(&local_url)
            .map(|_| ()),
        Ok(()),
    );
    assert_eq!(
        bootstrap_config
            .application_network_policy
            .acquire(&global_url)
            .map(|_| ()),
        Err(NetworkPolicyDenied::Destination),
    );
    manager.check_application_policy_load(&global_load)?;
    global_permit.check()?;
    assert_eq!(global_policy.acquire(&global_url).map(|_| ()), Ok(()));

    let selected = manager.with_cloud_config_bundle(
        CloudConfigBundleFixture::loader_with_enterprise_requirement(
            "[application.network.domains]\n'selected.example' = 'allow'",
        ),
        Default::default(),
    );
    let selected_config = selected.load_latest_config(/*fallback_cwd*/ None).await?;
    assert_eq!(
        selected_config
            .application_network_policy
            .acquire(&selected_url)
            .map(|_| ()),
        Ok(()),
    );
    manager.check_application_policy_load(&global_load)?;
    global_permit.check()?;
    assert_eq!(global_policy.acquire(&global_url).map(|_| ()), Ok(()));
    assert_eq!(
        global_policy.acquire(&selected_url).map(|_| ()),
        Err(NetworkPolicyDenied::Destination),
    );
    assert_eq!(
        bootstrap_config
            .application_network_policy
            .acquire(&selected_url)
            .map(|_| ()),
        Err(NetworkPolicyDenied::Destination),
    );
    for policy in [
        &global_policy,
        &bootstrap_config.application_network_policy,
        &selected_config.application_network_policy,
    ] {
        assert_eq!(
            policy.acquire(&blocked_url).map(|_| ()),
            Err(NetworkPolicyDenied::Destination),
        );
    }

    let local_policy = manager.local_network_policy.policy();
    let local_permit = local_policy.acquire(&local_url)?;
    std::fs::write(&requirements_path, "[application.network]")?;
    selected.refresh_local_network_policy().await?;
    assert_eq!(local_permit.check(), Err(NetworkPolicyDenied::Revoked));
    for scoped in [&manager, &bootstrap, &selected] {
        assert_eq!(
            scoped
                .local_network_policy
                .policy()
                .acquire(&local_url)
                .map(|_| ()),
            Err(NetworkPolicyDenied::Destination),
        );
    }
    manager.check_application_policy_load(&global_load)?;
    global_permit.check()?;
    Ok(())
}

#[tokio::test]
async fn nonmanaged_and_independent_admission_keeps_global_cloud_policy() -> Result<()> {
    let home = tempdir()?;
    let manager = ConfigManager::without_managed_config_for_tests(home.path().to_path_buf());
    let current = manager.load_latest_config(/*fallback_cwd*/ None).await?;
    let manager = manager.with_cloud_config_bundle(
        CloudConfigBundleFixture::loader_with_enterprise_requirement("model_provider = 'other'"),
        Default::default(),
    );
    for auth in [
        codex_login::CodexAuth::from_api_key("synthetic-api-key"),
        codex_login::CodexAuth::from_external_chatgpt_tokens(
            "header.e30.external",
            "external-workspace",
            /*chatgpt_plan_type*/ None,
        )?,
    ] {
        let auth = AuthManager::from_auth_for_testing(auth);
        assert_eq!(
            manager
                .check_thread_model_provider(&current, ProviderPolicyCheck::RequestScoped(&auth))
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied,
        );
    }
    let auth = AuthManager::from_auth_for_testing(
        codex_login::CodexAuth::create_dummy_chatgpt_auth_for_testing(),
    );
    for provider in [
        ModelProviderInfo {
            requires_openai_auth: false,
            ..current.model_provider.clone()
        },
        ModelProviderInfo {
            env_key: Some("INDEPENDENT_KEY".into()),
            ..current.model_provider.clone()
        },
        ModelProviderInfo {
            base_url: Some("https://independent.example/v1".into()),
            ..current.model_provider.clone()
        },
    ] {
        let mut independent = current.clone();
        independent.model_provider = provider;
        assert_eq!(
            manager
                .check_thread_model_provider(
                    &independent,
                    ProviderPolicyCheck::RequestScoped(&auth)
                )
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied,
        );
    }
    Ok(())
}
