use super::*;

impl AuthManager {
    pub(in crate::auth) fn managed_chatgpt_storage(&self) -> Arc<dyn AuthStorageBackend> {
        create_auth_storage(
            self.codex_home.clone(),
            self.auth_credentials_store_mode,
            self.keyring_backend_kind,
        )
    }

    pub(super) fn notify_managed_chatgpt_change(&self) {
        self.auth_change_tx.send_modify(|revision| *revision += 1);
    }

    pub(in crate::auth::manager) fn load_managed_chatgpt_document(
        &self,
    ) -> std::io::Result<Option<AuthDotJson>> {
        self.managed_chatgpt_storage().mutate(&mut |current| {
            let Some(mut auth) = current else {
                return Ok(AuthStorageMutation::Keep(None));
            };
            validate_document(&auth)?;
            if migrate_document(&mut auth, Utc::now()) {
                Ok(AuthStorageMutation::Save(auth))
            } else {
                Ok(AuthStorageMutation::Keep(Some(auth)))
            }
        })
    }

    pub fn managed_chatgpt_accounts(&self) -> std::io::Result<Vec<ManagedChatgptAccountView>> {
        if load_external_chatgpt_auth(&self.codex_home)?.is_some() {
            return Ok(Vec::new());
        }
        self.stored_managed_chatgpt_accounts()
    }

    /// Returns persisted managed accounts even when an external ChatGPT overlay is active.
    ///
    /// This is for account inventory surfaces only. Request routing must use
    /// [`Self::managed_chatgpt_accounts`] or [`Self::list_managed_chatgpt_accounts`].
    pub fn stored_managed_chatgpt_accounts(
        &self,
    ) -> std::io::Result<Vec<ManagedChatgptAccountView>> {
        Ok(self.stored_managed_chatgpt_account_list()?.accounts)
    }

    /// Returns the canonical persisted account inventory and durable pool revision.
    ///
    /// Unlike the effective routing list, this owner view remains visible while
    /// an external ChatGPT overlay is active and never performs account selection.
    pub fn stored_managed_chatgpt_account_list(
        &self,
    ) -> std::io::Result<ManagedChatgptAccountList> {
        let Some(auth) = self.load_managed_chatgpt_document()? else {
            return Ok(ManagedChatgptAccountList {
                accounts: Vec::new(),
                selected_account_id: None,
                pool_revision: 0,
                selection_revision: self.selection_pins.revision(),
            });
        };
        let forced = self.forced_chatgpt_workspace_id();
        let pool_revision = auth
            .managed_chatgpt
            .as_ref()
            .map(|pool| pool.revision)
            .unwrap_or(0);
        Ok(ManagedChatgptAccountList {
            accounts: views(&auth, forced.as_deref(), Utc::now()),
            selected_account_id: None,
            pool_revision,
            selection_revision: self.selection_pins.revision(),
        })
    }

    pub async fn list_managed_chatgpt_accounts(
        &self,
        scope: &ManagedChatgptSelectionScope,
    ) -> std::io::Result<ManagedChatgptAccountList> {
        if load_external_chatgpt_auth(&self.codex_home)?.is_some() {
            return Ok(ManagedChatgptAccountList {
                accounts: Vec::new(),
                selected_account_id: None,
                pool_revision: 0,
                selection_revision: self.selection_pins.revision(),
            });
        }
        self.resume_managed_chatgpt_tombstones().await?;
        let Some(auth) = self.load_managed_chatgpt_document()? else {
            return Ok(ManagedChatgptAccountList {
                accounts: Vec::new(),
                selected_account_id: None,
                pool_revision: 0,
                selection_revision: self.selection_pins.revision(),
            });
        };
        let forced = self.forced_chatgpt_workspace_id();
        let pool_revision = auth
            .managed_chatgpt
            .as_ref()
            .map(|pool| pool.revision)
            .unwrap_or(0);
        let selected_account_id = select(
            &auth,
            scope,
            &self.selection_pins,
            forced.as_deref(),
            Utc::now(),
        )
        .map(|account| account.identity_key.clone());
        Ok(ManagedChatgptAccountList {
            accounts: views(&auth, forced.as_deref(), Utc::now()),
            selected_account_id,
            pool_revision,
            selection_revision: self.selection_pins.revision(),
        })
    }

    pub async fn upsert_managed_chatgpt_oauth(
        &self,
        credentials: ManagedChatgptOauthCredentials,
    ) -> std::io::Result<String> {
        self.resume_managed_chatgpt_tombstones().await?;
        let storage = self.managed_chatgpt_storage();
        let forced = self.forced_chatgpt_workspace_id();
        let credentials = credentials.clone();
        let (auth, committed_identity) = loop {
            let mut committed = None;
            let result = storage.mutate(&mut |current| {
                let mut auth = current.unwrap_or(AuthDotJson {
                    auth_mode: Some(AuthMode::Chatgpt),
                    openai_api_key: None,
                    tokens: None,
                    last_refresh: None,
                    agent_identity: None,
                    managed_chatgpt: None,
                    personal_access_token: None,
                    bedrock_api_key: None,
                });
                migrate_document(&mut auth, Utc::now());
                validate_document(&auth)?;
                committed = Some(upsert(&mut auth, credentials.clone(), forced.as_deref())?);
                Ok(AuthStorageMutation::Save(auth))
            });
            match result {
                Ok(auth) => break (auth, committed),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(err) => return Err(err),
            }
        };
        let identity = committed_identity.ok_or_else(|| {
            std::io::Error::other(if auth.is_some() {
                "managed ChatGPT upsert committed without an identity"
            } else {
                "managed ChatGPT upsert unexpectedly deleted auth storage"
            })
        })?;
        self.notify_managed_chatgpt_change();
        self.reload().await;
        Ok(identity)
    }

    pub async fn managed_chatgpt_auth_snapshot(
        &self,
        scope: &ManagedChatgptSelectionScope,
    ) -> std::io::Result<Option<ManagedChatgptAuthSnapshot>> {
        if self.has_external_auth() || load_external_chatgpt_auth(&self.codex_home)?.is_some() {
            return Ok(None);
        }
        self.resume_managed_chatgpt_tombstones().await?;
        let Some(auth_document) = self.load_managed_chatgpt_document()? else {
            return Ok(None);
        };
        let forced = self.forced_chatgpt_workspace_id();
        let pool_revision = auth_document
            .managed_chatgpt
            .as_ref()
            .map(|pool| pool.revision)
            .unwrap_or(0);
        let Some(account) = select(
            &auth_document,
            scope,
            &self.selection_pins,
            forced.as_deref(),
            Utc::now(),
        ) else {
            return Ok(None);
        };
        let auth = CodexAuth::from_managed_account(
            &self.codex_home,
            account,
            self.auth_credentials_store_mode,
            self.chatgpt_base_url.as_deref(),
            self.keyring_backend_kind,
            self.agent_identity_authapi_base_url.as_deref(),
            &self.auth_route_config,
        )
        .await?;
        Ok(Some(ManagedChatgptAuthSnapshot {
            identity_key: account.identity_key.clone(),
            account_revision: credential_revision(account),
            account_state_revision: account.revision,
            pool_revision,
            selection_revision: self.selection_pins.revision(),
            transport: TransportAuthBinding {
                identity_key: account.identity_key.clone(),
                raw_account_id: account.chatgpt_account_id.clone(),
                fedramp: account.tokens.id_token.chatgpt_account_is_fedramp,
                auth_mode: AuthMode::Chatgpt,
                route_generation: credential_revision(account),
            },
            auth,
        }))
    }

    pub async fn managed_chatgpt_auth_snapshot_for_identity(
        &self,
        selector: &str,
    ) -> std::io::Result<Option<ManagedChatgptAuthSnapshot>> {
        if load_external_chatgpt_auth(&self.codex_home)?.is_some() {
            return Ok(None);
        }
        self.resume_managed_chatgpt_tombstones().await?;
        let Some(auth_document) = self.load_managed_chatgpt_document()? else {
            return Ok(None);
        };
        let Some(identity) = resolve_identity(&auth_document, selector)? else {
            return Ok(None);
        };
        let Some(account) = row(&auth_document, &identity) else {
            return Ok(None);
        };
        if account.tombstone.is_some() {
            return Ok(None);
        }
        if let Some(allowed) = self.forced_chatgpt_workspace_id()
            && !account
                .chatgpt_account_id
                .as_ref()
                .is_some_and(|id| allowed.contains(id))
        {
            return Err(std::io::Error::other(
                "managed ChatGPT account is disallowed by forced workspace policy",
            ));
        }
        let pool_revision = auth_document
            .managed_chatgpt
            .as_ref()
            .map(|pool| pool.revision)
            .unwrap_or(0);
        let auth = CodexAuth::from_managed_account(
            &self.codex_home,
            account,
            self.auth_credentials_store_mode,
            self.chatgpt_base_url.as_deref(),
            self.keyring_backend_kind,
            self.agent_identity_authapi_base_url.as_deref(),
            &self.auth_route_config,
        )
        .await?;
        Ok(Some(ManagedChatgptAuthSnapshot {
            identity_key: account.identity_key.clone(),
            account_revision: credential_revision(account),
            account_state_revision: account.revision,
            pool_revision,
            selection_revision: self.selection_pins.revision(),
            transport: TransportAuthBinding {
                identity_key: account.identity_key.clone(),
                raw_account_id: account.chatgpt_account_id.clone(),
                fedramp: account.tokens.id_token.chatgpt_account_is_fedramp,
                auth_mode: AuthMode::Chatgpt,
                route_generation: credential_revision(account),
            },
            auth,
        }))
    }

    /// Atomically merges independently fetched rate-window and token-usage status.
    ///
    /// The mutation is compare-safe: a response produced from an older credential or
    /// row-state snapshot cannot update a row after re-login, refresh, or another
    /// observation. `None` means that the identity no longer exists, is pending
    /// removal, or either expected revision no longer matches.
    pub fn record_managed_chatgpt_status_observation(
        &self,
        identity_key: &str,
        expected_credential_revision: u64,
        expected_state_revision: u64,
        observation: ManagedChatgptStatusObservation,
    ) -> std::io::Result<Option<ManagedChatgptAccountView>> {
        let storage = self.managed_chatgpt_storage();
        let mut changed_identity = None;
        let saved = storage.mutate(&mut |current| {
            let Some(mut auth) = current else {
                return Ok(AuthStorageMutation::Keep(None));
            };
            migrate_document(&mut auth, Utc::now());
            let Some(account) = row_mut(&mut auth, identity_key) else {
                return Ok(AuthStorageMutation::Keep(Some(auth)));
            };
            if account.tombstone.is_some()
                || credential_revision(account) != expected_credential_revision
                || account.revision != expected_state_revision
            {
                return Ok(AuthStorageMutation::Keep(Some(auth)));
            }
            if !record_status_observation(account, observation.clone()) {
                return Ok(AuthStorageMutation::Keep(Some(auth)));
            }
            account.revision = account.revision.saturating_add(1);
            changed_identity = Some(identity_key.to_string());
            Ok(AuthStorageMutation::Save(auth))
        })?;
        if changed_identity.is_some() {
            self.notify_managed_chatgpt_change();
        }
        self.managed_account_view_from_document(saved.as_ref(), changed_identity.as_deref())
    }

    fn managed_account_view_from_document(
        &self,
        auth: Option<&AuthDotJson>,
        identity: Option<&str>,
    ) -> std::io::Result<Option<ManagedChatgptAccountView>> {
        let (Some(auth), Some(identity)) = (auth, identity) else {
            return Ok(None);
        };
        let forced = self.forced_chatgpt_workspace_id();
        Ok(views(auth, forced.as_deref(), Utc::now())
            .into_iter()
            .find(|account| account.identity_key == identity))
    }

    pub async fn logout_all_managed_chatgpt(&self) -> std::io::Result<Vec<String>> {
        if let Some(overlay) = load_external_chatgpt_auth(&self.codex_home)? {
            if let Err(err) =
                revoke_auth_tokens(Some(&overlay), &self.auth_route_config).await
            {
                tracing::warn!("failed to revoke external ChatGPT auth during logout-all: {err}");
            }
            self.clear_external_auth();
            self.reload().await;
        }
        self.resume_managed_chatgpt_tombstones().await?;
        let identities: Vec<_> = self
            .managed_chatgpt_accounts()?
            .into_iter()
            .map(|account| account.identity_key)
            .collect();
        let mut removed = Vec::new();
        for identity in identities {
            if self.remove_managed_chatgpt_account(&identity).await? {
                removed.push(identity);
            }
        }
        Ok(removed)
    }
}
