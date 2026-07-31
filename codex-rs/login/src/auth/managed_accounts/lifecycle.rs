use super::*;

const REFRESH_FAILURE_CANCELLED_REASON: &str = "token_refresh_cancelled";
const REFRESH_FAILURE_TIMEOUT_REASON: &str = "token_refresh_timeout";
const REFRESH_FAILURE_TRANSIENT_REASON: &str = "token_refresh_unavailable";
const REFRESH_FAILURE_COMMIT_REASON: &str = "token_refresh_commit_failed";
const MANAGED_REFRESH_LEASE_DURATION: Duration = Duration::from_secs(5 * 60);
const MANAGED_REFRESH_TIMEOUT_MESSAGE: &str = "managed ChatGPT token refresh timed out";

fn refresh_failure_reason_code(error: &RefreshTokenError) -> &'static str {
    match error {
        RefreshTokenError::Permanent(error) => match error.reason {
            RefreshTokenFailedReason::Expired => "refresh_token_expired",
            RefreshTokenFailedReason::Exhausted => "refresh_token_reused",
            RefreshTokenFailedReason::Revoked => "refresh_token_invalidated",
            RefreshTokenFailedReason::Other => "refresh_token_other",
        },
        RefreshTokenError::Transient(_) => REFRESH_FAILURE_TRANSIENT_REASON,
    }
}

fn persisted_refresh_failure_result(failure: &ManagedChatgptRefreshFailure) -> RefreshTokenError {
    if !failure.permanent {
        let kind = if failure.reason_code.as_deref() == Some(REFRESH_FAILURE_TIMEOUT_REASON) {
            std::io::ErrorKind::TimedOut
        } else {
            std::io::ErrorKind::Other
        };
        let message = if kind == std::io::ErrorKind::TimedOut {
            MANAGED_REFRESH_TIMEOUT_MESSAGE
        } else {
            "managed ChatGPT token refresh failed in the active owner"
        };
        return RefreshTokenError::Transient(std::io::Error::new(kind, message));
    }
    let reason = match failure.reason_code.as_deref() {
        Some("refresh_token_expired") => RefreshTokenFailedReason::Expired,
        Some("refresh_token_reused") => RefreshTokenFailedReason::Exhausted,
        Some("refresh_token_invalidated") => RefreshTokenFailedReason::Revoked,
        _ => RefreshTokenFailedReason::Other,
    };
    let message = match reason {
        RefreshTokenFailedReason::Expired => REFRESH_TOKEN_EXPIRED_MESSAGE,
        RefreshTokenFailedReason::Exhausted => REFRESH_TOKEN_REUSED_MESSAGE,
        RefreshTokenFailedReason::Revoked => REFRESH_TOKEN_INVALIDATED_MESSAGE,
        RefreshTokenFailedReason::Other => REFRESH_TOKEN_UNKNOWN_MESSAGE,
    };
    RefreshTokenError::Permanent(RefreshTokenFailedError::new(reason, message))
}

pub(in super::super) fn persist_managed_refresh_failure(
    storage: &Arc<dyn AuthStorageBackend>,
    identity: &str,
    expected_operation_id: Option<&str>,
    reason_code: &str,
    permanent: bool,
) -> std::io::Result<(bool, bool)> {
    let mut changed = false;
    let mut transitioned = false;
    storage.mutate(&mut |current| {
        let Some(mut auth) = current else {
            return Ok(AuthStorageMutation::Keep(None));
        };
        let Some(account) = row_mut(&mut auth, identity) else {
            return Ok(AuthStorageMutation::Keep(Some(auth)));
        };
        let matching_operation_id = expected_operation_id.and_then(|expected| {
            account
                .mutation_lease
                .as_ref()
                .filter(|lease| lease.kind == ManagedChatgptMutationKind::Refresh)
                .filter(|lease| lease.operation_id == expected)
                .map(|lease| lease.operation_id.clone())
        });
        if let Some(operation_id) = matching_operation_id {
            account.mutation_lease = None;
            account.refresh_failure = Some(ManagedChatgptRefreshFailure {
                observed_at: Utc::now(),
                permanent,
                reason_code: Some(reason_code.to_string()),
                operation_id: Some(operation_id),
            });
            if permanent {
                account.block = Some(ManagedChatgptBlock {
                    kind: ManagedChatgptBlockKind::AuthInvalid,
                    blocked_at: Utc::now(),
                    reset_at: None,
                    credential_revision: credential_revision(account),
                });
            }
            account.revision = account.revision.saturating_add(1);
            changed = true;
            transitioned = true;
            return Ok(AuthStorageMutation::Save(auth));
        }
        if account.refresh_failure.as_ref().is_some_and(|failure| {
            !failure.permanent
                && failure.reason_code.as_deref() == Some(REFRESH_FAILURE_CANCELLED_REASON)
                && expected_operation_id
                    .is_none_or(|expected| failure.operation_id.as_deref() == Some(expected))
        }) {
            if let Some(failure) = account.refresh_failure.as_mut() {
                failure.reason_code = Some(reason_code.to_string());
                failure.observed_at = Utc::now();
            }
            account.revision = account.revision.saturating_add(1);
            changed = true;
            return Ok(AuthStorageMutation::Save(auth));
        }
        Ok(AuthStorageMutation::Keep(Some(auth)))
    })?;
    Ok((changed, transitioned))
}

/// External modifications to `auth.json` will NOT be observed until
/// `reload()` is called explicitly. This matches the design goal of avoiding
/// different parts of the program seeing inconsistent auth data mid‑run.
struct ManagedRefreshLeaseGuard {
    storage: Arc<dyn AuthStorageBackend>,
    identity: String,
    operation_id: String,
    auth_change_tx: watch::Sender<u64>,
    armed: bool,
}

impl ManagedRefreshLeaseGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ManagedRefreshLeaseGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        match persist_managed_refresh_failure(
            &self.storage,
            &self.identity,
            Some(&self.operation_id),
            REFRESH_FAILURE_CANCELLED_REASON,
            false,
        ) {
            Ok((_, true)) => {
                self.auth_change_tx.send_modify(|revision| *revision += 1);
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!("failed to persist cancelled managed ChatGPT refresh: {err}");
            }
        }
    }
}

impl AuthManager {
    pub async fn refresh_managed_chatgpt_account(
        &self,
        selector: &str,
    ) -> Result<ManagedChatgptAuthSnapshot, RefreshTokenError> {
        self.refresh_managed_chatgpt_account_bounded(selector, MANAGED_REFRESH_MAX_DURATION)
            .await
    }

    pub async fn refresh_managed_chatgpt_account_bounded(
        &self,
        selector: &str,
        timeout: Duration,
    ) -> Result<ManagedChatgptAuthSnapshot, RefreshTokenError> {
        self.refresh_managed_chatgpt_account_bounded_impl(selector, false, timeout)
            .await
    }

    pub(in crate::auth::manager) async fn refresh_managed_chatgpt_account_bounded_impl(
        &self,
        selector: &str,
        force: bool,
        timeout: Duration,
    ) -> Result<ManagedChatgptAuthSnapshot, RefreshTokenError> {
        let operation_id = format!("refresh:{:032x}", rand::rng().random::<u128>());
        match tokio::time::timeout(
            timeout.min(MANAGED_REFRESH_MAX_DURATION),
            self.refresh_managed_chatgpt_account_impl(selector, force, &operation_id),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                let identity = self
                    .load_managed_chatgpt_document()
                    .ok()
                    .flatten()
                    .and_then(|document| resolve_identity(&document, selector).ok().flatten());
                if let Some(identity) = identity {
                    match persist_managed_refresh_failure(
                        &self.managed_chatgpt_storage(),
                        &identity,
                        Some(operation_id.as_str()),
                        REFRESH_FAILURE_TIMEOUT_REASON,
                        false,
                    ) {
                        Ok((true, _)) => {
                            self.notify_managed_chatgpt_change();
                            self.reload().await;
                        }
                        Ok((false, _)) => {}
                        Err(err) => {
                            tracing::warn!(
                                "failed to persist timed out managed ChatGPT refresh: {err}"
                            );
                        }
                    }
                }
                Err(RefreshTokenError::Transient(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    MANAGED_REFRESH_TIMEOUT_MESSAGE,
                )))
            }
        }
    }

    async fn refresh_managed_chatgpt_account_impl(
        &self,
        selector: &str,
        force: bool,
        operation_id: &str,
    ) -> Result<ManagedChatgptAuthSnapshot, RefreshTokenError> {
        self.resume_managed_chatgpt_tombstones()
            .await
            .map_err(RefreshTokenError::Transient)?;
        let storage = self.managed_chatgpt_storage();
        let initial = self
            .load_managed_chatgpt_document()
            .map_err(RefreshTokenError::Transient)?
            .ok_or_else(|| {
                RefreshTokenError::Transient(std::io::Error::other(
                    "managed ChatGPT account pool is unavailable",
                ))
            })?;
        let identity = resolve_identity(&initial, selector)
            .map_err(RefreshTokenError::Transient)?
            .ok_or_else(|| {
                RefreshTokenError::Transient(std::io::Error::other(
                    "managed ChatGPT account was not found",
                ))
            })?;
        let initial_row = row(&initial, &identity).ok_or_else(|| {
            RefreshTokenError::Transient(std::io::Error::other(
                "managed ChatGPT account was not found",
            ))
        })?;
        if let Some(allowed) = self.forced_chatgpt_workspace_id()
            && !initial_row
                .chatgpt_account_id
                .as_ref()
                .is_some_and(|id| allowed.contains(id))
        {
            return Err(RefreshTokenError::Transient(std::io::Error::other(
                "no eligible managed ChatGPT account is available: account is disallowed by forced workspace policy",
            )));
        }
        if let Some(failure) = initial_row.refresh_failure.as_ref().filter(|failure| {
            failure.permanent
                || matches!(
                    failure.reason_code.as_deref(),
                    Some(
                        REFRESH_FAILURE_CANCELLED_REASON
                            | REFRESH_FAILURE_TIMEOUT_REASON
                            | REFRESH_FAILURE_COMMIT_REASON
                    )
                )
        }) {
            return Err(persisted_refresh_failure_result(failure));
        }
        let expected_revision = credential_revision(initial_row);
        let refresh_due = match parse_jwt_expiration(&initial_row.tokens.access_token) {
            Ok(Some(expires_at)) => {
                expires_at
                    <= Utc::now()
                        + chrono::Duration::minutes(CHATGPT_ACCESS_TOKEN_REFRESH_WINDOW_MINUTES)
            }
            Ok(None) | Err(_) => {
                initial_row.last_refresh
                    < Utc::now() - chrono::Duration::days(TOKEN_REFRESH_INTERVAL)
            }
        };
        if !force && !refresh_due {
            return self
                .managed_chatgpt_auth_snapshot_for_identity(&identity)
                .await
                .map_err(RefreshTokenError::Transient)?
                .ok_or_else(|| {
                    RefreshTokenError::Transient(std::io::Error::other(
                        "managed ChatGPT account disappeared before refresh",
                    ))
                });
        }
        let expected_refresh_token = initial_row.tokens.refresh_token.clone();
        let mut waiting_for_operation_id: Option<String> = None;
        let refresh_token = loop {
            let mut acquired = None;
            let mut owner_failure = None;
            let result =
                storage.mutate(&mut |current| {
                    let Some(mut auth) = current else {
                        return Ok(AuthStorageMutation::Keep(None));
                    };
                    let Some(account) = row_mut(&mut auth, &identity) else {
                        return Ok(AuthStorageMutation::Keep(Some(auth)));
                    };
                    if account.tombstone.is_some() {
                        return Err(std::io::Error::other(
                            "managed ChatGPT account is pending removal",
                        ));
                    }
                    if credential_revision(account) != expected_revision
                        || account.tokens.refresh_token != expected_refresh_token
                    {
                        return Ok(AuthStorageMutation::Keep(Some(auth)));
                    }
                    if let Some(waited_for) = waiting_for_operation_id.as_deref()
                        && let Some(failure) = account
                            .refresh_failure
                            .as_ref()
                            .filter(|failure| failure.operation_id.as_deref() == Some(waited_for))
                    {
                        owner_failure = Some(failure.clone());
                        return Ok(AuthStorageMutation::Keep(Some(auth)));
                    }
                    if let Some(lease) = account.mutation_lease.as_ref().filter(|lease| {
                        lease.expires_at > Utc::now() && lease.operation_id != operation_id
                    }) {
                        waiting_for_operation_id = Some(lease.operation_id.clone());
                        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                    }
                    account.mutation_lease = Some(ManagedChatgptMutationLease {
                        operation_id: operation_id.to_string(),
                        kind: ManagedChatgptMutationKind::Refresh,
                        expected_revision,
                        expected_refresh_token: expected_refresh_token.clone(),
                        expires_at: Utc::now()
                            + chrono::Duration::seconds(
                                MANAGED_REFRESH_LEASE_DURATION.as_secs() as i64
                            ),
                    });
                    acquired = Some(expected_refresh_token.clone());
                    Ok(AuthStorageMutation::SaveInternalState(auth))
                });
            match result {
                Ok(_) => {
                    if let Some(failure) = owner_failure {
                        return Err(persisted_refresh_failure_result(&failure));
                    }
                    if let Some(acquired) = acquired {
                        break acquired;
                    }
                    return self
                        .managed_chatgpt_auth_snapshot_for_identity(&identity)
                        .await
                        .map_err(RefreshTokenError::Transient)?
                        .ok_or_else(|| {
                            RefreshTokenError::Transient(std::io::Error::other(
                                "managed ChatGPT account disappeared during refresh",
                            ))
                        });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(err) => return Err(RefreshTokenError::Transient(err)),
            }
        };
        let mut lease_guard = ManagedRefreshLeaseGuard {
            storage: storage.clone(),
            identity: identity.clone(),
            operation_id: operation_id.to_string(),
            auth_change_tx: self.auth_change_tx.clone(),
            armed: true,
        };
        let response =
            match create_default_auth_client(&refresh_token_endpoint(), &self.auth_route_config) {
                Ok(client) => request_chatgpt_token_refresh(refresh_token, &client)
                    .await
                    .and_then(|response| {
                        for (field, token) in [
                            ("access_token", response.access_token.as_deref()),
                            ("refresh_token", response.refresh_token.as_deref()),
                        ] {
                            if token.is_some_and(|token| token.trim().is_empty()) {
                                return Err(RefreshTokenError::Transient(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("managed ChatGPT refresh returned a blank {field}"),
                                )));
                            }
                        }
                        let refreshed_id_token = response
                            .id_token
                            .as_deref()
                            .map(parse_chatgpt_jwt_claims)
                            .transpose()
                            .map_err(std::io::Error::other)
                            .map_err(RefreshTokenError::Transient)?;
                        Ok((response, refreshed_id_token))
                    }),
                Err(err) => Err(RefreshTokenError::Transient(std::io::Error::other(err))),
            };
        let (response, refreshed_id_token) = match response {
            Ok(response) => response,
            Err(err) => {
                let permanent = matches!(err, RefreshTokenError::Permanent(_));
                let reason_code = refresh_failure_reason_code(&err);
                let persisted = persist_managed_refresh_failure(
                    &storage,
                    &identity,
                    Some(operation_id),
                    reason_code,
                    permanent,
                );
                if persisted.as_ref().is_ok_and(|(changed, _)| *changed) {
                    lease_guard.disarm();
                }
                if persisted.as_ref().is_ok_and(|(changed, _)| *changed) {
                    self.notify_managed_chatgpt_change();
                    self.reload().await;
                }
                return Err(err);
            }
        };
        let forced = self.forced_chatgpt_workspace_id();
        let mut committed_identity = identity.clone();
        let commit_result = storage.mutate(&mut |current| {
            let Some(mut auth) = current else {
                return Err(std::io::Error::other(
                    "managed ChatGPT auth disappeared during refresh",
                ));
            };
            let mut tokens = {
                let account = row_mut(&mut auth, &identity).ok_or_else(|| {
                    std::io::Error::other("managed ChatGPT account disappeared during refresh")
                })?;
                if account.tombstone.is_some()
                    || credential_revision(account) != expected_revision
                    || account.tokens.refresh_token != expected_refresh_token
                    || account
                        .mutation_lease
                        .as_ref()
                        .is_none_or(|lease| lease.operation_id != operation_id)
                {
                    return Err(std::io::Error::other(
                        "managed ChatGPT refresh lost its mutation lease",
                    ));
                }
                account.tokens.clone()
            };
            if let Some(id_token) = refreshed_id_token.clone() {
                tokens.id_token = id_token;
            }
            if let Some(access_token) = response.access_token.clone() {
                tokens.access_token = access_token;
            }
            if let Some(refresh_token) = response.refresh_token.clone() {
                tokens.refresh_token = refresh_token;
            }
            let rebound_identity =
                rebind_refreshed_identity(&mut auth, &identity, tokens, forced.as_deref())?;
            let revision = {
                let pool = auth.managed_chatgpt.as_mut().ok_or_else(|| {
                    std::io::Error::other("managed ChatGPT account pool disappeared during refresh")
                })?;
                allocate_account_revision(pool)
            };
            let account = row_mut(&mut auth, &rebound_identity).ok_or_else(|| {
                std::io::Error::other("managed ChatGPT account disappeared during refresh")
            })?;
            account.revision = revision;
            account.credential_revision = revision;
            if let Some(block) = account.block.as_mut() {
                block.credential_revision = revision;
            }
            account.last_refresh = Utc::now();
            account.mutation_lease = None;
            account.refresh_failure = None;
            if account
                .block
                .as_ref()
                .is_some_and(|block| block.kind == ManagedChatgptBlockKind::AuthInvalid)
            {
                account.block = None;
            }
            committed_identity = rebound_identity;
            Ok(AuthStorageMutation::Save(auth))
        });
        if let Err(err) = commit_result {
            let refresh_error = RefreshTokenError::Transient(err);
            let persisted = persist_managed_refresh_failure(
                &storage,
                &identity,
                Some(operation_id),
                REFRESH_FAILURE_COMMIT_REASON,
                false,
            );
            if persisted.as_ref().is_ok_and(|(changed, _)| *changed) {
                lease_guard.disarm();
                self.notify_managed_chatgpt_change();
                self.reload().await;
            }
            return Err(refresh_error);
        }
        lease_guard.disarm();
        self.notify_managed_chatgpt_change();
        self.reload().await;
        self.managed_chatgpt_auth_snapshot_for_identity(&committed_identity)
            .await
            .map_err(RefreshTokenError::Transient)?
            .ok_or_else(|| {
                RefreshTokenError::Transient(std::io::Error::other(
                    "managed ChatGPT account disappeared after refresh",
                ))
            })
    }
    pub async fn recover_failed_attempt(
        &self,
        snapshot: &ManagedChatgptAuthSnapshot,
        failure: ManagedChatgptFailure,
        committed: bool,
        scope: &ManagedChatgptSelectionScope,
    ) -> std::io::Result<ManagedChatgptRecoveryDecision> {
        self.resume_managed_chatgpt_tombstones().await?;
        let Some(current) = self
            .managed_chatgpt_auth_snapshot_for_identity(&snapshot.identity_key)
            .await?
            .filter(|current| {
                current.account_revision == snapshot.account_revision
                    && current.account_state_revision >= snapshot.account_state_revision
                    && current.transport == snapshot.transport
            })
        else {
            return Ok(ManagedChatgptRecoveryDecision::Stop);
        };
        if committed
            || matches!(
                failure,
                ManagedChatgptFailure::Transport
                    | ManagedChatgptFailure::Server
                    | ManagedChatgptFailure::TransientRateLimit
            )
        {
            return Ok(ManagedChatgptRecoveryDecision::Keep(current));
        }
        let storage = self.managed_chatgpt_storage();
        let mut changed = false;
        storage.mutate(&mut |current| {
            let Some(mut auth) = current else {
                return Ok(AuthStorageMutation::Keep(None));
            };
            changed = apply_failure(
                &mut auth,
                &snapshot.identity_key,
                snapshot.account_revision,
                failure,
                Utc::now(),
            );
            if changed {
                Ok(AuthStorageMutation::Save(auth))
            } else {
                Ok(AuthStorageMutation::Keep(Some(auth)))
            }
        })?;
        if !changed {
            return Ok(ManagedChatgptRecoveryDecision::Stop);
        }
        self.notify_managed_chatgpt_change();
        match self.managed_chatgpt_auth_snapshot(scope).await? {
            Some(next) if next.identity_key != snapshot.identity_key => {
                Ok(ManagedChatgptRecoveryDecision::Rotate(next))
            }
            Some(next) => Ok(ManagedChatgptRecoveryDecision::Keep(next)),
            None => Ok(ManagedChatgptRecoveryDecision::Stop),
        }
    }

    pub(in crate::auth::manager) async fn resume_managed_chatgpt_tombstones(
        &self,
    ) -> std::io::Result<()> {
        let _permit = self
            .managed_lifecycle_lock
            .acquire()
            .await
            .map_err(std::io::Error::other)?;
        self.resume_managed_chatgpt_tombstones_impl().await
    }

    async fn resume_managed_chatgpt_tombstones_impl(&self) -> std::io::Result<()> {
        let identities = self
            .load_managed_chatgpt_document()?
            .and_then(|auth| auth.managed_chatgpt)
            .map(|pool| {
                pool.accounts
                    .into_iter()
                    .filter(|account| account.tombstone.is_some())
                    .map(|account| account.identity_key)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for identity in identities {
            self.remove_managed_chatgpt_account_impl(&identity).await?;
        }
        Ok(())
    }

    pub async fn remove_managed_chatgpt_account(&self, selector: &str) -> std::io::Result<bool> {
        let _permit = self
            .managed_lifecycle_lock
            .acquire()
            .await
            .map_err(std::io::Error::other)?;
        let removed = self.remove_managed_chatgpt_account_impl(selector).await?;
        self.resume_managed_chatgpt_tombstones_impl().await?;
        Ok(removed)
    }

    async fn remove_managed_chatgpt_account_impl(&self, selector: &str) -> std::io::Result<bool> {
        let storage = self.managed_chatgpt_storage();
        let Some(initial) = self.load_managed_chatgpt_document()? else {
            return Ok(false);
        };
        let Some(identity) = resolve_identity(&initial, selector)? else {
            return Ok(false);
        };
        let operation_id = initial
            .managed_chatgpt
            .as_ref()
            .and_then(|pool| {
                pool.accounts
                    .iter()
                    .find(|account| account.identity_key == identity)
            })
            .and_then(|account| account.tombstone.as_ref())
            .map(|tombstone| tombstone.operation_id.clone())
            .unwrap_or_else(|| format!("remove:{:032x}", rand::rng().random::<u128>()));
        let tombstoned = loop {
            let mut selected = None;
            let result = storage.mutate(&mut |current| {
                let Some(mut auth) = current else {
                    return Ok(AuthStorageMutation::Keep(None));
                };
                migrate_document(&mut auth, Utc::now());
                let Some(account) = row_mut(&mut auth, &identity) else {
                    return Ok(AuthStorageMutation::Keep(Some(auth)));
                };
                if account.mutation_lease.as_ref().is_some_and(|lease| {
                    lease.expires_at > Utc::now() && lease.operation_id != operation_id
                }) {
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                if let Some(existing) = account.tombstone.as_ref() {
                    if existing.operation_id != operation_id {
                        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                    }
                } else {
                    account.tombstone = Some(ManagedChatgptTombstone {
                        operation_id: operation_id.clone(),
                        revision: credential_revision(account),
                        refresh_token: account.tokens.refresh_token.clone(),
                    });
                    account.revision = account.revision.saturating_add(1);
                }
                account.mutation_lease = Some(ManagedChatgptMutationLease {
                    operation_id: operation_id.clone(),
                    kind: ManagedChatgptMutationKind::Remove,
                    expected_revision: credential_revision(account),
                    expected_refresh_token: account.tokens.refresh_token.clone(),
                    expires_at: Utc::now() + chrono::Duration::minutes(5),
                });
                selected = Some(singular_document(account));
                Ok(AuthStorageMutation::Save(auth))
            });
            match result {
                Ok(_) => break selected,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(err) => return Err(err),
            }
        };
        let Some(revoke_document) = tombstoned else {
            return Ok(false);
        };
        if let Err(err) = revoke_auth_tokens(Some(&revoke_document), &self.auth_route_config).await
        {
            tracing::warn!("failed to revoke targeted managed ChatGPT account: {err}");
        }
        let mut removed = false;
        storage.mutate(&mut |current| {
            let Some(mut auth) = current else {
                return Ok(AuthStorageMutation::Keep(None));
            };
            if let Some(pool) = auth.managed_chatgpt.as_mut()
                && let Some(index) = pool.accounts.iter().position(|account| {
                    account
                        .tombstone
                        .as_ref()
                        .is_some_and(|tombstone| tombstone.operation_id == operation_id)
                })
            {
                pool.accounts.remove(index);
                removed = true;
            }
            if removed {
                auth.auth_mode = Some(AuthMode::Chatgpt);
                auth.openai_api_key = None;
                auth.tokens = None;
                auth.last_refresh = None;
                auth.agent_identity = None;
                auth.personal_access_token = None;
                auth.bedrock_api_key = None;
                Ok(AuthStorageMutation::Save(auth))
            } else {
                Ok(AuthStorageMutation::Keep(Some(auth)))
            }
        })?;
        if removed {
            self.selection_pins.clear();
            self.notify_managed_chatgpt_change();
            self.reload().await;
        }
        Ok(removed)
    }
}
