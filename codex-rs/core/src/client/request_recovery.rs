use super::*;

/// Recovery belongs to one logical request, not a credential generation or transport attempt.
#[derive(Default)]
pub(super) struct RequestRecovery {
    unauthorized: Vec<UnauthorizedAllowance>,
    provider_auth_recovery_attempted: bool,
    pub(super) pending_retry: PendingUnauthorizedRetry,
    rotations_remaining: Option<usize>,
    pub(super) excluded_identities: Option<Arc<Vec<String>>>,
}

struct UnauthorizedAllowance {
    identity: RecoveryIdentity,
    recovery: Option<UnauthorizedRecovery>,
}

enum RecoveryIdentity {
    Managed(String),
    Other(TransportAuthBinding, Option<u64>),
}

impl RequestRecovery {
    pub(super) fn prepare(
        &mut self,
        auth_manager: Option<&Arc<AuthManager>>,
        setup: &ProviderRequestSetup,
    ) -> usize {
        if setup.managed_snapshot.is_some() && self.rotations_remaining.is_none() {
            // Freeze the initial pool size. Cooldown expiry or concurrent additions cannot
            // extend this request, but failure persistence still runs after exhaustion.
            let accounts = auth_manager.and_then(|manager| manager.managed_chatgpt_accounts().ok());
            self.rotations_remaining =
                Some(accounts.map_or(0, |accounts| accounts.len().saturating_sub(1)));
        }
        if let Some(index) = self
            .unauthorized
            .iter()
            .position(|entry| match &entry.identity {
                RecoveryIdentity::Managed(identity) => setup.managed_id.as_ref() == Some(identity),
                RecoveryIdentity::Other(binding, revision) => {
                    setup.managed_id.is_none()
                        && binding == &setup.transport_auth_binding
                        && *revision == setup.credential_revision.or(setup.auth_revision)
                }
            })
        {
            return index;
        }
        let identity = match &setup.managed_id {
            Some(identity) => RecoveryIdentity::Managed(identity.clone()),
            None => RecoveryIdentity::Other(
                setup.transport_auth_binding.clone(),
                setup.credential_revision.or(setup.auth_revision),
            ),
        };
        let recovery = auth_manager.map(|manager| {
            setup.managed_snapshot.as_ref().map_or_else(
                || manager.unauthorized_recovery(),
                |snapshot| manager.unauthorized_recovery_for_snapshot(snapshot),
            )
        });
        self.pending_retry = PendingUnauthorizedRetry::default();
        self.unauthorized
            .push(UnauthorizedAllowance { identity, recovery });
        self.unauthorized.len() - 1
    }

    pub(super) async fn recover_unauthorized(
        &mut self,
        transport: TransportError,
        allowance: usize,
        session_telemetry: &SessionTelemetry,
        client: &ModelClient,
        turn_id: Option<&str>,
    ) -> Result<()> {
        let recovery = handle_unauthorized(
            transport,
            &mut self.unauthorized[allowance].recovery,
            &mut self.provider_auth_recovery_attempted,
            session_telemetry,
            &client.state.provider,
            client.event_sender.as_ref(),
            turn_id,
        )
        .await?;
        self.pending_retry = PendingUnauthorizedRetry::from_recovery(recovery);
        Ok(())
    }

    pub(super) async fn recover_managed_attempt(
        &mut self,
        client: &ModelClient,
        attempt: &ManagedChatgptAttemptContext,
        error: &CodexErr,
        committed: bool,
    ) -> bool {
        let Some(failure) = managed_accounts::managed_chatgpt_failure(error) else {
            return false;
        };
        let Some(auth_manager) = client.state.provider.auth_manager() else {
            return false;
        };
        let model_quota = match error.details() {
            CodexErrorDetails::UsageLimitReached(quota)
                if matches!(
                    quota.rate_limit_reached_type,
                    None | Some(RateLimitReachedType::RateLimitReached)
                ) =>
            {
                quota
                    .model_limit_name()
                    .is_some_and(|name| !name.eq_ignore_ascii_case("gpt_reserve"))
                    && quota.rate_limits.as_ref().is_some_and(|limits| {
                        !limits.limit_id.as_deref().is_some_and(|id| {
                            ["codex", "gpt-reserve", "gpt_reserve"]
                                .iter()
                                .any(|global| id.trim().eq_ignore_ascii_case(global))
                        })
                    })
            }
            _ => false,
        };
        if model_quota {
            if committed
                || self
                    .rotations_remaining
                    .is_none_or(|remaining| remaining == 0)
            {
                return false;
            }
            if !matches!(
                auth_manager
                    .managed_chatgpt_auth_snapshot_for_attempt(&attempt.snapshot)
                    .await,
                Ok(Some(_))
            ) {
                return false;
            }
            let excluded = self
                .excluded_identities
                .get_or_insert_with(Default::default);
            if !excluded.contains(&attempt.snapshot.identity_key) {
                Arc::make_mut(excluded).push(attempt.snapshot.identity_key.clone());
            }
        }
        // A subsequent durable/auth failure must not reselect a locally exhausted identity.
        let scope = ManagedChatgptSelectionScope {
            excluded_identities: self.excluded_identities.clone(),
            ..attempt.scope.clone()
        };
        let decision = if model_quota {
            auth_manager
                .managed_chatgpt_auth_snapshot(&scope)
                .await
                .map(|next| {
                    next.map_or(
                        ManagedChatgptRecoveryDecision::Stop,
                        ManagedChatgptRecoveryDecision::Rotate,
                    )
                })
        } else {
            auth_manager
                .recover_failed_attempt(&attempt.snapshot, failure, committed, &scope)
                .await
        };
        match decision {
            Ok(ManagedChatgptRecoveryDecision::Rotate(_)) => {
                let Some(remaining) = self.rotations_remaining.as_mut() else {
                    return false;
                };
                if *remaining == 0 {
                    return false;
                }
                *remaining -= 1;
                true
            }
            Ok(ManagedChatgptRecoveryDecision::Keep(_) | ManagedChatgptRecoveryDecision::Stop) => {
                false
            }
            Err(err) => {
                warn!(
                    managed_account = %attempt.snapshot.diagnostic_account_fingerprint(),
                    "failed to recover managed account request: {err}"
                );
                false
            }
        }
    }
}

impl ModelClientSession {
    /// Starts a logical request without discarding turn-scoped transport or sticky routing.
    /// Call once before its retry loop, including when reusing a session after compaction.
    pub fn begin_request(&mut self) {
        self.request_recovery = RequestRecovery::default();
        self.request_scope_refresh_pending = false;
        self.managed_attempt = None;
    }
}
