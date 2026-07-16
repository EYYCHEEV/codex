use super::*;

pub(in crate::request_processors::account_processor) struct PoolUpdateWatcherShutdown(
    pub(in crate::request_processors::account_processor) CancellationToken,
);

impl PoolUpdateWatcherShutdown {
    pub(in crate::request_processors::account_processor) fn cancel(&self) {
        self.0.cancel();
    }
}

impl Drop for PoolUpdateWatcherShutdown {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(in crate::request_processors::account_processor) fn start_pool_update_watcher(
    auth_manager: &Arc<AuthManager>,
    outgoing: &Arc<OutgoingMessageSender>,
) -> (
    Arc<Mutex<AccountSelectionObserverState>>,
    Arc<PoolUpdateWatcherShutdown>,
) {
    let pool_update_shutdown = CancellationToken::new();
    let selection_observer_state = Arc::new(Mutex::new(AccountSelectionObserverState::default()));
    let mut revisions = auth_manager.auth_change_receiver();
    let subscriber_auth_manager = Arc::clone(auth_manager);
    let subscriber_outgoing = Arc::clone(outgoing);
    let subscriber_shutdown = pool_update_shutdown.clone();
    let subscriber_selection_observer = AccountSelectionObserver {
        state: Arc::clone(&selection_observer_state),
        event_registration: None,
    };
    tokio::spawn(async move {
        let mut last_pool_revision = None;
        loop {
            tokio::select! {
                _ = subscriber_shutdown.cancelled() => break,
                changed = revisions.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    if subscriber_auth_manager.is_external_chatgpt_auth_active() {
                        continue;
                    }
                    let list = match subscriber_auth_manager
                        .list_managed_chatgpt_accounts(
                            &ManagedChatgptSelectionScope::default(),
                        )
                        .await
                    {
                        Ok(list) => list,
                        Err(err) => {
                            warn!("failed to read managed account pool update: {err}");
                            continue;
                        }
                    };
                    if !should_emit_pool_update(
                        &mut last_pool_revision,
                        list.pool_revision,
                        list.accounts.is_empty(),
                    ) {
                        continue;
                    }
                    let response = AccountRequestProcessor::list_accounts_response_from_owner(
                        list,
                        false,
                        &HashMap::new(),
                    );
                    if !send_pool_update_unless_shutdown(
                        &subscriber_outgoing,
                        &subscriber_shutdown,
                        AccountPoolUpdatedNotification {
                            accounts: response.accounts,
                            pool_revision: response.pool_revision,
                        },
                    )
                    .await
                    {
                        break;
                    }
                    let observed: Vec<_> = subscriber_selection_observer
                        .state
                        .lock()
                        .await
                        .observed_selections
                        .values()
                        .cloned()
                        .collect();
                    for previous in observed {
                        let Ok(scoped) = subscriber_auth_manager
                            .list_managed_chatgpt_accounts(&previous.scope)
                            .await
                        else {
                            continue;
                        };
                        if scoped.selection_revision <= previous.selection_revision {
                            continue;
                        }
                        let Some(thread_id) = previous.scope.thread_id.clone() else {
                            continue;
                        };
                        let notification = AccountSelectionUpdatedNotification {
                            thread_id: thread_id.clone(),
                            selected_account_id: scoped.selected_account_id.clone(),
                            selection_revision: scoped.selection_revision,
                        };
                        let routes = subscriber_selection_observer
                            .update_if_current(
                                &previous,
                                scoped.selected_account_id.clone(),
                                scoped.selection_revision,
                            )
                            .await;
                        for route in routes {
                            route.send(notification.clone()).await;
                        }
                    }
                }
            }
        }
    });
    (
        selection_observer_state,
        Arc::new(PoolUpdateWatcherShutdown(pool_update_shutdown)),
    )
}

pub(in crate::request_processors::account_processor) async fn send_pool_update_unless_shutdown(
    outgoing: &OutgoingMessageSender,
    shutdown: &CancellationToken,
    notification: AccountPoolUpdatedNotification,
) -> bool {
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => false,
        _ = outgoing.send_server_notification(
            ServerNotification::AccountPoolUpdated(notification)
        ) => true,
    }
}

pub(in crate::request_processors::account_processor) fn should_emit_pool_update(
    last_pool_revision: &mut Option<u64>,
    pool_revision: u64,
    accounts_empty: bool,
) -> bool {
    if pool_revision == 0 && accounts_empty {
        return false;
    }
    if *last_pool_revision == Some(pool_revision) {
        return false;
    }
    *last_pool_revision = Some(pool_revision);
    true
}
