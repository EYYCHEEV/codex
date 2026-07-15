use super::bedrock_auth::clear_user_model_provider_if_bedrock;
use super::bedrock_auth::set_user_model_provider_to_bedrock;
use super::*;
use crate::auth_mode::auth_mode_to_api;
use crate::external_auth::ExternalAuthBridge;
use chrono::DateTime;
use chrono::Utc;
use codex_model_provider::BearerAuthProvider;
use codex_model_provider::is_supported_amazon_bedrock_region;

mod rate_limit_resets;

// Duration before a browser ChatGPT login attempt is abandoned.
const LOGIN_CHATGPT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const ACCOUNT_RATE_LIMIT_FETCH_TIMEOUT: Duration = Duration::from_secs(/*secs*/ 10);
const ACCOUNT_TOKEN_REFRESH_TIMEOUT: Duration = Duration::from_secs(/*secs*/ 10);
const ACCOUNT_TOKEN_USAGE_FETCH_TIMEOUT: Duration = Duration::from_secs(/*secs*/ 10);
const ACCOUNT_WORKSPACE_MESSAGES_FETCH_TIMEOUT: Duration =
    Duration::from_millis(/*millis*/ 1000);
// Login overrides are intentionally available only in debug builds.
#[cfg(debug_assertions)]
const LOGIN_ISSUER_OVERRIDE_ENV_VAR: &str = "CODEX_APP_SERVER_LOGIN_ISSUER";
#[cfg(debug_assertions)]
const LOGIN_OPEN_APP_URL_OVERRIDE_ENV_VAR: &str = "CODEX_APP_SERVER_DEV_OPEN_APP_URL";

enum ActiveLogin {
    Browser {
        shutdown_handle: ShutdownHandle,
        login_id: Uuid,
    },
    DeviceCode {
        cancel: CancellationToken,
        login_id: Uuid,
    },
}

impl ActiveLogin {
    fn login_id(&self) -> Uuid {
        match self {
            ActiveLogin::Browser { login_id, .. } | ActiveLogin::DeviceCode { login_id, .. } => {
                *login_id
            }
        }
    }

    fn cancel(&self) {
        match self {
            ActiveLogin::Browser {
                shutdown_handle, ..
            } => shutdown_handle.shutdown(),
            ActiveLogin::DeviceCode { cancel, .. } => cancel.cancel(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CancelLoginError {
    NotFound,
}

enum RefreshTokenRequestOutcome {
    NotAttemptedOrSucceeded,
    FailedTransiently,
    FailedPermanently,
}
type RefreshStatusByIdentity = HashMap<String, (DateTime<Utc>, ManagedChatgptAccountRefreshStatus)>;

impl Drop for ActiveLogin {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[derive(Clone)]
struct SelectionNotificationTarget {
    connection_id: ConnectionId,
    validity: CancellationToken,
}

#[derive(Clone)]
struct SelectionNotificationRoute {
    outgoing: Arc<OutgoingMessageSender>,
    targets: Arc<Vec<SelectionNotificationTarget>>,
}

impl SelectionNotificationRoute {
    fn from_thread(outgoing: &ThreadScopedOutgoingMessageSender) -> Self {
        let (outgoing, connection_ids) = outgoing.notification_target();
        Self {
            outgoing,
            targets: Arc::new(
                connection_ids
                    .iter()
                    .copied()
                    .map(|connection_id| SelectionNotificationTarget {
                        connection_id,
                        validity: CancellationToken::new(),
                    })
                    .collect(),
            ),
        }
    }

    fn for_connection(outgoing: Arc<OutgoingMessageSender>, connection_id: ConnectionId) -> Self {
        Self {
            outgoing,
            targets: Arc::new(vec![SelectionNotificationTarget {
                connection_id,
                validity: CancellationToken::new(),
            }]),
        }
    }

    fn same_sender(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.outgoing, &other.outgoing)
    }

    fn merge(&mut self, mut other: Self) -> Self {
        debug_assert!(self.same_sender(&other));
        let targets = Arc::make_mut(&mut self.targets);
        for target in Arc::make_mut(&mut other.targets) {
            if let Some(known) = targets
                .iter()
                .find(|known| known.connection_id == target.connection_id)
            {
                *target = known.clone();
            } else {
                targets.push(target.clone());
            }
        }
        other
    }

    fn remove_connection(&mut self, connection_id: ConnectionId) {
        let targets = Arc::make_mut(&mut self.targets);
        for target in targets
            .iter()
            .filter(|target| target.connection_id == connection_id)
        {
            target.validity.cancel();
        }
        targets.retain(|target| target.connection_id != connection_id);
    }

    fn invalidate(&self) {
        for target in self.targets.iter() {
            target.validity.cancel();
        }
    }

    fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    async fn send(&self, notification: AccountSelectionUpdatedNotification) {
        for target in self.targets.iter() {
            tokio::select! {
                biased;
                _ = target.validity.cancelled() => {}
                _ = self.outgoing.send_server_notification_to_connections(
                    std::slice::from_ref(&target.connection_id),
                    ServerNotification::AccountSelectionUpdated(notification.clone()),
                ) => {}
            }
        }
    }

    #[cfg(test)]
    fn connection_ids_for_test(&self) -> Vec<ConnectionId> {
        self.targets
            .iter()
            .map(|target| target.connection_id)
            .collect()
    }
}

#[derive(Clone)]
struct ObservedSelection {
    scope: ManagedChatgptSelectionScope,
    selected_account_id: Option<String>,
    selection_revision: u64,
    lifecycle_generation: u64,
    routes: Vec<SelectionNotificationRoute>,
}

struct EventRouteInvalidations {
    thread_id: String,
    connection_ids: std::sync::Mutex<HashSet<ConnectionId>>,
}

struct AccountSelectionObserverState {
    next_generation: u64,
    observed_selections: HashMap<String, ObservedSelection>,
    lifecycle_generations: HashMap<String, u64>,
    route_generations: HashMap<(String, ConnectionId), u64>,
    connection_generations: HashMap<ConnectionId, u64>,
    event_registrations: Vec<std::sync::Weak<EventRouteInvalidations>>,
}

impl Default for AccountSelectionObserverState {
    fn default() -> Self {
        Self {
            next_generation: 1,
            observed_selections: HashMap::new(),
            lifecycle_generations: HashMap::new(),
            route_generations: HashMap::new(),
            connection_generations: HashMap::new(),
            event_registrations: Vec::new(),
        }
    }
}

impl AccountSelectionObserverState {
    fn allocate_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        assert_ne!(
            generation,
            u64::MAX,
            "account selection observer generation exhausted"
        );
        self.next_generation += 1;
        generation
    }

    fn invalidate_event_routes(&mut self, thread_id: Option<&str>, connection_id: ConnectionId) {
        self.event_registrations.retain(|registration| {
            let Some(registration) = registration.upgrade() else {
                return false;
            };
            if thread_id.is_none_or(|thread_id| registration.thread_id == thread_id) {
                registration
                    .connection_ids
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(connection_id);
            }
            true
        });
    }
}

#[derive(Clone)]
struct AccountSelectionRegistration {
    thread_id: String,
    lifecycle_generation: u64,
    route_generation: Option<(ConnectionId, Option<u64>)>,
    connection_generation: Option<(ConnectionId, Option<u64>)>,
    event_invalidations: Option<Arc<EventRouteInvalidations>>,
}

#[derive(Clone)]
pub(crate) struct AccountSelectionEventObserver {
    observer: AccountSelectionObserver,
    thread_id: String,
    lifecycle_generation: u64,
}

impl AccountSelectionEventObserver {
    pub(crate) async fn capture_event(&self) -> Option<AccountSelectionObserver> {
        let event_registration = self.observer.capture_event_registration(self).await?;
        Some(AccountSelectionObserver {
            state: Arc::clone(&self.observer.state),
            event_registration: Some(event_registration),
        })
    }

    pub(crate) async fn deactivate_if_current(&self) {
        self.observer
            .remove_thread_if_generation(&self.thread_id, self.lifecycle_generation)
            .await;
    }
}

#[derive(Clone)]
pub(crate) struct AccountSelectionObserver {
    state: Arc<Mutex<AccountSelectionObserverState>>,
    event_registration: Option<AccountSelectionRegistration>,
}

impl AccountSelectionObserver {
    pub(crate) async fn notify_if_changed(
        &self,
        scope: ManagedChatgptSelectionScope,
        selected_account_id: String,
        selection_revision: u64,
        outgoing: &ThreadScopedOutgoingMessageSender,
    ) {
        let Some(registration) = self.event_registration.clone() else {
            return;
        };
        let Some((notification, routes)) = self
            .record_if_changed(
                registration,
                scope,
                Some(selected_account_id),
                selection_revision,
                SelectionNotificationRoute::from_thread(outgoing),
            )
            .await
        else {
            return;
        };
        for route in routes {
            route.send(notification.clone()).await;
        }
    }
    pub(crate) async fn activate_thread(&self, thread_id: &str) -> AccountSelectionEventObserver {
        let mut state = self.state.lock().await;
        let lifecycle_generation = state.allocate_generation();
        state
            .lifecycle_generations
            .insert(thread_id.to_string(), lifecycle_generation);
        if let Some(observed) = state.observed_selections.get_mut(thread_id) {
            observed.lifecycle_generation = lifecycle_generation;
        }
        AccountSelectionEventObserver {
            observer: self.clone(),
            thread_id: thread_id.to_string(),
            lifecycle_generation,
        }
    }

    async fn remove_thread_if_generation(&self, thread_id: &str, lifecycle_generation: u64) {
        let mut state = self.state.lock().await;
        if state.lifecycle_generations.get(thread_id).copied() != Some(lifecycle_generation) {
            return;
        }
        if let Some(selection) = state.observed_selections.remove(thread_id) {
            for route in selection.routes {
                route.invalidate();
            }
        }
        state.lifecycle_generations.remove(thread_id);
        state
            .route_generations
            .retain(|(route_thread_id, _), _| route_thread_id != thread_id);
        state.event_registrations.retain(|registration| {
            registration
                .upgrade()
                .is_some_and(|registration| registration.thread_id != thread_id)
        });
    }

    async fn capture_event_registration(
        &self,
        event_observer: &AccountSelectionEventObserver,
    ) -> Option<AccountSelectionRegistration> {
        let mut state = self.state.lock().await;
        let lifecycle_generation = state
            .lifecycle_generations
            .get(&event_observer.thread_id)
            .copied()
            .unwrap_or_default();
        if lifecycle_generation != event_observer.lifecycle_generation {
            return None;
        }
        let event_invalidations = Arc::new(EventRouteInvalidations {
            thread_id: event_observer.thread_id.clone(),
            connection_ids: std::sync::Mutex::new(HashSet::new()),
        });
        state
            .event_registrations
            .retain(|registration| registration.strong_count() > 0);
        state
            .event_registrations
            .push(Arc::downgrade(&event_invalidations));
        Some(AccountSelectionRegistration {
            thread_id: event_observer.thread_id.clone(),
            lifecycle_generation,
            route_generation: None,
            connection_generation: None,
            event_invalidations: Some(event_invalidations),
        })
    }

    async fn capture_list_registration(
        &self,
        thread_id: &str,
        connection_id: ConnectionId,
    ) -> AccountSelectionRegistration {
        let mut state = self.state.lock().await;
        let event_invalidations = Arc::new(EventRouteInvalidations {
            thread_id: thread_id.to_string(),
            connection_ids: std::sync::Mutex::new(HashSet::new()),
        });
        state
            .event_registrations
            .retain(|registration| registration.strong_count() > 0);
        state
            .event_registrations
            .push(Arc::downgrade(&event_invalidations));
        AccountSelectionRegistration {
            thread_id: thread_id.to_string(),
            lifecycle_generation: state
                .lifecycle_generations
                .get(thread_id)
                .copied()
                .unwrap_or_default(),
            route_generation: Some((
                connection_id,
                state
                    .route_generations
                    .get(&(thread_id.to_string(), connection_id))
                    .copied(),
            )),
            connection_generation: Some((
                connection_id,
                state.connection_generations.get(&connection_id).copied(),
            )),
            event_invalidations: Some(event_invalidations),
        }
    }

    fn registration_is_current(
        state: &AccountSelectionObserverState,
        registration: &AccountSelectionRegistration,
    ) -> bool {
        state
            .lifecycle_generations
            .get(&registration.thread_id)
            .copied()
            == Some(registration.lifecycle_generation)
            && !registration
                .route_generation
                .as_ref()
                .is_some_and(|(connection_id, generation)| {
                    state
                        .route_generations
                        .get(&(registration.thread_id.clone(), *connection_id))
                        .copied()
                        != *generation
                })
            && !registration.connection_generation.as_ref().is_some_and(
                |(connection_id, generation)| {
                    state.connection_generations.get(connection_id).copied() != *generation
                },
            )
    }
    fn activate_list_route(
        state: &mut AccountSelectionObserverState,
        registration: &AccountSelectionRegistration,
    ) {
        if let Some((connection_id, None)) = registration.route_generation {
            let generation = state.allocate_generation();
            state
                .route_generations
                .insert((registration.thread_id.clone(), connection_id), generation);
        }
        if let Some((connection_id, None)) = registration.connection_generation {
            let generation = state.allocate_generation();
            state
                .connection_generations
                .insert(connection_id, generation);
        }
    }

    fn filter_event_route(
        registration: &AccountSelectionRegistration,
        route: &mut SelectionNotificationRoute,
    ) {
        let Some(invalidations) = registration.event_invalidations.as_ref() else {
            return;
        };
        let invalidated = invalidations
            .connection_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let targets = Arc::make_mut(&mut route.targets);
        for target in targets
            .iter()
            .filter(|target| invalidated.contains(&target.connection_id))
        {
            target.validity.cancel();
        }
        targets.retain(|target| !invalidated.contains(&target.connection_id));
    }

    fn merge_route(
        routes: &mut Vec<SelectionNotificationRoute>,
        route: SelectionNotificationRoute,
    ) -> SelectionNotificationRoute {
        if let Some(known) = routes.iter_mut().find(|known| known.same_sender(&route)) {
            known.merge(route)
        } else {
            routes.push(route.clone());
            route
        }
    }

    async fn record_list_response(
        &self,
        registration: AccountSelectionRegistration,
        scope: ManagedChatgptSelectionScope,
        selected_account_id: Option<String>,
        selection_revision: u64,
        mut route: SelectionNotificationRoute,
    ) -> Option<(
        AccountSelectionUpdatedNotification,
        Vec<SelectionNotificationRoute>,
    )> {
        let thread_id = scope.thread_id.clone()?;
        if thread_id != registration.thread_id {
            return None;
        }
        let mut state = self.state.lock().await;
        if !Self::registration_is_current(&state, &registration) {
            return None;
        }
        Self::filter_event_route(&registration, &mut route);
        if route.is_empty() {
            return None;
        }
        Self::activate_list_route(&mut state, &registration);
        if let Some(previous) = state.observed_selections.get_mut(&thread_id) {
            if selection_revision < previous.selection_revision {
                let catch_up = AccountSelectionUpdatedNotification {
                    thread_id,
                    selected_account_id: previous.selected_account_id.clone(),
                    selection_revision: previous.selection_revision,
                };
                let route = Self::merge_route(&mut previous.routes, route);
                return Some((catch_up, vec![route]));
            }
            if selection_revision == previous.selection_revision {
                Self::merge_route(&mut previous.routes, route);
                return None;
            }
            Self::merge_route(&mut previous.routes, route);
            let routes = previous.routes.clone();
            state.observed_selections.insert(
                thread_id.clone(),
                ObservedSelection {
                    scope,
                    selected_account_id: selected_account_id.clone(),
                    selection_revision,
                    lifecycle_generation: registration.lifecycle_generation,
                    routes: routes.clone(),
                },
            );
            return Some((
                AccountSelectionUpdatedNotification {
                    thread_id,
                    selected_account_id,
                    selection_revision,
                },
                routes,
            ));
        }
        state.observed_selections.insert(
            thread_id.clone(),
            ObservedSelection {
                scope,
                selected_account_id: selected_account_id.clone(),
                selection_revision,
                lifecycle_generation: registration.lifecycle_generation,
                routes: vec![route.clone()],
            },
        );
        Some((
            AccountSelectionUpdatedNotification {
                thread_id,
                selected_account_id,
                selection_revision,
            },
            vec![route],
        ))
    }

    async fn record_if_changed(
        &self,
        registration: AccountSelectionRegistration,
        scope: ManagedChatgptSelectionScope,
        selected_account_id: Option<String>,
        selection_revision: u64,
        mut route: SelectionNotificationRoute,
    ) -> Option<(
        AccountSelectionUpdatedNotification,
        Vec<SelectionNotificationRoute>,
    )> {
        let thread_id = scope.thread_id.clone()?;
        if thread_id != registration.thread_id {
            return None;
        }
        let mut state = self.state.lock().await;
        if !Self::registration_is_current(&state, &registration) {
            return None;
        }
        Self::filter_event_route(&registration, &mut route);
        if route.is_empty() {
            return None;
        }
        let routes = if let Some(previous) = state.observed_selections.get_mut(&thread_id) {
            if selection_revision <= previous.selection_revision {
                return None;
            }
            Self::merge_route(&mut previous.routes, route);
            previous.routes.clone()
        } else {
            vec![route]
        };
        state.observed_selections.insert(
            thread_id.clone(),
            ObservedSelection {
                scope,
                selected_account_id: selected_account_id.clone(),
                selection_revision,
                lifecycle_generation: registration.lifecycle_generation,
                routes: routes.clone(),
            },
        );
        Some((
            AccountSelectionUpdatedNotification {
                thread_id,
                selected_account_id,
                selection_revision,
            },
            routes,
        ))
    }

    pub(crate) async fn remove_connection(&self, connection_id: ConnectionId) {
        let mut state = self.state.lock().await;
        state.invalidate_event_routes(None, connection_id);
        state.connection_generations.remove(&connection_id);
        state
            .route_generations
            .retain(|(_, route_connection_id), _| *route_connection_id != connection_id);
        for selection in state.observed_selections.values_mut() {
            for route in &mut selection.routes {
                route.remove_connection(connection_id);
            }
            selection.routes.retain(|route| !route.is_empty());
        }
    }

    pub(crate) async fn remove_connection_from_thread(
        &self,
        thread_id: &str,
        connection_id: ConnectionId,
    ) {
        let mut state = self.state.lock().await;
        state.invalidate_event_routes(Some(thread_id), connection_id);
        state
            .route_generations
            .remove(&(thread_id.to_string(), connection_id));
        if let Some(selection) = state.observed_selections.get_mut(thread_id) {
            for route in &mut selection.routes {
                route.remove_connection(connection_id);
            }
            selection.routes.retain(|route| !route.is_empty());
        }
    }

    pub(crate) async fn remove_thread(&self, thread_id: &str) {
        let mut state = self.state.lock().await;
        if let Some(selection) = state.observed_selections.remove(thread_id) {
            for route in selection.routes {
                route.invalidate();
            }
        }
        state.lifecycle_generations.remove(thread_id);
        state
            .route_generations
            .retain(|(route_thread_id, _), _| route_thread_id != thread_id);
        state.event_registrations.retain(|registration| {
            registration
                .upgrade()
                .is_some_and(|registration| registration.thread_id != thread_id)
        });
    }

    async fn update_if_current(
        &self,
        previous: &ObservedSelection,
        selected_account_id: Option<String>,
        selection_revision: u64,
    ) -> Vec<SelectionNotificationRoute> {
        let Some(thread_id) = previous.scope.thread_id.as_deref() else {
            return Vec::new();
        };
        let mut state = self.state.lock().await;
        let Some(current) = state.observed_selections.get_mut(thread_id) else {
            return Vec::new();
        };
        if current.scope != previous.scope
            || current.selection_revision != previous.selection_revision
            || current.lifecycle_generation != previous.lifecycle_generation
        {
            return Vec::new();
        }
        current.selected_account_id = selected_account_id;
        current.selection_revision = selection_revision;
        current.routes.clone()
    }

    #[cfg(test)]
    pub(crate) fn for_test(_outgoing: Arc<OutgoingMessageSender>) -> Self {
        Self {
            state: Arc::new(Mutex::new(AccountSelectionObserverState::default())),
            event_registration: None,
        }
    }

    #[cfg(test)]
    pub(crate) async fn observed_scope_for_test(
        &self,
        thread_id: &str,
    ) -> Option<ManagedChatgptSelectionScope> {
        self.state
            .lock()
            .await
            .observed_selections
            .get(thread_id)
            .map(|observed| observed.scope.clone())
    }
}

struct PoolUpdateWatcherShutdown(CancellationToken);

impl PoolUpdateWatcherShutdown {
    fn cancel(&self) {
        self.0.cancel();
    }
}

impl Drop for PoolUpdateWatcherShutdown {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[derive(Clone)]
pub(crate) struct AccountRequestProcessor {
    auth_manager: Arc<AuthManager>,
    thread_manager: Arc<ThreadManager>,
    thread_state_manager: ThreadStateManager,
    outgoing: Arc<OutgoingMessageSender>,
    config: Arc<Config>,
    config_manager: ConfigManager,
    active_login: Arc<Mutex<Option<ActiveLogin>>>,
    selection_observer_state: Arc<Mutex<AccountSelectionObserverState>>,
    pool_update_shutdown: Arc<PoolUpdateWatcherShutdown>,
}

impl AccountRequestProcessor {
    pub(crate) fn new(
        auth_manager: Arc<AuthManager>,
        thread_manager: Arc<ThreadManager>,
        thread_state_manager: ThreadStateManager,
        outgoing: Arc<OutgoingMessageSender>,
        config: Arc<Config>,
        config_manager: ConfigManager,
    ) -> Self {
        let pool_update_shutdown = CancellationToken::new();
        let selection_observer_state =
            Arc::new(Mutex::new(AccountSelectionObserverState::default()));
        let mut revisions = auth_manager.auth_change_receiver();
        let subscriber_auth_manager = Arc::clone(&auth_manager);
        let subscriber_outgoing = Arc::clone(&outgoing);
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
                        let response = Self::list_accounts_response_from_owner(
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
        Self {
            auth_manager,
            thread_manager,
            thread_state_manager,
            outgoing,
            config,
            config_manager,
            active_login: Arc::new(Mutex::new(None)),
            selection_observer_state,
            pool_update_shutdown: Arc::new(PoolUpdateWatcherShutdown(pool_update_shutdown)),
        }
    }

    pub(crate) fn selection_observer(&self) -> AccountSelectionObserver {
        AccountSelectionObserver {
            state: Arc::clone(&self.selection_observer_state),
            event_registration: None,
        }
    }

    pub(crate) async fn login_account(
        &self,
        request_id: ConnectionRequestId,
        params: LoginAccountParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.login_v2(request_id, params).await.map(|()| None)
    }

    pub(crate) async fn list_accounts(
        &self,
        request_id: ConnectionRequestId,
        params: ListAccountsParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        let scope = self.selection_scope_for_list(&params).await;
        let selection_scope = params.thread_id.is_some().then(|| scope.clone());
        let list_registration = match selection_scope
            .as_ref()
            .and_then(|scope| scope.thread_id.as_deref())
        {
            Some(thread_id) => Some(
                self.selection_observer()
                    .capture_list_registration(thread_id, request_id.connection_id)
                    .await,
            ),
            None => None,
        };
        let connection_id = request_id.connection_id;
        let result = self.list_accounts_response(params, scope).await;
        let selection_result = result.as_ref().ok().and_then(|response| {
            response.selection_revision.map(|selection_revision| {
                (response.selected_account_id.clone(), selection_revision)
            })
        });
        self.outgoing.send_result(request_id, result).await;

        let is_still_subscribed = match selection_scope
            .as_ref()
            .and_then(|scope| scope.thread_id.as_deref())
            .and_then(|thread_id| ThreadId::from_string(thread_id).ok())
        {
            Some(thread_id) => self
                .thread_state_manager
                .subscribed_connection_ids(thread_id)
                .await
                .contains(&connection_id),
            None => false,
        };
        let selection_update = match (list_registration, selection_scope, selection_result) {
            (Some(registration), Some(scope), Some((selected_account_id, selection_revision)))
                if is_still_subscribed =>
            {
                self.selection_observer()
                    .record_list_response(
                        registration,
                        scope,
                        selected_account_id,
                        selection_revision,
                        SelectionNotificationRoute::for_connection(
                            Arc::clone(&self.outgoing),
                            connection_id,
                        ),
                    )
                    .await
            }
            _ => None,
        };
        if let Some((selection_update, routes)) = selection_update {
            for route in routes {
                route.send(selection_update.clone()).await;
            }
        }
        Ok(None)
    }

    pub(crate) async fn logout_account(
        &self,
        request_id: ConnectionRequestId,
        params: Option<LogoutAccountParams>,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.logout_v2(request_id, params).await.map(|()| None)
    }

    pub(crate) async fn cancel_login_account(
        &self,
        params: CancelLoginAccountParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.cancel_login_response(params)
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn get_account(
        &self,
        params: GetAccountParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.get_account_response(params)
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn get_auth_status(
        &self,
        params: GetAuthStatusParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.get_auth_status_response(params)
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn get_account_rate_limits(
        &self,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.get_account_rate_limits_response()
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn get_account_token_usage(
        &self,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.get_account_token_usage_response()
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn get_workspace_messages(
        &self,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.get_workspace_messages_response()
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn send_add_credits_nudge_email(
        &self,
        params: SendAddCreditsNudgeEmailParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.send_add_credits_nudge_email_response(params)
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn cancel_active_login(&self) {
        let mut guard = self.active_login.lock().await;
        if let Some(active_login) = guard.take() {
            drop(active_login);
        }
    }

    pub(crate) fn clear_external_auth(&self) {
        self.pool_update_shutdown.cancel();
        self.auth_manager.clear_external_auth();
        self.thread_manager
            .plugins_manager()
            .set_auth_mode(self.auth_manager.get_api_auth_mode());
    }

    fn current_account_updated_notification(&self) -> AccountUpdatedNotification {
        let auth = self.auth_manager.auth_cached();
        AccountUpdatedNotification {
            auth_mode: auth
                .as_ref()
                .map(CodexAuth::api_auth_mode)
                .map(auth_mode_to_api),
            plan_type: auth.as_ref().and_then(CodexAuth::account_plan_type),
        }
    }

    async fn load_latest_config(&self) -> Config {
        match self
            .config_manager
            .load_latest_config(/*fallback_cwd*/ None)
            .await
        {
            Ok(config) => config,
            Err(err) => {
                tracing::warn!("failed to reload config, using startup config: {err}");
                self.config.as_ref().clone()
            }
        }
    }

    async fn maybe_refresh_plugin_caches_for_current_config(
        config_manager: &ConfigManager,
        thread_manager: &Arc<ThreadManager>,
        auth: Option<CodexAuth>,
    ) {
        thread_manager
            .plugins_manager()
            .set_auth_mode(auth.as_ref().map(CodexAuth::api_auth_mode));
        thread_manager
            .plugins_manager()
            .clear_recommended_plugins_cache();

        match config_manager
            .load_latest_config(/*fallback_cwd*/ None)
            .await
        {
            Ok(config) => {
                Self::spawn_effective_plugins_changed_task(
                    Arc::clone(thread_manager),
                    config_manager.clone(),
                );
                let refresh_thread_manager = Arc::clone(thread_manager);
                let refresh_config_manager = config_manager.clone();
                thread_manager
                    .plugins_manager()
                    .maybe_start_remote_plugin_caches_refresh(
                        &config.plugins_config_input(),
                        auth,
                        Some(Arc::new(move |_change| {
                            Self::spawn_effective_plugins_changed_task(
                                Arc::clone(&refresh_thread_manager),
                                refresh_config_manager.clone(),
                            );
                        })),
                    );
            }
            Err(err) => {
                warn!(
                    "failed to reload config after account changed, skipping remote installed plugins cache refresh: {err}"
                );
            }
        }
    }

    fn spawn_effective_plugins_changed_task(
        thread_manager: Arc<ThreadManager>,
        config_manager: ConfigManager,
    ) {
        tokio::spawn(async move {
            thread_manager.plugins_manager().clear_cache();
            thread_manager.skills_service().clear_cache();
            crate::mcp_refresh::reload_mcp_config_best_effort(&thread_manager, &config_manager)
                .await;
            thread_manager.invalidate_mcp_runtimes().await;
        });
    }

    async fn login_v2(
        &self,
        request_id: ConnectionRequestId,
        params: LoginAccountParams,
    ) -> Result<(), JSONRPCErrorError> {
        match params {
            LoginAccountParams::ApiKey { api_key } => {
                self.login_api_key_v2(request_id, LoginApiKeyParams { api_key })
                    .await;
            }
            LoginAccountParams::Chatgpt {
                app_brand,
                codex_streamlined_login,
                use_hosted_login_success_page,
            } => {
                let login_success_page = if use_hosted_login_success_page {
                    let app_brand = match app_brand.unwrap_or_default() {
                        LoginAppBrand::Codex => LoginSuccessPageBrand::Codex,
                        LoginAppBrand::Chatgpt => LoginSuccessPageBrand::Chatgpt,
                    };
                    LoginSuccessPage::Hosted {
                        url: CODEX_OPEN_APP_URL.parse().map_err(|err| {
                            internal_error(format!("invalid Codex open app URL: {err}"))
                        })?,
                        app_brand,
                    }
                } else {
                    LoginSuccessPage::default()
                };
                self.login_chatgpt_v2(request_id, codex_streamlined_login, login_success_page)
                    .await;
            }
            LoginAccountParams::ChatgptDeviceCode => {
                self.login_chatgpt_device_code_v2(request_id).await;
            }
            LoginAccountParams::ChatgptAuthTokens {
                access_token,
                chatgpt_account_id,
                chatgpt_plan_type,
            } => {
                self.login_chatgpt_auth_tokens(
                    request_id,
                    access_token,
                    chatgpt_account_id,
                    chatgpt_plan_type,
                )
                .await;
            }
            LoginAccountParams::AmazonBedrock { api_key, region } => {
                self.login_amazon_bedrock_v2(request_id, api_key, region)
                    .await;
            }
        }
        Ok(())
    }

    fn external_auth_active_error(&self) -> JSONRPCErrorError {
        invalid_request(
            "External auth is active. Use account/login/start (chatgptAuthTokens) to update it or account/logout to clear it.",
        )
    }

    async fn login_api_key_common(
        &self,
        params: &LoginApiKeyParams,
    ) -> std::result::Result<(), JSONRPCErrorError> {
        if self.auth_manager.is_external_chatgpt_auth_active() {
            return Err(self.external_auth_active_error());
        }

        if matches!(
            self.config.forced_login_method,
            Some(ForcedLoginMethod::Chatgpt)
        ) {
            return Err(invalid_request(
                "API key login is disabled. Use ChatGPT login instead.",
            ));
        }

        // Cancel any active login attempt.
        {
            let mut guard = self.active_login.lock().await;
            if let Some(active) = guard.take() {
                drop(active);
            }
        }

        match login_with_api_key(
            &self.config.codex_home,
            &params.api_key,
            self.config.cli_auth_credentials_store_mode,
            self.config.auth_keyring_backend_kind(),
        ) {
            Ok(()) => {
                self.auth_manager.reload().await;
                Ok(())
            }
            Err(err) => Err(internal_error(format!("failed to save api key: {err}"))),
        }
    }

    async fn login_api_key_v2(&self, request_id: ConnectionRequestId, params: LoginApiKeyParams) {
        let result = self
            .login_api_key_common(&params)
            .await
            .map(|()| LoginAccountResponse::ApiKey {});
        let logged_in = result.is_ok();
        self.outgoing.send_result(request_id, result).await;

        if logged_in {
            self.send_login_success_notifications(/*login_id*/ None)
                .await;
        }
    }

    async fn login_amazon_bedrock_v2(
        &self,
        request_id: ConnectionRequestId,
        api_key: String,
        region: String,
    ) {
        let result = async {
            if self.auth_manager.is_external_chatgpt_auth_active() {
                return Err(self.external_auth_active_error());
            }
            if matches!(
                self.config.forced_login_method,
                Some(ForcedLoginMethod::Chatgpt)
            ) {
                return Err(invalid_request(
                    "Amazon Bedrock login is disabled. Use ChatGPT login instead.",
                ));
            }

            let api_key = api_key.trim();
            if api_key.is_empty() {
                return Err(invalid_request("Amazon Bedrock API key must not be empty."));
            }
            let region = region.trim();
            if !is_supported_amazon_bedrock_region(region) {
                return Err(invalid_request(format!(
                    "Amazon Bedrock Mantle does not support region `{region}`"
                )));
            }

            {
                let mut guard = self.active_login.lock().await;
                if let Some(active) = guard.take() {
                    drop(active);
                }
            }

            set_user_model_provider_to_bedrock(&self.config_manager).await?;
            login_with_bedrock_api_key(
                &self.config.codex_home,
                api_key,
                region,
                self.config.cli_auth_credentials_store_mode,
                self.config.auth_keyring_backend_kind(),
            )
            .map_err(|err| internal_error(format!("failed to save Amazon Bedrock auth: {err}")))?;
            self.auth_manager.reload().await;
            Ok(LoginAccountResponse::AmazonBedrock {})
        }
        .await;
        let logged_in = result.is_ok();
        self.outgoing.send_result(request_id, result).await;

        if logged_in {
            self.send_login_success_notifications(/*login_id*/ None)
                .await;
        }
    }

    // Build options for a ChatGPT login attempt; performs validation.
    async fn login_chatgpt_common(
        &self,
        codex_streamlined_login: bool,
        login_success_page: LoginSuccessPage,
    ) -> std::result::Result<LoginServerOptions, JSONRPCErrorError> {
        let config = self.config.as_ref();

        if self.auth_manager.is_external_chatgpt_auth_active() {
            return Err(self.external_auth_active_error());
        }

        if matches!(config.forced_login_method, Some(ForcedLoginMethod::Api)) {
            return Err(invalid_request(
                "ChatGPT login is disabled. Use API key login instead.",
            ));
        }

        let opts = LoginServerOptions {
            open_browser: false,
            codex_streamlined_login,
            login_success_page,
            ..LoginServerOptions::new(
                config.codex_home.to_path_buf(),
                oauth_client_id(),
                config.forced_chatgpt_workspace_id.clone(),
                config.cli_auth_credentials_store_mode,
                config.auth_keyring_backend_kind(),
                config.auth_route_config(),
            )
        };
        #[cfg(debug_assertions)]
        let opts = {
            let mut opts = opts;
            if let Ok(issuer) = std::env::var(LOGIN_ISSUER_OVERRIDE_ENV_VAR)
                && !issuer.trim().is_empty()
            {
                opts.issuer = issuer;
            }
            if let LoginSuccessPage::Hosted { url, .. } = &mut opts.login_success_page
                && let Ok(open_app_url) = std::env::var(LOGIN_OPEN_APP_URL_OVERRIDE_ENV_VAR)
                && !open_app_url.trim().is_empty()
            {
                *url = open_app_url
                    .parse()
                    .map_err(|err| internal_error(format!("invalid Codex open app URL: {err}")))?;
            }
            opts
        };

        Ok(opts)
    }

    fn login_chatgpt_device_code_start_error(err: IoError) -> JSONRPCErrorError {
        let is_not_found = err.kind() == std::io::ErrorKind::NotFound;
        if is_not_found {
            invalid_request(err.to_string())
        } else {
            internal_error(format!("failed to request device code: {err}"))
        }
    }

    async fn login_chatgpt_v2(
        &self,
        request_id: ConnectionRequestId,
        codex_streamlined_login: bool,
        login_success_page: LoginSuccessPage,
    ) {
        let result = self
            .login_chatgpt_response(codex_streamlined_login, login_success_page)
            .await;
        self.outgoing.send_result(request_id, result).await;
    }

    async fn login_chatgpt_response(
        &self,
        codex_streamlined_login: bool,
        login_success_page: LoginSuccessPage,
    ) -> Result<LoginAccountResponse, JSONRPCErrorError> {
        let opts = self
            .login_chatgpt_common(codex_streamlined_login, login_success_page)
            .await?;
        let server = run_login_server(opts)
            .map_err(|err| internal_error(format!("failed to start login server: {err}")))?;
        let login_id = Uuid::new_v4();
        let shutdown_handle = server.cancel_handle();

        // Replace active login if present.
        {
            let mut guard = self.active_login.lock().await;
            if let Some(existing) = guard.take() {
                drop(existing);
            }
            *guard = Some(ActiveLogin::Browser {
                shutdown_handle: shutdown_handle.clone(),
                login_id,
            });
        }

        let outgoing_clone = self.outgoing.clone();
        let config_manager = self.config_manager.clone();
        let thread_manager = Arc::clone(&self.thread_manager);
        let config = Arc::clone(&self.config);
        let active_login = self.active_login.clone();
        let auth_url = server.auth_url.clone();
        tokio::spawn(async move {
            let (success, error_msg, managed_account_id) = match tokio::time::timeout(
                LOGIN_CHATGPT_TIMEOUT,
                server.block_until_done(),
            )
            .await
            {
                Ok(Ok(managed_account_id)) => (true, None, Some(managed_account_id)),
                Ok(Err(err)) => (false, Some(format!("Login server error: {err}")), None),
                Err(_elapsed) => {
                    shutdown_handle.shutdown();
                    (false, Some("Login timed out".to_string()), None)
                }
            };

            Self::send_chatgpt_login_completion_notifications(
                &outgoing_clone,
                config_manager,
                thread_manager,
                config,
                login_id,
                success,
                error_msg,
                managed_account_id,
            )
            .await;

            // Clear the active login if it matches this attempt. It may have been replaced or cancelled.
            let mut guard = active_login.lock().await;
            if guard.as_ref().map(ActiveLogin::login_id) == Some(login_id) {
                *guard = None;
            }
        });

        Ok(LoginAccountResponse::Chatgpt {
            login_id: login_id.to_string(),
            auth_url,
        })
    }

    async fn login_chatgpt_device_code_v2(&self, request_id: ConnectionRequestId) {
        let result = self.login_chatgpt_device_code_response().await;
        self.outgoing.send_result(request_id, result).await;
    }

    async fn login_chatgpt_device_code_response(
        &self,
    ) -> Result<LoginAccountResponse, JSONRPCErrorError> {
        let opts = self
            .login_chatgpt_common(
                /*codex_streamlined_login*/ false,
                LoginSuccessPage::default(),
            )
            .await?;
        let device_code = request_device_code(&opts)
            .await
            .map_err(Self::login_chatgpt_device_code_start_error)?;
        let login_id = Uuid::new_v4();
        let cancel = CancellationToken::new();

        {
            let mut guard = self.active_login.lock().await;
            if let Some(existing) = guard.take() {
                drop(existing);
            }
            *guard = Some(ActiveLogin::DeviceCode {
                cancel: cancel.clone(),
                login_id,
            });
        }

        let verification_url = device_code.verification_url.clone();
        let user_code = device_code.user_code.clone();

        let outgoing_clone = self.outgoing.clone();
        let config_manager = self.config_manager.clone();
        let thread_manager = Arc::clone(&self.thread_manager);
        let config = Arc::clone(&self.config);
        let active_login = self.active_login.clone();
        tokio::spawn(async move {
            let (success, error_msg, managed_account_id) = tokio::select! {
                _ = cancel.cancelled() => {
                    (false, Some("Login was not completed".to_string()), None)
                }
                r = complete_device_code_login(opts, device_code) => {
                    match r {
                        Ok(managed_account_id) => (true, None, Some(managed_account_id)),
                        Err(err) => (false, Some(err.to_string()), None),
                    }
                }
            };

            Self::send_chatgpt_login_completion_notifications(
                &outgoing_clone,
                config_manager,
                thread_manager,
                config,
                login_id,
                success,
                error_msg,
                managed_account_id,
            )
            .await;

            let mut guard = active_login.lock().await;
            if guard.as_ref().map(ActiveLogin::login_id) == Some(login_id) {
                *guard = None;
            }
        });

        Ok(LoginAccountResponse::ChatgptDeviceCode {
            login_id: login_id.to_string(),
            verification_url,
            user_code,
        })
    }

    async fn cancel_login_chatgpt_common(
        &self,
        login_id: Uuid,
    ) -> std::result::Result<(), CancelLoginError> {
        let mut guard = self.active_login.lock().await;
        if guard.as_ref().map(ActiveLogin::login_id) == Some(login_id) {
            if let Some(active) = guard.take() {
                drop(active);
            }
            Ok(())
        } else {
            Err(CancelLoginError::NotFound)
        }
    }

    async fn cancel_login_response(
        &self,
        params: CancelLoginAccountParams,
    ) -> Result<CancelLoginAccountResponse, JSONRPCErrorError> {
        let login_id = params.login_id;
        let uuid = Uuid::parse_str(&login_id)
            .map_err(|_| invalid_request(format!("invalid login id: {login_id}")))?;
        let status = match self.cancel_login_chatgpt_common(uuid).await {
            Ok(()) => CancelLoginAccountStatus::Canceled,
            Err(CancelLoginError::NotFound) => CancelLoginAccountStatus::NotFound,
        };
        Ok(CancelLoginAccountResponse { status })
    }

    async fn login_chatgpt_auth_tokens(
        &self,
        request_id: ConnectionRequestId,
        access_token: String,
        chatgpt_account_id: String,
        chatgpt_plan_type: Option<String>,
    ) {
        let result = self
            .login_chatgpt_auth_tokens_response(access_token, chatgpt_account_id, chatgpt_plan_type)
            .await;
        let logged_in = result.is_ok();
        self.outgoing.send_result(request_id, result).await;

        if logged_in {
            self.send_login_success_notifications(/*login_id*/ None)
                .await;
        }
    }

    async fn login_chatgpt_auth_tokens_response(
        &self,
        access_token: String,
        chatgpt_account_id: String,
        chatgpt_plan_type: Option<String>,
    ) -> Result<LoginAccountResponse, JSONRPCErrorError> {
        if matches!(
            self.config.forced_login_method,
            Some(ForcedLoginMethod::Api)
        ) {
            return Err(invalid_request(
                "External ChatGPT auth is disabled. Use API key login instead.",
            ));
        }

        // Cancel any active login attempt to avoid persisting managed auth state.
        {
            let mut guard = self.active_login.lock().await;
            if let Some(active) = guard.take() {
                drop(active);
            }
        }

        if let Some(expected_workspaces) = self.config.forced_chatgpt_workspace_id.as_deref()
            && !expected_workspaces.contains(&chatgpt_account_id)
        {
            return Err(invalid_request(format!(
                "External auth must use one of workspace(s) {expected_workspaces:?}, but received {chatgpt_account_id:?}.",
            )));
        }

        let auth = CodexAuth::from_external_chatgpt_tokens(
            &access_token,
            &chatgpt_account_id,
            chatgpt_plan_type.as_deref(),
        )
        .map_err(|err| internal_error(format!("failed to set external auth: {err}")))?;
        self.auth_manager
            .set_external_auth(Arc::new(ExternalAuthBridge::new(
                Arc::clone(&self.outgoing),
                auth,
            )))
            .await
            .map_err(|err| internal_error(format!("failed to set external auth: {err}")))?;
        self.config_manager.replace_cloud_config_bundle_loader(
            self.auth_manager.clone(),
            self.config.chatgpt_base_url.clone(),
            self.config.http_client_factory(),
        );
        self.config_manager
            .sync_default_client_residency_requirement()
            .await;

        Ok(LoginAccountResponse::ChatgptAuthTokens {})
    }

    async fn send_login_success_notifications(&self, login_id: Option<Uuid>) {
        Self::maybe_refresh_plugin_caches_for_current_config(
            &self.config_manager,
            &self.thread_manager,
            self.auth_manager.auth_cached(),
        )
        .await;

        let payload_login_completed = AccountLoginCompletedNotification {
            login_id: login_id.map(|id| id.to_string()),
            success: true,
            error: None,
            managed_account_id: None,
        };
        self.outgoing
            .send_server_notification(ServerNotification::AccountLoginCompleted(
                payload_login_completed,
            ))
            .await;

        self.outgoing
            .send_server_notification(ServerNotification::AccountUpdated(
                self.current_account_updated_notification(),
            ))
            .await;
    }

    async fn send_chatgpt_login_completion_notifications(
        outgoing: &OutgoingMessageSender,
        config_manager: ConfigManager,
        thread_manager: Arc<ThreadManager>,
        config: Arc<Config>,
        login_id: Uuid,
        success: bool,
        error_msg: Option<String>,
        managed_account_id: Option<String>,
    ) {
        let payload_v2 = AccountLoginCompletedNotification {
            login_id: Some(login_id.to_string()),
            success,
            error: error_msg,
            managed_account_id,
        };
        outgoing
            .send_server_notification(ServerNotification::AccountLoginCompleted(payload_v2))
            .await;

        if success {
            let auth_manager = thread_manager.auth_manager();
            auth_manager.reload().await;
            config_manager.replace_cloud_config_bundle_loader(
                auth_manager.clone(),
                config.chatgpt_base_url.clone(),
                config.http_client_factory(),
            );
            config_manager
                .sync_default_client_residency_requirement()
                .await;

            let auth = auth_manager.auth_cached();
            Self::maybe_refresh_plugin_caches_for_current_config(
                &config_manager,
                &thread_manager,
                auth.clone(),
            )
            .await;
            let payload_v2 = AccountUpdatedNotification {
                auth_mode: auth
                    .as_ref()
                    .map(CodexAuth::api_auth_mode)
                    .map(auth_mode_to_api),
                plan_type: auth.as_ref().and_then(CodexAuth::account_plan_type),
            };
            outgoing
                .send_server_notification(ServerNotification::AccountUpdated(payload_v2))
                .await;
        }
    }

    async fn logout_common(
        &self,
        params: Option<LogoutAccountParams>,
    ) -> Result<LogoutAccountResponse, JSONRPCErrorError> {
        let managed_bedrock_auth = matches!(
            self.auth_manager.auth_cached(),
            Some(CodexAuth::BedrockApiKey(_))
        );
        let config = self.load_latest_config().await;
        if config.model_provider.is_amazon_bedrock() && !managed_bedrock_auth {
            return Err(invalid_request(
                "cannot log out while Amazon Bedrock is using AWS-managed credentials; manage those credentials through AWS or switch model providers before logging out Codex authentication",
            ));
        }

        if params
            .as_ref()
            .is_some_and(|params| params.all && params.account_id.is_some())
        {
            return Err(invalid_request(
                "account/logout accepts either accountId or all, not both",
            ));
        }

        if params
            .as_ref()
            .is_none_or(|params| params.account_id.is_none())
        {
            let mut guard = self.active_login.lock().await;
            if let Some(active) = guard.take() {
                drop(active);
            }
        }

        let listed_accounts = match params.as_ref() {
            Some(LogoutAccountParams {
                account_id: Some(_),
                all: false,
            }) => Some(
                self.auth_manager
                    .stored_managed_chatgpt_account_list()
                    .map_err(|err| internal_error(format!("logout failed: {err}")))?
                    .accounts,
            ),
            Some(LogoutAccountParams {
                account_id: None,
                all: false,
            })
            | None
                if !self.auth_manager.is_external_chatgpt_auth_active() =>
            {
                Some(
                    self.auth_manager
                        .list_managed_chatgpt_accounts(&ManagedChatgptSelectionScope::default())
                        .await
                        .map_err(|err| internal_error(format!("logout failed: {err}")))?
                        .accounts,
                )
            }
            _ => None,
        };

        let mut removed_account_ids = Vec::new();
        match params {
            Some(LogoutAccountParams {
                account_id: Some(account_id),
                all: false,
            }) => {
                let selector = account_id.trim();
                let normalized_selector = selector.to_lowercase();
                let canonical_id = listed_accounts
                    .as_ref()
                    .expect("managed account list loaded for targeted logout")
                    .iter()
                    .find(|account| {
                        account.identity_key.trim() == selector
                            || account
                                .identity_aliases
                                .iter()
                                .any(|alias| alias.trim() == selector)
                            || account.chatgpt_account_id.as_deref().map(str::trim)
                                == Some(selector)
                            || account.normalized_email.as_deref()
                                == Some(normalized_selector.as_str())
                    })
                    .map(|account| account.identity_key.clone())
                    .unwrap_or_else(|| selector.to_string());
                if self
                    .auth_manager
                    .remove_managed_chatgpt_account(selector)
                    .await
                    .map_err(|err| internal_error(format!("logout failed: {err}")))?
                {
                    removed_account_ids.push(canonical_id);
                }
            }
            Some(LogoutAccountParams {
                account_id: None,
                all: true,
            }) => {
                removed_account_ids = self
                    .auth_manager
                    .logout_all_managed_chatgpt()
                    .await
                    .map_err(|err| internal_error(format!("logout failed: {err}")))?;
            }
            Some(LogoutAccountParams {
                account_id: None,
                all: false,
            })
            | None => {
                if self.auth_manager.is_external_chatgpt_auth_active() {
                    self.auth_manager
                        .logout_with_revoke()
                        .await
                        .map_err(|err| internal_error(format!("logout failed: {err}")))?;
                } else {
                    let accounts = listed_accounts
                        .as_ref()
                        .expect("managed account list loaded for singular logout");
                    match accounts.as_slice() {
                        [] => {
                            self.auth_manager
                                .logout_with_revoke()
                                .await
                                .map_err(|err| internal_error(format!("logout failed: {err}")))?;
                        }
                        [account] => {
                            let identity = account.identity_key.clone();
                            if self
                                .auth_manager
                                .remove_managed_chatgpt_account(&identity)
                                .await
                                .map_err(|err| internal_error(format!("logout failed: {err}")))?
                            {
                                removed_account_ids.push(identity);
                            }
                        }
                        _ => {
                            return Err(invalid_request(
                                "multiple managed ChatGPT accounts are present; specify accountId or all",
                            ));
                        }
                    }
                }
            }
            Some(LogoutAccountParams {
                account_id: Some(_),
                all: true,
            }) => unreachable!("validated above"),
        }

        if managed_bedrock_auth {
            clear_user_model_provider_if_bedrock(&self.config_manager).await?;
        }

        Self::maybe_refresh_plugin_caches_for_current_config(
            &self.config_manager,
            &self.thread_manager,
            self.auth_manager.auth_cached(),
        )
        .await;
        let list = if self.auth_manager.is_external_chatgpt_auth_active() {
            self.auth_manager
                .stored_managed_chatgpt_account_list()
                .map_err(|err| internal_error(format!("failed to list managed accounts: {err}")))?
        } else {
            self.auth_manager
                .list_managed_chatgpt_accounts(&ManagedChatgptSelectionScope::default())
                .await
                .map_err(|err| internal_error(format!("failed to list managed accounts: {err}")))?
        };
        let response = Self::list_accounts_response_from_owner(list, false, &HashMap::new());
        Ok(LogoutAccountResponse {
            removed_account_ids,
            accounts: response.accounts,
            selected_account_id: response.selected_account_id,
        })
    }

    async fn send_changed_selection_notifications(&self) {
        let observed: Vec<_> = self
            .selection_observer_state
            .lock()
            .await
            .observed_selections
            .values()
            .cloned()
            .collect();
        for previous in observed {
            let Ok(list) = self
                .auth_manager
                .list_managed_chatgpt_accounts(&previous.scope)
                .await
            else {
                continue;
            };
            if list.selected_account_id == previous.selected_account_id
                && list.selection_revision == previous.selection_revision
            {
                continue;
            }
            let Some(thread_id) = previous.scope.thread_id.clone() else {
                continue;
            };
            let notification = AccountSelectionUpdatedNotification {
                thread_id: thread_id.clone(),
                selected_account_id: list.selected_account_id.clone(),
                selection_revision: list.selection_revision,
            };
            let routes = self
                .selection_observer()
                .update_if_current(&previous, list.selected_account_id, list.selection_revision)
                .await;
            for route in routes {
                route.send(notification.clone()).await;
            }
        }
    }

    async fn logout_v2(
        &self,
        request_id: ConnectionRequestId,
        params: Option<LogoutAccountParams>,
    ) -> Result<(), JSONRPCErrorError> {
        let result = self.logout_common(params).await;
        let succeeded = result.is_ok();
        self.outgoing.send_result(request_id, result).await;
        if succeeded {
            self.outgoing
                .send_server_notification(ServerNotification::AccountUpdated(
                    self.current_account_updated_notification(),
                ))
                .await;
            self.send_changed_selection_notifications().await;
        }
        Ok(())
    }

    async fn refresh_token_if_requested(&self, do_refresh: bool) -> RefreshTokenRequestOutcome {
        if self.auth_manager.is_external_chatgpt_auth_active() {
            return RefreshTokenRequestOutcome::NotAttemptedOrSucceeded;
        }
        if do_refresh && let Err(err) = self.auth_manager.refresh_token().await {
            let failed_reason = err.failed_reason();
            if failed_reason.is_none() {
                tracing::warn!("failed to refresh token while getting account: {err}");
                return RefreshTokenRequestOutcome::FailedTransiently;
            }
            return RefreshTokenRequestOutcome::FailedPermanently;
        }
        RefreshTokenRequestOutcome::NotAttemptedOrSucceeded
    }

    async fn get_auth_status_response(
        &self,
        params: GetAuthStatusParams,
    ) -> Result<GetAuthStatusResponse, JSONRPCErrorError> {
        let include_token = params.include_token.unwrap_or(false);
        let do_refresh = params.refresh_token.unwrap_or(false);

        self.refresh_token_if_requested(do_refresh).await;

        // Determine whether auth is required based on the active model provider.
        // If a custom provider is configured with `requires_openai_auth == false`,
        // then no auth step is required; otherwise, default to requiring auth.
        let config = self.load_latest_config().await;
        let requires_openai_auth = config.model_provider.requires_openai_auth;

        let response = if !requires_openai_auth {
            GetAuthStatusResponse {
                auth_method: None,
                auth_token: None,
                requires_openai_auth: Some(false),
            }
        } else {
            let auth = if do_refresh {
                self.auth_manager.auth_cached()
            } else {
                self.auth_manager.auth().await
            };
            match auth {
                Some(auth) => {
                    let permanent_refresh_failure =
                        self.auth_manager.refresh_failure_for_auth(&auth).is_some();
                    let auth_mode = auth_mode_to_api(auth.api_auth_mode());
                    let (reported_auth_method, token_opt) = if matches!(
                        auth,
                        CodexAuth::Headers(_)
                            | CodexAuth::AgentIdentity(_)
                            | CodexAuth::PersonalAccessToken(_)
                    ) || include_token
                        && permanent_refresh_failure
                    {
                        // This response cannot represent the metadata needed to reuse these
                        // credentials.
                        (Some(auth_mode), None)
                    } else {
                        match auth.get_token() {
                            Ok(token) if !token.is_empty() => {
                                let tok = if include_token { Some(token) } else { None };
                                (Some(auth_mode), tok)
                            }
                            Ok(_) => (None, None),
                            Err(err) => {
                                tracing::warn!("failed to get token for auth status: {err}");
                                (None, None)
                            }
                        }
                    };
                    GetAuthStatusResponse {
                        auth_method: reported_auth_method,
                        auth_token: token_opt,
                        requires_openai_auth: Some(true),
                    }
                }
                None => GetAuthStatusResponse {
                    auth_method: None,
                    auth_token: None,
                    requires_openai_auth: Some(true),
                },
            }
        };

        Ok(response)
    }

    async fn selection_scope_for_list(
        &self,
        params: &ListAccountsParams,
    ) -> ManagedChatgptSelectionScope {
        let observed = match params.thread_id.as_ref() {
            Some(thread_id) => self
                .selection_observer_state
                .lock()
                .await
                .observed_selections
                .get(thread_id)
                .cloned(),
            None => None,
        };
        let configured = match params
            .thread_id
            .as_deref()
            .and_then(|thread_id| ThreadId::from_string(thread_id).ok())
        {
            Some(thread_id) => self
                .thread_manager
                .get_thread(thread_id)
                .await
                .ok()
                .map(|thread| {
                    let configured = thread.session_configured();
                    ManagedChatgptSelectionScope {
                        thread_id: Some(configured.thread_id.to_string()),
                        session_id: Some(configured.session_id.to_string()),
                        model: Some(configured.model),
                    }
                }),
            None => None,
        };
        Self::selection_scope_from_observed(params, observed.as_ref(), configured.as_ref())
    }

    fn selection_scope_from_observed(
        params: &ListAccountsParams,
        observed: Option<&ObservedSelection>,
        configured: Option<&ManagedChatgptSelectionScope>,
    ) -> ManagedChatgptSelectionScope {
        if params.thread_id.is_none() {
            return ManagedChatgptSelectionScope::default();
        }
        ManagedChatgptSelectionScope {
            thread_id: params.thread_id.clone(),
            session_id: observed
                .and_then(|observed| observed.scope.session_id.clone())
                .or_else(|| configured.and_then(|configured| configured.session_id.clone())),
            model: params
                .model
                .clone()
                .or_else(|| observed.and_then(|observed| observed.scope.model.clone()))
                .or_else(|| configured.and_then(|configured| configured.model.clone())),
        }
    }

    async fn list_accounts_response(
        &self,
        params: ListAccountsParams,
        scope: ManagedChatgptSelectionScope,
    ) -> Result<ListAccountsResponse, JSONRPCErrorError> {
        if self.auth_manager.is_external_chatgpt_auth_active() {
            let hidden_pool = self
                .auth_manager
                .stored_managed_chatgpt_account_list()
                .map_err(|err| {
                    internal_error(format!("failed to read hidden managed account pool: {err}"))
                })?;
            return Ok(ListAccountsResponse {
                accounts: Vec::new(),
                selected_account_id: None,
                selection_revision: None,
                pool_revision: hidden_pool.pool_revision,
            });
        }
        let initial = self
            .auth_manager
            .list_managed_chatgpt_accounts(&scope)
            .await
            .map_err(|err| internal_error(format!("failed to list managed accounts: {err}")))?;
        let mut refresh_statuses = HashMap::new();

        for account in initial.accounts {
            let attempted_last_refresh = account.last_refresh;
            let identity = account.identity_key;
            let snapshot = if params.refresh_tokens {
                match self
                    .auth_manager
                    .refresh_managed_chatgpt_account_bounded(
                        &identity,
                        ACCOUNT_TOKEN_REFRESH_TIMEOUT,
                    )
                    .await
                {
                    Ok(snapshot) => Some(snapshot),
                    Err(err) => {
                        warn!("failed to refresh managed account {identity}: {err}");
                        None
                    }
                }
            } else {
                match self
                    .auth_manager
                    .managed_chatgpt_auth_snapshot_for_identity(&identity)
                    .await
                {
                    Ok(snapshot) => snapshot,
                    Err(err) => {
                        warn!("failed to resolve managed account {identity}: {err}");
                        refresh_statuses.insert(
                            identity.clone(),
                            (
                                attempted_last_refresh,
                                ManagedChatgptAccountRefreshStatus::TransientUnavailable {
                                    observed_at: Utc::now().timestamp(),
                                },
                            ),
                        );
                        None
                    }
                }
            };

            if !params.refresh_usage {
                continue;
            }
            let Some(snapshot) = snapshot else {
                continue;
            };
            let client = match snapshot
                .auth
                .get_token()
                .map_err(|err| err.to_string())
                .map(|token| {
                    BackendClient::new(
                        self.config.chatgpt_base_url.clone(),
                        self.config.http_client_factory(),
                    )
                    .with_auth_provider(Arc::new(BearerAuthProvider {
                        token: Some(token),
                        account_id: snapshot.transport.raw_account_id.clone(),
                        is_fedramp_account: snapshot.transport.fedramp,
                    }))
                }) {
                Ok(client) => client,
                Err(err) => {
                    warn!("failed to construct backend client for {identity}: {err}");
                    let observation = ManagedChatgptStatusObservation {
                        observed_at: Utc::now(),
                        rate: ManagedChatgptRateObservation::Unavailable {
                            reason: "backend_client_unavailable".to_string(),
                        },
                        token: ManagedChatgptTokenObservation::Unavailable {
                            reason: "backend_client_unavailable".to_string(),
                        },
                    };
                    match self.auth_manager.record_managed_chatgpt_status_observation(
                        &snapshot.identity_key,
                        snapshot.account_revision,
                        snapshot.account_state_revision,
                        observation,
                    ) {
                        Ok(Some(account)) => {
                            self.send_managed_usage_notification(account).await;
                        }
                        Ok(None) => {
                            warn!("discarded stale managed account status for {identity}");
                        }
                        Err(err) => {
                            warn!("failed to record managed account status for {identity}: {err}");
                        }
                    }
                    continue;
                }
            };

            let (rate_result, token_result) = tokio::join!(
                tokio::time::timeout(
                    ACCOUNT_RATE_LIMIT_FETCH_TIMEOUT,
                    client.get_rate_limits_with_reset_credits(),
                ),
                tokio::time::timeout(
                    ACCOUNT_TOKEN_USAGE_FETCH_TIMEOUT,
                    client.get_token_usage_profile(),
                ),
            );
            let rate = match rate_result {
                Ok(Ok(response)) => managed_rate_observation(response.rate_limits),
                Ok(Err(err)) => {
                    warn!("failed to fetch managed account rate limits for {identity}: {err}");
                    ManagedChatgptRateObservation::Unavailable {
                        reason: "rate_limits_unavailable".to_string(),
                    }
                }
                Err(_) => ManagedChatgptRateObservation::Unavailable {
                    reason: "rate_limits_timeout".to_string(),
                },
            };
            let token = match token_result {
                Ok(Ok(profile)) => {
                    let stats = profile.stats;
                    ManagedChatgptTokenObservation::Available(ManagedChatgptTokenUsageSummary {
                        lifetime_tokens: stats.lifetime_tokens,
                        peak_daily_tokens: stats.peak_daily_tokens,
                        longest_running_turn_sec: stats.longest_running_turn_sec,
                        current_streak_days: stats.current_streak_days,
                        longest_streak_days: stats.longest_streak_days,
                    })
                }
                Ok(Err(err)) => {
                    warn!("failed to fetch managed account token usage for {identity}: {err}");
                    ManagedChatgptTokenObservation::Unavailable {
                        reason: "token_usage_unavailable".to_string(),
                    }
                }
                Err(_) => ManagedChatgptTokenObservation::Unavailable {
                    reason: "token_usage_timeout".to_string(),
                },
            };
            let observation = ManagedChatgptStatusObservation {
                observed_at: Utc::now(),
                rate,
                token,
            };
            match self.auth_manager.record_managed_chatgpt_status_observation(
                &snapshot.identity_key,
                snapshot.account_revision,
                snapshot.account_state_revision,
                observation,
            ) {
                Ok(Some(account)) => {
                    self.send_managed_usage_notification(account).await;
                }
                Ok(None) => {
                    warn!("discarded stale managed account status for {identity}");
                }
                Err(err) => {
                    warn!("failed to record managed account status for {identity}: {err}");
                }
            }
        }

        let list = self
            .auth_manager
            .list_managed_chatgpt_accounts(&scope)
            .await
            .map_err(|err| internal_error(format!("failed to list managed accounts: {err}")))?;
        Ok(Self::list_accounts_response_from_owner(
            list,
            params.thread_id.is_some(),
            &refresh_statuses,
        ))
    }

    fn list_accounts_response_from_owner(
        list: codex_login::ManagedChatgptAccountList,
        scoped: bool,
        refresh_statuses: &RefreshStatusByIdentity,
    ) -> ListAccountsResponse {
        let has_managed_pool = !list.accounts.is_empty();
        ListAccountsResponse {
            accounts: list
                .accounts
                .into_iter()
                .map(|account| {
                    let refresh_status = Self::refresh_status_for_account(
                        refresh_statuses,
                        &account.identity_key,
                        account.last_refresh,
                    );
                    Self::managed_account_view_from_owner(account, refresh_status)
                })
                .collect(),
            selected_account_id: list.selected_account_id,
            selection_revision: (scoped && has_managed_pool).then_some(list.selection_revision),
            pool_revision: list.pool_revision,
        }
    }

    fn refresh_status_for_account(
        refresh_statuses: &RefreshStatusByIdentity,
        identity: &str,
        account_last_refresh: DateTime<Utc>,
    ) -> Option<ManagedChatgptAccountRefreshStatus> {
        refresh_statuses
            .get(identity)
            .and_then(|(attempted_last_refresh, status)| {
                (*attempted_last_refresh == account_last_refresh).then(|| status.clone())
            })
    }

    fn refresh_status_from_owner(
        refresh_status: ManagedChatgptRefreshStatus,
        block_kind: Option<ManagedChatgptBlockKindView>,
        last_refresh: DateTime<Utc>,
    ) -> ManagedChatgptAccountRefreshStatus {
        if block_kind == Some(ManagedChatgptBlockKindView::AuthInvalid) {
            return ManagedChatgptAccountRefreshStatus::ReloginRequired {
                reason_code: "auth_invalid".to_string(),
                observed_at: last_refresh.timestamp(),
            };
        }
        match refresh_status {
            ManagedChatgptRefreshStatus::Healthy => ManagedChatgptAccountRefreshStatus::Healthy,
            ManagedChatgptRefreshStatus::TransientUnavailable { observed_at, .. } => {
                ManagedChatgptAccountRefreshStatus::TransientUnavailable {
                    observed_at: observed_at.timestamp(),
                }
            }
            ManagedChatgptRefreshStatus::ReloginRequired {
                observed_at,
                reason_code,
            } => ManagedChatgptAccountRefreshStatus::ReloginRequired {
                reason_code: reason_code.unwrap_or_else(|| "token_refresh_failed".to_string()),
                observed_at: observed_at.timestamp(),
            },
        }
    }

    fn managed_account_view_from_owner(
        account: ManagedChatgptAccountView,
        refresh_status: Option<ManagedChatgptAccountRefreshStatus>,
    ) -> ApiManagedChatgptAccountView {
        let mut rate_limits = std::collections::BTreeMap::new();
        if let Some(usage) = account.usage.as_ref() {
            for window in &usage.rate_windows {
                let snapshot = rate_limits
                    .entry(window.limit_id.clone())
                    .or_insert_with(|| ApiRateLimitSnapshot {
                        limit_id: Some(window.limit_id.clone()),
                        limit_name: None,
                        primary: None,
                        secondary: None,
                        credits: None,
                        individual_limit: None,
                        spend_control_reached: None,
                        plan_type: None,
                        rate_limit_reached_type: None,
                    });
                let wire_window = ApiRateLimitWindow {
                    used_percent: window
                        .remaining_percent
                        .map(|remaining| (100.0 - remaining).round() as i32)
                        .unwrap_or(0),
                    window_duration_mins: window.window_duration_mins,
                    resets_at: window.reset_at.map(|value| value.timestamp()),
                };
                match window.kind {
                    ManagedChatgptLimitKind::Primary | ManagedChatgptLimitKind::Additional => {
                        snapshot.primary = Some(wire_window);
                    }
                    ManagedChatgptLimitKind::Secondary => {
                        snapshot.secondary = Some(wire_window);
                    }
                }
            }
        }
        let token_usage = account
            .usage
            .as_ref()
            .and_then(|usage| usage.token_usage.as_ref())
            .map(|summary| AccountTokenUsageSummary {
                lifetime_tokens: summary.lifetime_tokens,
                peak_daily_tokens: summary.peak_daily_tokens,
                longest_running_turn_sec: summary.longest_running_turn_sec,
                current_streak_days: summary.current_streak_days,
                longest_streak_days: summary.longest_streak_days,
            });
        let usage_state = match account.usage_state {
            ManagedChatgptUsageState::Unknown => ManagedChatgptAccountUsageState::Unknown,
            ManagedChatgptUsageState::Fresh => ManagedChatgptAccountUsageState::Fresh,
            ManagedChatgptUsageState::Stale => ManagedChatgptAccountUsageState::Stale,
            ManagedChatgptUsageState::Unavailable => ManagedChatgptAccountUsageState::Unavailable,
        };
        let refresh_status = refresh_status.unwrap_or_else(|| {
            Self::refresh_status_from_owner(
                account.refresh_status,
                account.block_kind,
                account.last_refresh,
            )
        });
        let (eligible, eligibility_reason) = match account.eligibility {
            ManagedChatgptEligibility::Eligible => (true, None),
            ManagedChatgptEligibility::Blocked => (false, Some("blocked".to_string())),
            ManagedChatgptEligibility::ForcedWorkspaceDisallowed => {
                (false, Some("forced_workspace_disallowed".to_string()))
            }
            ManagedChatgptEligibility::PendingRemoval => {
                (false, Some("pending_removal".to_string()))
            }
        };
        let block = account.block_kind.map(|kind| ManagedChatgptAccountBlock {
            reason: match kind {
                ManagedChatgptBlockKindView::AuthInvalid => "auth_invalid",
                ManagedChatgptBlockKindView::Quota => "quota",
                ManagedChatgptBlockKindView::Workspace => "workspace",
            }
            .to_string(),
            blocked_until: account.block_reset_at.map(|value| value.timestamp()),
        });
        let plan_type = match account.plan.as_deref() {
            Some("go") => PlanType::Go,
            Some("plus") => PlanType::Plus,
            Some("pro") => PlanType::Pro,
            Some("prolite" | "pro_lite") => PlanType::ProLite,
            Some("team") => PlanType::Team,
            Some("self_serve_business_usage_based") => PlanType::SelfServeBusinessUsageBased,
            Some("business") => PlanType::Business,
            Some("enterprise_cbp_usage_based") => PlanType::EnterpriseCbpUsageBased,
            Some("enterprise") => PlanType::Enterprise,
            Some("edu") => PlanType::Edu,
            Some("free") => PlanType::Free,
            Some(_) | None => PlanType::Unknown,
        };
        let observed_at = account
            .usage
            .as_ref()
            .map(|usage| usage.observed_at.timestamp())
            .or_else(|| {
                (account.token_observed_at.timestamp() > 0)
                    .then_some(account.token_observed_at.timestamp())
            });
        let unavailable_observed_at = if account.usage_unavailable_reason.is_some() {
            account
                .usage_unavailable_observed_at
                .map(|observed_at| observed_at.timestamp())
        } else {
            account
                .token_unavailable_observed_at
                .map(|observed_at| observed_at.timestamp())
        };
        ApiManagedChatgptAccountView {
            managed_account_id: account.identity_key,
            chatgpt_account_id: account.chatgpt_account_id,
            email: account.normalized_email,
            plan_type,
            eligible,
            eligibility_reason,
            account_revision: account.revision,
            credential_revision: account.credential_revision,
            refresh_status,
            block,
            usage: ManagedChatgptAccountUsage {
                state: usage_state,
                rate_limits: rate_limits.into_values().collect(),
                token_usage,
                observed_at,
                unavailable_reason: account
                    .usage_unavailable_reason
                    .or(account.token_unavailable_reason),
                unavailable_observed_at,
            },
        }
    }

    async fn send_managed_usage_notification(&self, account: ManagedChatgptAccountView) {
        let account = Self::managed_account_view_from_owner(account, None);
        self.outgoing
            .send_server_notification(ServerNotification::AccountUsageUpdated(
                AccountUsageUpdatedNotification {
                    managed_account_id: account.managed_account_id.clone(),
                    account_revision: account.account_revision,
                    usage: account.usage.clone(),
                },
            ))
            .await;
    }

    async fn get_account_response(
        &self,
        params: GetAccountParams,
    ) -> Result<GetAccountResponse, JSONRPCErrorError> {
        let do_refresh = params.refresh_token;

        self.refresh_token_if_requested(do_refresh).await;

        let config = self.load_latest_config().await;
        let provider =
            create_model_provider(config.model_provider, Some(self.auth_manager.clone()));
        let account_state = match provider.account_state() {
            Ok(account_state) => account_state,
            Err(err) => return Err(invalid_request(err.to_string())),
        };
        let account = account_state.account.map(Account::from);

        Ok(GetAccountResponse {
            account,
            requires_openai_auth: account_state.requires_openai_auth,
        })
    }

    async fn get_account_rate_limits_response(
        &self,
    ) -> Result<GetAccountRateLimitsResponse, JSONRPCErrorError> {
        let Some(auth) = self.auth_manager.auth().await else {
            return Err(invalid_request(
                "codex account authentication required to read rate limits",
            ));
        };

        if !auth.uses_codex_backend() {
            return Err(invalid_request(
                "chatgpt authentication required to read rate limits",
            ));
        }

        let client = BackendClient::from_auth(
            self.config.chatgpt_base_url.clone(),
            &auth,
            self.config.http_client_factory(),
        );

        let (response, detailed_rate_limit_reset_credits) = tokio::join!(
            client.get_rate_limits_with_reset_credits(),
            Self::detailed_rate_limit_reset_credits(&client),
        );
        let response = response
            .map_err(|err| internal_error(format!("failed to fetch codex rate limits: {err}")))?;
        if response.rate_limits.is_empty() {
            return Err(internal_error(
                "failed to fetch codex rate limits: no snapshots returned",
            ));
        }

        let rate_limits_by_limit_id: HashMap<_, _> = response
            .rate_limits
            .iter()
            .cloned()
            .map(|snapshot| {
                let limit_id = snapshot
                    .limit_id
                    .clone()
                    .unwrap_or_else(|| "codex".to_string());
                (limit_id, snapshot)
            })
            .collect();
        let rate_limits = response
            .rate_limits
            .iter()
            .find(|snapshot| snapshot.limit_id.as_deref() == Some("codex"))
            .cloned()
            .unwrap_or_else(|| response.rate_limits[0].clone());

        let rate_limit_reset_credits = detailed_rate_limit_reset_credits.or_else(|| {
            response
                .rate_limit_reset_credits
                .map(|summary| RateLimitResetCreditsSummary {
                    available_count: summary.available_count,
                    credits: None,
                })
        });

        Ok(GetAccountRateLimitsResponse {
            rate_limits: rate_limits.into(),
            rate_limits_by_limit_id: Some(
                rate_limits_by_limit_id
                    .into_iter()
                    .map(|(limit_id, snapshot)| (limit_id, snapshot.into()))
                    .collect(),
            ),
            rate_limit_reset_credits,
        })
    }

    async fn get_account_token_usage_response(
        &self,
    ) -> Result<GetAccountTokenUsageResponse, JSONRPCErrorError> {
        let Some(auth) = self.auth_manager.auth().await else {
            return Err(invalid_request(
                "codex account authentication required to read token usage",
            ));
        };

        if !auth.uses_codex_backend() {
            return Err(invalid_request(
                "chatgpt authentication required to read token usage",
            ));
        }

        let client = BackendClient::from_auth(
            self.config.chatgpt_base_url.clone(),
            &auth,
            self.config.http_client_factory(),
        );
        let profile = tokio::time::timeout(
            ACCOUNT_TOKEN_USAGE_FETCH_TIMEOUT,
            client.get_token_usage_profile(),
        )
        .await
        .map_err(|_| internal_error("token usage profile fetch timed out"))?
        .map_err(|err| internal_error(format!("failed to fetch token usage profile: {err}")))?;
        Ok(Self::account_token_usage_response(profile))
    }

    async fn get_workspace_messages_response(
        &self,
    ) -> Result<GetWorkspaceMessagesResponse, JSONRPCErrorError> {
        let Some(auth) = self.auth_manager.auth().await else {
            return Err(invalid_request(
                "codex account authentication required to read workspace messages",
            ));
        };

        if !auth.uses_codex_backend() {
            return Err(invalid_request(
                "chatgpt authentication required to read workspace messages",
            ));
        }

        let client = BackendClient::from_auth(
            self.config.chatgpt_base_url.clone(),
            &auth,
            self.config.http_client_factory(),
        );
        let messages = tokio::time::timeout(
            ACCOUNT_WORKSPACE_MESSAGES_FETCH_TIMEOUT,
            client.list_workspace_messages(),
        )
        .await
        .map_err(|_| internal_error("workspace messages fetch timed out"))?;

        match messages {
            Ok(messages) => {
                Self::workspace_messages_response(messages, /*feature_enabled*/ true)
            }
            Err(err) if workspace_messages_feature_disabled(&err) => {
                Self::workspace_messages_response(
                    BackendWorkspaceMessagesResponse {
                        messages: Vec::new(),
                    },
                    /*feature_enabled*/ false,
                )
            }
            Err(err) => Err(internal_error(format!(
                "failed to fetch workspace messages: {err}"
            ))),
        }
    }

    fn account_token_usage_response(profile: TokenUsageProfile) -> GetAccountTokenUsageResponse {
        let stats = profile.stats;
        GetAccountTokenUsageResponse {
            summary: AccountTokenUsageSummary {
                lifetime_tokens: stats.lifetime_tokens,
                peak_daily_tokens: stats.peak_daily_tokens,
                longest_running_turn_sec: stats.longest_running_turn_sec,
                current_streak_days: stats.current_streak_days,
                longest_streak_days: stats.longest_streak_days,
            },
            daily_usage_buckets: stats.daily_usage_buckets.map(|buckets| {
                buckets
                    .into_iter()
                    .map(|bucket| AccountTokenUsageDailyBucket {
                        start_date: bucket.start_date,
                        tokens: bucket.tokens,
                    })
                    .collect()
            }),
        }
    }

    fn workspace_messages_response(
        messages: BackendWorkspaceMessagesResponse,
        feature_enabled: bool,
    ) -> Result<GetWorkspaceMessagesResponse, JSONRPCErrorError> {
        Ok(GetWorkspaceMessagesResponse {
            feature_enabled,
            messages: messages
                .messages
                .into_iter()
                .map(workspace_message_from_backend)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    async fn send_add_credits_nudge_email_response(
        &self,
        params: SendAddCreditsNudgeEmailParams,
    ) -> Result<SendAddCreditsNudgeEmailResponse, JSONRPCErrorError> {
        self.send_add_credits_nudge_email_inner(params)
            .await
            .map(|status| SendAddCreditsNudgeEmailResponse { status })
    }

    async fn send_add_credits_nudge_email_inner(
        &self,
        params: SendAddCreditsNudgeEmailParams,
    ) -> Result<AddCreditsNudgeEmailStatus, JSONRPCErrorError> {
        let Some(auth) = self.auth_manager.auth().await else {
            return Err(invalid_request(
                "codex account authentication required to notify workspace owner",
            ));
        };

        if !auth.uses_codex_backend() {
            return Err(invalid_request(
                "chatgpt authentication required to notify workspace owner",
            ));
        }

        let client = BackendClient::from_auth(
            self.config.chatgpt_base_url.clone(),
            &auth,
            self.config.http_client_factory(),
        );

        match client
            .send_add_credits_nudge_email(Self::backend_credit_type(params.credit_type))
            .await
        {
            Ok(()) => Ok(AddCreditsNudgeEmailStatus::Sent),
            Err(err) if err.status().is_some_and(|status| status.as_u16() == 429) => {
                Ok(AddCreditsNudgeEmailStatus::CooldownActive)
            }
            Err(err) => Err(internal_error(format!(
                "failed to notify workspace owner: {err}"
            ))),
        }
    }

    fn backend_credit_type(value: AddCreditsNudgeCreditType) -> BackendAddCreditsNudgeCreditType {
        match value {
            AddCreditsNudgeCreditType::Credits => BackendAddCreditsNudgeCreditType::Credits,
            AddCreditsNudgeCreditType::UsageLimit => BackendAddCreditsNudgeCreditType::UsageLimit,
        }
    }
}

fn managed_rate_observation(
    rate_limits: Vec<codex_protocol::protocol::RateLimitSnapshot>,
) -> ManagedChatgptRateObservation {
    if rate_limits.is_empty() {
        return ManagedChatgptRateObservation::Unavailable {
            reason: "rate_limits_empty".to_string(),
        };
    }
    let mut windows = Vec::new();
    for (snapshot_index, snapshot) in rate_limits.into_iter().enumerate() {
        let limit_id = snapshot.limit_id.unwrap_or_else(|| "codex".to_string());
        let canonical = snapshot_index == 0 || limit_id == "codex";
        for (kind, suffix, window) in [
            (
                if canonical {
                    ManagedChatgptLimitKind::Primary
                } else {
                    ManagedChatgptLimitKind::Additional
                },
                "primary",
                snapshot.primary,
            ),
            (
                if canonical {
                    ManagedChatgptLimitKind::Secondary
                } else {
                    ManagedChatgptLimitKind::Additional
                },
                "secondary",
                snapshot.secondary,
            ),
        ] {
            let Some(window) = window else {
                continue;
            };
            windows.push(ManagedChatgptRateWindowView {
                limit_id: if canonical {
                    limit_id.clone()
                } else {
                    format!("{limit_id}:{suffix}")
                },
                kind,
                remaining_percent: Some((100.0 - window.used_percent).clamp(0.0, 100.0)),
                reset_at: window
                    .resets_at
                    .and_then(|value| DateTime::from_timestamp(value, 0)),
                window_duration_mins: window.window_minutes,
            });
        }
    }
    if windows.is_empty() {
        ManagedChatgptRateObservation::Unavailable {
            reason: "rate_limit_windows_empty".to_string(),
        }
    } else {
        ManagedChatgptRateObservation::Available(windows)
    }
}

fn workspace_message_from_backend(
    message: BackendWorkspaceMessage,
) -> Result<WorkspaceMessage, JSONRPCErrorError> {
    Ok(WorkspaceMessage {
        message_id: message.message_id,
        message_type: workspace_message_type_from_backend(message.message_type),
        message_body: message.message_body,
        created_at: workspace_message_timestamp_from_backend(message.created_at)?,
        archived_at: workspace_message_timestamp_from_backend(message.archived_at)?,
    })
}

fn workspace_message_timestamp_from_backend(
    timestamp: Option<String>,
) -> Result<Option<i64>, JSONRPCErrorError> {
    timestamp
        .map(|timestamp| {
            DateTime::parse_from_rfc3339(&timestamp)
                .map(|timestamp| timestamp.timestamp())
                .map_err(|err| {
                    internal_error(format!(
                        "failed to parse workspace message timestamp `{timestamp}`: {err}"
                    ))
                })
        })
        .transpose()
}

fn workspace_message_type_from_backend(
    message_type: BackendWorkspaceMessageType,
) -> WorkspaceMessageType {
    match message_type {
        BackendWorkspaceMessageType::Headline => WorkspaceMessageType::Headline,
        BackendWorkspaceMessageType::Announcement => WorkspaceMessageType::Announcement,
        BackendWorkspaceMessageType::Unknown => WorkspaceMessageType::Unknown,
    }
}

fn workspace_messages_feature_disabled(err: &BackendRequestError) -> bool {
    err.status().is_some_and(|status| status.as_u16() == 404)
}

async fn send_pool_update_unless_shutdown(
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

fn should_emit_pool_update(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outgoing_message::OutgoingEnvelope;
    use codex_backend_client::TokenUsageProfileDailyBucket;
    use codex_backend_client::TokenUsageProfileStats;
    use codex_protocol::protocol::RateLimitSnapshot;
    use codex_protocol::protocol::RateLimitWindow;
    use pretty_assertions::assert_eq;
    use tokio::sync::mpsc;

    #[test]
    fn account_token_usage_response_maps_profile_stats_and_daily_buckets() {
        let response = AccountRequestProcessor::account_token_usage_response(TokenUsageProfile {
            stats: TokenUsageProfileStats {
                lifetime_tokens: Some(123),
                peak_daily_tokens: Some(45),
                longest_running_turn_sec: Some(67),
                current_streak_days: Some(8),
                longest_streak_days: Some(9),
                daily_usage_buckets: Some(vec![TokenUsageProfileDailyBucket {
                    start_date: "2026-05-29".to_string(),
                    tokens: 10,
                }]),
            },
        });

        assert_eq!(
            response,
            GetAccountTokenUsageResponse {
                summary: AccountTokenUsageSummary {
                    lifetime_tokens: Some(123),
                    peak_daily_tokens: Some(45),
                    longest_running_turn_sec: Some(67),
                    current_streak_days: Some(8),
                    longest_streak_days: Some(9),
                },
                daily_usage_buckets: Some(vec![AccountTokenUsageDailyBucket {
                    start_date: "2026-05-29".to_string(),
                    tokens: 10,
                }]),
            }
        );
    }

    #[test]
    fn workspace_messages_response_maps_backend_messages() {
        let response = AccountRequestProcessor::workspace_messages_response(
            BackendWorkspaceMessagesResponse {
                messages: vec![BackendWorkspaceMessage {
                    message_id: "headline-id".to_string(),
                    message_type: BackendWorkspaceMessageType::Headline,
                    message_body: "Headline body".to_string(),
                    created_at: Some("2026-06-14T00:00:00Z".to_string()),
                    archived_at: Some("2026-06-15T00:00:00Z".to_string()),
                }],
            },
            /*feature_enabled*/ true,
        )
        .expect("workspace message timestamps should parse");

        assert_eq!(
            response,
            GetWorkspaceMessagesResponse {
                feature_enabled: true,
                messages: vec![WorkspaceMessage {
                    message_id: "headline-id".to_string(),
                    message_type: WorkspaceMessageType::Headline,
                    message_body: "Headline body".to_string(),
                    created_at: Some(1_781_395_200),
                    archived_at: Some(1_781_481_600),
                }],
            }
        );
    }

    #[test]
    fn persisted_refresh_status_maps_without_an_explicit_refresh_attempt() {
        let observed_at = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        assert_eq!(
            AccountRequestProcessor::refresh_status_from_owner(
                ManagedChatgptRefreshStatus::TransientUnavailable {
                    observed_at,
                    reason_code: Some("token_refresh_timeout".to_string()),
                },
                None,
                observed_at,
            ),
            ManagedChatgptAccountRefreshStatus::TransientUnavailable {
                observed_at: 1_700_000_000,
            }
        );
        assert_eq!(
            AccountRequestProcessor::refresh_status_from_owner(
                ManagedChatgptRefreshStatus::ReloginRequired {
                    observed_at,
                    reason_code: Some("refresh_token_expired".to_string()),
                },
                None,
                observed_at,
            ),
            ManagedChatgptAccountRefreshStatus::ReloginRequired {
                reason_code: "refresh_token_expired".to_string(),
                observed_at: 1_700_000_000,
            }
        );
        assert_eq!(
            AccountRequestProcessor::refresh_status_from_owner(
                ManagedChatgptRefreshStatus::Healthy,
                Some(ManagedChatgptBlockKindView::AuthInvalid),
                observed_at,
            ),
            ManagedChatgptAccountRefreshStatus::ReloginRequired {
                reason_code: "auth_invalid".to_string(),
                observed_at: 1_700_000_000,
            }
        );
    }

    #[test]
    fn managed_rate_observation_uses_first_or_codex_snapshot_as_canonical() {
        let observation = managed_rate_observation(vec![
            RateLimitSnapshot {
                limit_id: None,
                limit_name: None,
                primary: Some(RateLimitWindow {
                    used_percent: 10.0,
                    window_minutes: Some(15),
                    resets_at: Some(1_700_000_000),
                }),
                secondary: None,
                credits: None,
                individual_limit: None,
                plan_type: None,
                rate_limit_reached_type: None,
            },
            RateLimitSnapshot {
                limit_id: Some("other".to_string()),
                limit_name: None,
                primary: Some(RateLimitWindow {
                    used_percent: 20.0,
                    window_minutes: Some(30),
                    resets_at: Some(1_700_000_100),
                }),
                secondary: None,
                credits: None,
                individual_limit: None,
                plan_type: None,
                rate_limit_reached_type: None,
            },
            RateLimitSnapshot {
                limit_id: Some("codex".to_string()),
                limit_name: None,
                primary: Some(RateLimitWindow {
                    used_percent: 30.0,
                    window_minutes: Some(60),
                    resets_at: Some(1_700_000_200),
                }),
                secondary: Some(RateLimitWindow {
                    used_percent: 40.0,
                    window_minutes: Some(120),
                    resets_at: Some(1_700_000_300),
                }),
                credits: None,
                individual_limit: None,
                plan_type: None,
                rate_limit_reached_type: None,
            },
        ]);

        let ManagedChatgptRateObservation::Available(windows) = observation else {
            panic!("expected available rate windows");
        };
        assert_eq!(windows.len(), 4);
        assert_eq!(windows[0].limit_id, "codex");
        assert_eq!(windows[0].kind, ManagedChatgptLimitKind::Primary);
        assert_eq!(windows[1].limit_id, "other:primary");
        assert_eq!(windows[1].kind, ManagedChatgptLimitKind::Additional);
        assert_eq!(windows[2].limit_id, "codex");
        assert_eq!(windows[2].kind, ManagedChatgptLimitKind::Primary);
        assert_eq!(windows[3].limit_id, "codex");
        assert_eq!(windows[3].kind, ManagedChatgptLimitKind::Secondary);
        assert_eq!(windows[2].window_duration_mins, Some(60));
        assert_eq!(windows[3].window_duration_mins, Some(120));
        assert_eq!(
            windows[3].reset_at.map(|reset_at| reset_at.timestamp()),
            Some(1_700_000_300)
        );
    }

    #[test]
    fn managed_rate_observation_without_actual_windows_is_unavailable() {
        let observation = managed_rate_observation(vec![RateLimitSnapshot {
            limit_id: Some("codex".to_string()),
            limit_name: None,
            primary: None,
            secondary: None,
            credits: None,
            individual_limit: None,
            plan_type: None,
            rate_limit_reached_type: None,
        }]);

        assert_eq!(
            observation,
            ManagedChatgptRateObservation::Unavailable {
                reason: "rate_limit_windows_empty".to_string(),
            }
        );
    }

    #[test]
    fn workspace_messages_feature_disabled_only_for_not_found() {
        let cases = [
            (reqwest::StatusCode::NOT_FOUND, true),
            (reqwest::StatusCode::UNAUTHORIZED, false),
            (reqwest::StatusCode::FORBIDDEN, false),
        ];

        for (status, expected) in cases {
            let err = BackendRequestError::UnexpectedStatus {
                method: "GET".to_string(),
                url: "https://example.test/api/codex/workspace-messages".to_string(),
                status,
                content_type: "application/json".to_string(),
                body: "{}".to_string(),
            };
            assert_eq!(workspace_messages_feature_disabled(&err), expected);
        }
    }

    #[test]
    fn scoped_list_reuses_core_selected_scope_before_considering_siblings() {
        let params = ListAccountsParams {
            thread_id: Some("thread-1".to_string()),
            model: Some("requested-model".to_string()),
            ..Default::default()
        };
        let core_scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: Some("root-session-1".to_string()),
            model: Some("turn-model".to_string()),
        };
        let observed = ObservedSelection {
            scope: core_scope.clone(),
            selected_account_id: Some("email:managed-a@example.com".to_string()),
            selection_revision: 8,
            lifecycle_generation: 0,
            routes: Vec::new(),
        };

        assert_eq!(
            AccountRequestProcessor::selection_scope_from_observed(&params, Some(&observed), None,),
            ManagedChatgptSelectionScope {
                model: Some("requested-model".to_string()),
                ..core_scope
            },
            "a scoped list must reuse the core pin identity while honoring a request model override"
        );
        let configured = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: Some("root-session-1".to_string()),
            model: Some("configured-model".to_string()),
        };
        let without_model_override = ListAccountsParams {
            model: None,
            ..params.clone()
        };
        assert_eq!(
            AccountRequestProcessor::selection_scope_from_observed(
                &without_model_override,
                None,
                Some(&configured),
            ),
            configured,
            "a cold observer must recover canonical session and model identity from thread metadata"
        );
        assert_eq!(
            AccountRequestProcessor::selection_scope_from_observed(&params, None, None).session_id,
            None,
            "a cold observer must not assume that a child thread id is its root session id"
        );
    }

    #[test]
    fn model_only_list_scope_is_unscoped() {
        let params = ListAccountsParams {
            model: Some("requested-model".to_string()),
            ..Default::default()
        };
        let configured = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: Some("root-session-1".to_string()),
            model: Some("configured-model".to_string()),
        };

        assert_eq!(
            AccountRequestProcessor::selection_scope_from_observed(
                &params,
                None,
                Some(&configured),
            ),
            ManagedChatgptSelectionScope::default(),
            "a model without an explicit thread must not create an invisible selection pin"
        );
    }

    #[test]
    fn refresh_failure_tracks_credential_generation_not_row_revision() {
        let failure = ManagedChatgptAccountRefreshStatus::ReloginRequired {
            reason_code: "token_refresh_failed".to_string(),
            observed_at: 123,
        };
        let attempted_last_refresh = Utc::now();
        let refresh_statuses = HashMap::from([(
            "email:user@example.com".to_string(),
            (attempted_last_refresh, failure.clone()),
        )]);

        assert_eq!(
            AccountRequestProcessor::refresh_status_for_account(
                &refresh_statuses,
                "email:user@example.com",
                attempted_last_refresh,
            ),
            Some(failure),
            "a usage or lease row-revision bump must retain this list call's refresh failure"
        );

        assert_eq!(
            AccountRequestProcessor::refresh_status_for_account(
                &refresh_statuses,
                "email:user@example.com",
                attempted_last_refresh + chrono::Duration::seconds(1),
            ),
            None,
            "a relogin that replaced the attempted credentials must not inherit their failure"
        );
    }

    #[test]
    fn pool_update_coalesces_duplicate_ticks_but_emits_monotonic_empty_cutover() {
        let mut last_pool_revision = None;
        assert!(!should_emit_pool_update(&mut last_pool_revision, 0, true,));
        assert!(should_emit_pool_update(&mut last_pool_revision, 7, false,));
        assert!(!should_emit_pool_update(&mut last_pool_revision, 7, false,));
        assert!(should_emit_pool_update(&mut last_pool_revision, 8, true,));
        assert!(!should_emit_pool_update(&mut last_pool_revision, 8, true,));
    }

    #[tokio::test]
    async fn delayed_list_registration_is_rejected_after_cleanup() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 4);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let observer = AccountSelectionObserver::for_test(Arc::clone(&outgoing));
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: None,
            model: None,
        };

        observer.activate_thread("thread-1").await;
        let unsubscribed_registration = observer
            .capture_list_registration("thread-1", ConnectionId(1))
            .await;
        observer
            .remove_connection_from_thread("thread-1", ConnectionId(1))
            .await;
        assert!(
            observer
                .record_list_response(
                    unsubscribed_registration,
                    scope.clone(),
                    Some("managed-a".to_string()),
                    8,
                    SelectionNotificationRoute::for_connection(
                        Arc::clone(&outgoing),
                        ConnectionId(1),
                    ),
                )
                .await
                .is_none()
        );
        {
            let state = observer.state.lock().await;
            assert!(state.observed_selections.is_empty());
            assert!(state.route_generations.is_empty());
            assert!(state.connection_generations.is_empty());
            assert_eq!(state.lifecycle_generations.len(), 1);
        }

        let removed_thread_registration = observer
            .capture_list_registration("thread-1", ConnectionId(1))
            .await;
        observer.remove_thread("thread-1").await;
        assert!(
            observer
                .record_list_response(
                    removed_thread_registration,
                    scope,
                    Some("managed-a".to_string()),
                    8,
                    SelectionNotificationRoute::for_connection(outgoing, ConnectionId(1)),
                )
                .await
                .is_none()
        );
        assert!(observer.observed_scope_for_test("thread-1").await.is_none());
        assert!(
            rx.try_recv().is_err(),
            "cleanup must prevent both stale observer state and notifications"
        );
    }

    #[expect(
        clippy::await_holding_invalid_type,
        reason = "test holds the observer lock to verify teardown ordering"
    )]
    #[tokio::test]
    async fn thread_teardown_removes_subscriptions_before_observer_invalidation() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 4);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let observer = AccountSelectionObserver::for_test(Arc::clone(&outgoing));
        let manager = ThreadStateManager::new();
        let thread_id = ThreadId::new();
        let connection_id = ConnectionId(1);
        manager
            .connection_initialized(connection_id, ConnectionCapabilities::default())
            .await;
        manager
            .try_ensure_connection_subscribed(
                thread_id,
                connection_id,
                /*experimental_raw_events*/ false,
            )
            .await
            .expect("connection should be live");
        observer
            .activate_thread(&thread_id.to_string())
            .await
            .capture_event()
            .await
            .expect("active listener registration")
            .notify_if_changed(
                ManagedChatgptSelectionScope {
                    thread_id: Some(thread_id.to_string()),
                    session_id: None,
                    model: None,
                },
                "managed-a".to_string(),
                8,
                &ThreadScopedOutgoingMessageSender::new(outgoing, vec![connection_id], thread_id),
            )
            .await;
        rx.recv().await.expect("initial selection notification");

        let observer_state = Arc::clone(&observer.state);
        let observer_guard = observer_state.lock().await;
        let manager_for_cleanup = manager.clone();
        let observer_for_cleanup = observer.clone();
        let cleanup = tokio::spawn(async move {
            super::super::thread_processor::finalize_account_selection_state(
                &manager_for_cleanup,
                &observer_for_cleanup,
                thread_id,
            )
            .await;
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !manager
                .subscribed_connection_ids(thread_id)
                .await
                .is_empty()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("thread subscriptions must be removed before observer invalidation blocks");
        assert!(
            observer_guard
                .observed_selections
                .contains_key(&thread_id.to_string()),
            "observer invalidation is intentionally blocked by this interleaving"
        );
        drop(observer_guard);
        cleanup.await.expect("teardown task");
        assert!(
            observer
                .observed_scope_for_test(&thread_id.to_string())
                .await
                .is_none(),
            "no observer route may survive thread-state removal"
        );
    }

    #[tokio::test]
    async fn queued_selection_event_is_rejected_after_teardown_but_resume_reactivates() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 4);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let scoped_outgoing = ThreadScopedOutgoingMessageSender::new(
            Arc::clone(&outgoing),
            vec![ConnectionId(1)],
            ThreadId::new(),
        );
        let observer = AccountSelectionObserver::for_test(outgoing);
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: Some("session-1".to_string()),
            model: Some("gpt-5".to_string()),
        };

        let removed_listener = observer.activate_thread("thread-1").await;
        let queued_event = removed_listener
            .capture_event()
            .await
            .expect("active listener registration");
        observer.remove_thread("thread-1").await;
        queued_event
            .notify_if_changed(scope.clone(), "managed-a".to_string(), 8, &scoped_outgoing)
            .await;
        assert!(observer.observed_scope_for_test("thread-1").await.is_none());
        assert!(
            rx.try_recv().is_err(),
            "a queued event from the removed listener must be silent"
        );

        let resumed_listener = observer.activate_thread("thread-1").await;
        resumed_listener
            .capture_event()
            .await
            .expect("resumed listener registration")
            .notify_if_changed(scope.clone(), "managed-b".to_string(), 9, &scoped_outgoing)
            .await;
        assert_eq!(
            observer.observed_scope_for_test("thread-1").await,
            Some(scope)
        );
        assert!(
            rx.recv().await.is_some(),
            "the same persisted thread must reactivate observation after resume"
        );
    }

    #[tokio::test]
    async fn queued_selection_event_filters_unsubscribed_and_closed_connections() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 8);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let scoped_outgoing = ThreadScopedOutgoingMessageSender::new(
            Arc::clone(&outgoing),
            vec![ConnectionId(1), ConnectionId(2), ConnectionId(3)],
            ThreadId::new(),
        );
        let observer = AccountSelectionObserver::for_test(outgoing);
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: None,
            model: None,
        };
        let listener = observer.activate_thread("thread-1").await;
        let queued_event = listener
            .capture_event()
            .await
            .expect("active listener registration");

        observer
            .remove_connection_from_thread("thread-1", ConnectionId(1))
            .await;
        observer.remove_connection(ConnectionId(2)).await;
        queued_event
            .notify_if_changed(scope, "managed-a".to_string(), 8, &scoped_outgoing)
            .await;

        let OutgoingEnvelope::ToConnection { connection_id, .. } =
            rx.recv().await.expect("current connection notification")
        else {
            panic!("expected connection-scoped notification");
        };
        assert_eq!(connection_id, ConnectionId(3));
        assert!(
            rx.try_recv().is_err(),
            "stale thread and connection routes must not receive notifications"
        );
        let state = observer.state.lock().await;
        let routes = &state
            .observed_selections
            .get("thread-1")
            .expect("current route remains observed")
            .routes;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].connection_ids_for_test(), vec![ConnectionId(3)]);
    }

    #[tokio::test]
    async fn stale_selection_updates_do_not_mutate_or_duplicate_routes() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 8);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let scoped_outgoing = ThreadScopedOutgoingMessageSender::new(
            Arc::clone(&outgoing),
            vec![ConnectionId(1), ConnectionId(2)],
            ThreadId::new(),
        );
        let observer = AccountSelectionObserver::for_test(Arc::clone(&outgoing));
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: None,
            model: None,
        };
        let listener = observer.activate_thread("thread-1").await;
        let event_route = listener
            .capture_event()
            .await
            .expect("active listener registration");
        event_route
            .notify_if_changed(scope.clone(), "managed-a".to_string(), 8, &scoped_outgoing)
            .await;
        rx.recv()
            .await
            .expect("initial notification for connection 1");
        rx.recv()
            .await
            .expect("initial notification for connection 2");

        event_route
            .notify_if_changed(scope.clone(), "stale".to_string(), 7, &scoped_outgoing)
            .await;
        let equal_list_registration = observer
            .capture_list_registration("thread-1", ConnectionId(1))
            .await;
        assert!(
            observer
                .record_list_response(
                    equal_list_registration,
                    scope.clone(),
                    Some("managed-a".to_string()),
                    8,
                    SelectionNotificationRoute::for_connection(
                        Arc::clone(&outgoing),
                        ConnectionId(1),
                    ),
                )
                .await
                .is_none()
        );
        {
            let state = observer.state.lock().await;
            let routes = &state
                .observed_selections
                .get("thread-1")
                .expect("observed selection")
                .routes;
            assert_eq!(routes.len(), 1);
            assert_eq!(
                routes[0].connection_ids_for_test(),
                vec![ConnectionId(1), ConnectionId(2)]
            );
        }

        listener
            .capture_event()
            .await
            .expect("current listener registration")
            .notify_if_changed(scope, "managed-b".to_string(), 9, &scoped_outgoing)
            .await;
        let mut connection_ids = Vec::new();
        for _ in 0..2 {
            let OutgoingEnvelope::ToConnection { connection_id, .. } =
                rx.recv().await.expect("newer selection notification")
            else {
                panic!("expected connection-scoped notification");
            };
            connection_ids.push(connection_id);
        }
        connection_ids.sort_by_key(|connection_id| connection_id.0);
        assert_eq!(connection_ids, vec![ConnectionId(1), ConnectionId(2)]);
        assert!(
            rx.try_recv().is_err(),
            "each connection must receive the newer selection exactly once"
        );
    }

    #[tokio::test]
    async fn list_registration_survives_sibling_cleanup_and_catches_up_stale_response() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 8);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let observer = AccountSelectionObserver::for_test(Arc::clone(&outgoing));
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: None,
            model: None,
        };
        let listener = observer.activate_thread("thread-1").await;
        listener
            .capture_event()
            .await
            .expect("active listener registration")
            .notify_if_changed(
                scope.clone(),
                "managed-current".to_string(),
                9,
                &ThreadScopedOutgoingMessageSender::new(
                    Arc::clone(&outgoing),
                    vec![ConnectionId(1)],
                    ThreadId::new(),
                ),
            )
            .await;
        rx.recv().await.expect("initial notification");

        let connection_two = observer
            .capture_list_registration("thread-1", ConnectionId(2))
            .await;
        observer
            .remove_connection_from_thread("thread-1", ConnectionId(1))
            .await;
        observer.remove_connection(ConnectionId(1)).await;
        let (catch_up, routes) = observer
            .record_list_response(
                connection_two,
                scope.clone(),
                Some("managed-stale".to_string()),
                8,
                SelectionNotificationRoute::for_connection(Arc::clone(&outgoing), ConnectionId(2)),
            )
            .await
            .expect("sibling cleanup must not invalidate connection two");
        assert_eq!(
            catch_up.selected_account_id.as_deref(),
            Some("managed-current")
        );
        assert_eq!(catch_up.selection_revision, 9);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].connection_ids_for_test(), vec![ConnectionId(2)]);

        let connection_three = observer
            .capture_list_registration("thread-1", ConnectionId(3))
            .await;
        assert!(
            observer
                .record_list_response(
                    connection_three,
                    scope,
                    Some("managed-current".to_string()),
                    9,
                    SelectionNotificationRoute::for_connection(outgoing, ConnectionId(3)),
                )
                .await
                .is_none(),
            "an equal response registers the route without replaying the same revision"
        );
        let state = observer.state.lock().await;
        let routes = &state
            .observed_selections
            .get("thread-1")
            .expect("observed selection")
            .routes;
        let mut connection_ids = routes
            .iter()
            .flat_map(SelectionNotificationRoute::connection_ids_for_test)
            .collect::<Vec<_>>();
        connection_ids.sort_by_key(|connection_id| connection_id.0);
        assert_eq!(connection_ids, vec![ConnectionId(2), ConnectionId(3)]);
    }

    #[tokio::test]
    async fn blocked_targeted_send_is_cancelled_before_unsubscribe_returns() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 1);
        let capacity_probe = tx.clone();
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let observer = AccountSelectionObserver::for_test(Arc::clone(&outgoing));
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: None,
            model: None,
        };
        let event_observer = observer.activate_thread("thread-1").await;
        let registration = observer
            .capture_event_registration(&event_observer)
            .await
            .expect("active event registration");
        let (notification, routes) = observer
            .record_if_changed(
                registration,
                scope,
                Some("managed-a".to_string()),
                8,
                SelectionNotificationRoute::from_thread(&ThreadScopedOutgoingMessageSender::new(
                    Arc::clone(&outgoing),
                    vec![ConnectionId(1), ConnectionId(2)],
                    ThreadId::new(),
                )),
            )
            .await
            .expect("new selection should record both targets");

        let send = tokio::spawn({
            let route = routes[0].clone();
            async move { route.send(notification).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while capacity_probe.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first target must fill the bounded channel");
        assert!(!send.is_finished(), "second target must be blocked");

        observer
            .remove_connection_from_thread("thread-1", ConnectionId(2))
            .await;
        tokio::time::timeout(Duration::from_secs(1), send)
            .await
            .expect("invalidating the blocked target must release the send")
            .expect("send task");

        let OutgoingEnvelope::ToConnection { connection_id, .. } =
            rx.recv().await.expect("first target notification")
        else {
            panic!("expected connection-scoped notification");
        };
        assert_eq!(connection_id, ConnectionId(1));
        assert!(
            rx.try_recv().is_err(),
            "the invalidated blocked target must never enter the channel"
        );
    }

    #[tokio::test]
    async fn list_capture_does_not_allocate_and_same_id_recreation_stays_stale() {
        let (tx, _rx) = mpsc::channel(/*buffer*/ 4);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let observer = AccountSelectionObserver::for_test(Arc::clone(&outgoing));

        for id in 0..128 {
            observer
                .capture_list_registration(&format!("arbitrary-thread-{id}"), ConnectionId(id))
                .await;
        }
        {
            let state = observer.state.lock().await;
            assert_eq!(state.next_generation, 1);
            assert!(state.lifecycle_generations.is_empty());
            assert!(state.route_generations.is_empty());
            assert!(state.connection_generations.is_empty());
            assert!(state.observed_selections.is_empty());
        }

        let stale_scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-0".to_string()),
            session_id: None,
            model: None,
        };
        observer.activate_thread("thread-0").await;
        let stale_registration = observer
            .capture_list_registration("thread-0", ConnectionId(0))
            .await;
        for id in 1..128 {
            observer
                .capture_list_registration("thread-0", ConnectionId(id))
                .await;
        }
        {
            let state = observer.state.lock().await;
            assert_eq!(state.lifecycle_generations.len(), 1);
            assert!(state.route_generations.is_empty());
            assert!(state.connection_generations.is_empty());
            assert!(state.observed_selections.is_empty());
        }

        observer.remove_thread("thread-0").await;
        observer.activate_thread("thread-0").await;
        let recreated = observer
            .capture_list_registration("thread-0", ConnectionId(0))
            .await;
        assert_ne!(
            stale_registration.lifecycle_generation,
            recreated.lifecycle_generation
        );
        assert!(
            observer
                .record_list_response(
                    stale_registration,
                    stale_scope,
                    Some("managed-stale".to_string()),
                    8,
                    SelectionNotificationRoute::for_connection(outgoing, ConnectionId(0)),
                )
                .await
                .is_none(),
            "a captured registration must remain stale after same-ID recreation"
        );
    }

    #[tokio::test]
    async fn saturated_pool_update_send_exits_on_shutdown() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 1);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let first_shutdown = CancellationToken::new();
        assert!(
            send_pool_update_unless_shutdown(
                &outgoing,
                &first_shutdown,
                AccountPoolUpdatedNotification {
                    accounts: Vec::new(),
                    pool_revision: 1,
                },
            )
            .await
        );

        let shutdown = CancellationToken::new();
        let blocked_outgoing = Arc::clone(&outgoing);
        let blocked_shutdown = shutdown.clone();
        let blocked = tokio::spawn(async move {
            send_pool_update_unless_shutdown(
                &blocked_outgoing,
                &blocked_shutdown,
                AccountPoolUpdatedNotification {
                    accounts: Vec::new(),
                    pool_revision: 2,
                },
            )
            .await
        });
        tokio::task::yield_now().await;
        shutdown.cancel();
        assert!(
            !tokio::time::timeout(Duration::from_secs(1), blocked)
                .await
                .expect("blocked pool send must stop on shutdown")
                .expect("pool send task must not panic")
        );
        assert!(rx.recv().await.is_some());
        assert!(
            rx.try_recv().is_err(),
            "cancelled pool update must not enter the saturated channel"
        );
    }

    #[test]
    fn pool_update_watcher_shutdown_cancels_when_last_owner_drops() {
        let token = CancellationToken::new();
        let shutdown = Arc::new(PoolUpdateWatcherShutdown(token.clone()));
        let second_owner = Arc::clone(&shutdown);
        drop(shutdown);
        assert!(!token.is_cancelled());
        drop(second_owner);
        assert!(token.is_cancelled());
    }
}
