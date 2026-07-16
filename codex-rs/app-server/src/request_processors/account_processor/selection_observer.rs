use super::*;

mod lifecycle;

pub(super) use lifecycle::PoolUpdateWatcherShutdown;
#[cfg(test)]
pub(super) use lifecycle::send_pool_update_unless_shutdown;
#[cfg(test)]
pub(super) use lifecycle::should_emit_pool_update;
pub(super) use lifecycle::start_pool_update_watcher;

#[derive(Clone)]
struct SelectionNotificationTarget {
    connection_id: ConnectionId,
    validity: CancellationToken,
}

#[derive(Clone)]
pub(super) struct SelectionNotificationRoute {
    outgoing: Arc<OutgoingMessageSender>,
    targets: Arc<Vec<SelectionNotificationTarget>>,
}

impl SelectionNotificationRoute {
    pub(super) fn from_thread(outgoing: &ThreadScopedOutgoingMessageSender) -> Self {
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

    pub(super) fn for_connection(
        outgoing: Arc<OutgoingMessageSender>,
        connection_id: ConnectionId,
    ) -> Self {
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

    pub(super) async fn send(&self, notification: AccountSelectionUpdatedNotification) {
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
    pub(super) fn connection_ids_for_test(&self) -> Vec<ConnectionId> {
        self.targets
            .iter()
            .map(|target| target.connection_id)
            .collect()
    }
}

#[derive(Clone)]
pub(super) struct ObservedSelection {
    pub(super) scope: ManagedChatgptSelectionScope,
    pub(super) selected_account_id: Option<String>,
    pub(super) selection_revision: u64,
    pub(super) lifecycle_generation: u64,
    pub(super) routes: Vec<SelectionNotificationRoute>,
}

struct EventRouteInvalidations {
    thread_id: String,
    connection_ids: std::sync::Mutex<HashSet<ConnectionId>>,
}

pub(super) struct AccountSelectionObserverState {
    pub(super) next_generation: u64,
    pub(super) observed_selections: HashMap<String, ObservedSelection>,
    pub(super) lifecycle_generations: HashMap<String, u64>,
    pub(super) route_generations: HashMap<(String, ConnectionId), u64>,
    pub(super) connection_generations: HashMap<ConnectionId, u64>,
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
pub(super) struct AccountSelectionRegistration {
    pub(super) thread_id: String,
    pub(super) lifecycle_generation: u64,
    pub(super) route_generation: Option<(ConnectionId, Option<u64>)>,
    pub(super) connection_generation: Option<(ConnectionId, Option<u64>)>,
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
    pub(super) state: Arc<Mutex<AccountSelectionObserverState>>,
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

    pub(super) async fn capture_event_registration(
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

    pub(super) async fn capture_list_registration(
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

    pub(super) async fn record_list_response(
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

    pub(super) async fn record_if_changed(
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

impl AccountRequestProcessor {
    pub(crate) fn selection_observer(&self) -> AccountSelectionObserver {
        AccountSelectionObserver {
            state: Arc::clone(&self.selection_observer_state),
            event_registration: None,
        }
    }

    pub(super) async fn selection_scope_for_list(
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

    pub(super) fn selection_scope_from_observed(
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
}
