use super::*;
use keyring::credential::Credential;
use keyring::credential::CredentialApi;
use keyring::credential::CredentialBuilderApi;
use keyring::credential::CredentialPersistence;
use keyring::mock::MockCredential;
use pretty_assertions::assert_eq;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const FIXTURE_WAIT: Duration = Duration::from_secs(15);
const CHILD_HOME: &str = "CODEX_TEST_REFRESH_ACQUISITION_HOME";

#[derive(Default)]
struct ReadProbe {
    successful_reads: usize,
    captured: Option<mpsc::Sender<Vec<u8>>>,
}

#[derive(Clone, Default)]
struct TestKeyring {
    values: Arc<Mutex<HashMap<String, Arc<MockCredential>>>>,
    probe: Arc<Mutex<ReadProbe>>,
}

struct TestCredential {
    value: Arc<MockCredential>,
    probe: Arc<Mutex<ReadProbe>>,
}

impl CredentialApi for TestCredential {
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        self.value.set_secret(secret)
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        let secret = self.value.get_secret()?;
        let captured = {
            let mut probe = self.probe.lock().expect("read probe lock");
            if probe.captured.is_some() {
                probe.successful_reads += 1;
            }
            if probe.successful_reads == 2 {
                probe.captured.take()
            } else {
                None
            }
        };
        // Storage still holds its file lock here. Only notify: never wait or
        // mutate storage in this callback. B's policy lock is the actual gate.
        if let Some(captured) = captured {
            let _ = captured.send(secret.clone());
        }
        Ok(secret)
    }

    fn delete_credential(&self) -> keyring::Result<()> {
        self.value.delete_credential()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CredentialBuilderApi for TestKeyring {
    fn build(
        &self,
        _target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring::Result<Box<Credential>> {
        assert_eq!(service, "Codex Auth");
        Ok(Box::new(TestCredential {
            value: self
                .values
                .lock()
                .expect("synthetic keyring lock")
                .entry(user.to_string())
                .or_default()
                .clone(),
            probe: self.probe.clone(),
        }))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::ProcessOnly
    }
}

struct RefreshServer {
    release_owner: Option<mpsc::Sender<()>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Drop for RefreshServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Disconnecting also releases the response gate during unwinding.
        self.release_owner.take();
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.expect("loopback responder must finish without a fixture failure");
            }
        }
    }
}

#[derive(Clone, Copy)]
enum OwnerFailure {
    Permanent,
    Commit,
    Transient,
}

#[test]
fn first_acquisition_after_permanent_owner_failure_does_not_post_again() {
    assert_first_acquisition_after_owner_failure(OwnerFailure::Permanent);
}

#[test]
fn first_acquisition_after_uncertain_owner_commit_does_not_post_again() {
    assert_first_acquisition_after_owner_failure(OwnerFailure::Commit);
}

#[test]
fn first_acquisition_after_transient_owner_failure_can_retry() {
    assert_first_acquisition_after_owner_failure(OwnerFailure::Transient);
}

fn assert_first_acquisition_after_owner_failure(scenario: OwnerFailure) {
    let Some(home) = std::env::var_os(CHILD_HOME) else {
        // The keyring builder is process-global. An exact-test subprocess, not
        // a serial annotation, isolates it from unrelated keyring tests.
        let home = tempdir().expect("isolated home");
        let test_name = match scenario {
            OwnerFailure::Permanent => {
                "first_acquisition_after_permanent_owner_failure_does_not_post_again"
            }
            OwnerFailure::Commit => {
                "first_acquisition_after_uncertain_owner_commit_does_not_post_again"
            }
            OwnerFailure::Transient => "first_acquisition_after_transient_owner_failure_can_retry",
        };
        let selector = format!("{}::{test_name}", module_path!());
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                selector.trim_start_matches("codex_login::"),
                "--nocapture",
            ])
            .env_clear()
            .env(CHILD_HOME, home.path())
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("CODEX_HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path())
            .output()
            .expect("run isolated refresh acquisition test");
        assert!(
            output.status.success(),
            "isolated refresh acquisition regression failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    };
    let home = std::path::PathBuf::from(home);
    let keyring = TestKeyring::default();
    keyring::set_default_credential_builder(Box::new(keyring.clone()));

    let server = tiny_http::Server::http("127.0.0.1:0").expect("loopback OAuth server");
    let endpoint = format!("http://{}/oauth/token", server.server_addr());
    let _endpoint = EnvVarGuard::set(REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR, &endpoint);
    let posts = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (arrived_tx, arrived_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (status, body) = match scenario {
        OwnerFailure::Permanent => (401, json!({"error": {"code": "refresh_token_reused"}})),
        OwnerFailure::Commit => (
            200,
            json!({
                "access_token": "refreshed-access",
                "refresh_token": "refreshed-token",
                "id_token": managed_id_token("acquisition@example.com", "workspace-disallowed"),
            }),
        ),
        OwnerFailure::Transient => (503, json!({"error": {"code": "temporarily_unavailable"}})),
    };
    let body = body.to_string();
    let mut responder = RefreshServer {
        release_owner: Some(release_tx),
        stop: stop.clone(),
        worker: Some(thread::spawn({
            let posts = posts.clone();
            move || {
                while !stop.load(Ordering::SeqCst) {
                    let Some(request) = server
                        .recv_timeout(Duration::from_millis(50))
                        .expect("receive loopback request")
                    else {
                        continue;
                    };
                    assert_eq!(request.method(), &tiny_http::Method::Post);
                    assert_eq!(request.url(), "/oauth/token");
                    if posts.fetch_add(1, Ordering::SeqCst) == 0 {
                        arrived_tx.send(()).expect("announce owner's POST");
                        match release_rx.recv_timeout(FIXTURE_WAIT) {
                            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                panic!("broken fixture: owner's response gate was not released")
                            }
                        }
                    }
                    // An accidental second exchange must complete promptly so
                    // the red result is a request-count mismatch, not a timeout.
                    request
                        .respond(
                            tiny_http::Response::from_string(body.clone())
                                .with_status_code(status)
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        "Content-Type",
                                        "application/json",
                                    )
                                    .expect("JSON header"),
                                ),
                        )
                        .expect("respond to refresh request");
                }
            }
        })),
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("setup runtime");
    let (owner, contender, identity) = runtime.block_on(async {
        let mut managers = Vec::new();
        for _ in 0..2 {
            managers.push(
                AuthManager::shared(
                    home.clone(),
                    /*enable_codex_api_key_env*/ false,
                    AuthCredentialsStoreMode::Keyring,
                    /*forced_chatgpt_workspace_id*/ None,
                    /*chatgpt_base_url*/ None,
                    AuthKeyringBackendKind::Direct,
                    crate::test_support::transport_default_auth_route_config(),
                )
                .await,
            );
        }
        let mut credentials = managed_oauth_credentials(
            "acquisition@example.com",
            "workspace-a",
            "synthetic-refresh",
        );
        credentials.last_refresh = Utc::now() - chrono::Duration::days(10);
        let identity = managers[0]
            .upsert_managed_chatgpt_oauth(credentials)
            .await
            .expect("seed managed credentials via public login");
        if matches!(scenario, OwnerFailure::Commit) {
            managers[0].set_forced_chatgpt_workspace_id(Some(vec!["workspace-a".to_string()]));
        }
        (managers.remove(0), managers.remove(0), identity)
    });
    let (owner_tx, owner_rx) = mpsc::channel();
    let owner_thread = thread::spawn({
        let identity = identity.clone();
        move || {
            let result = runtime.block_on(owner.refresh_managed_chatgpt_account(&identity));
            let _ = owner_tx.send(result);
        }
    });
    arrived_rx
        .recv_timeout(FIXTURE_WAIT)
        .expect("broken fixture: A must acquire its lease and reach OAuth");

    let policy_gate = contender
        .forced_chatgpt_workspace_id
        .write()
        .expect("hold B's policy gate");
    let (captured_tx, captured_rx) = mpsc::channel();
    *keyring.probe.lock().expect("arm read probe") = ReadProbe {
        successful_reads: 0,
        captured: Some(captured_tx),
    };
    let (contender_tx, contender_rx) = mpsc::channel();
    let contender_thread = thread::spawn({
        let contender = contender.clone();
        let identity = identity.clone();
        move || {
            // The policy getter is synchronous: B needs its own OS thread so
            // the coordinator can complete A while retaining the policy gate.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("contender runtime");
            let result = runtime.block_on(contender.refresh_managed_chatgpt_account(&identity));
            let _ = contender_tx.send(result);
        }
    });
    let captured: AuthDotJson = serde_json::from_slice(
        &captured_rx
            .recv_timeout(FIXTURE_WAIT)
            .expect("broken fixture: B must capture its second successful keyring read"),
    )
    .expect("decode B's captured initial document");
    // With no tombstones, read 1 resumes removals; read 2 is B's initial
    // snapshot. A is still HTTP-gated and cannot interleave another read.
    let initial = row(&captured, &identity).expect("B's initial account");
    assert!(initial.tombstone.is_none());
    assert!(initial.refresh_failure.is_none());
    assert!(initial.credential_revision > 0);
    assert_eq!(initial.tokens.refresh_token, "synthetic-refresh");
    let lease = initial.mutation_lease.as_ref().expect("A's live lease");
    assert_eq!(lease.kind, ManagedChatgptMutationKind::Refresh);
    assert_eq!(lease.expected_revision, initial.credential_revision);
    assert_eq!(lease.expected_refresh_token, initial.tokens.refresh_token);
    assert!(lease.expires_at > Utc::now());

    responder
        .release_owner
        .take()
        .expect("owner response gate")
        .send(())
        .expect("release A's response");
    let owner_result = owner_rx
        .recv_timeout(FIXTURE_WAIT)
        .expect("broken fixture: A must finish persisting its failure");
    owner_thread.join().expect("owner thread");
    match (&owner_result, scenario) {
        (Err(RefreshTokenError::Permanent(error)), OwnerFailure::Permanent) => {
            assert_eq!(error.reason, RefreshTokenFailedReason::Exhausted);
        }
        (Err(RefreshTokenError::Transient(_)), OwnerFailure::Commit | OwnerFailure::Transient) => {}
        _ => panic!("A must return the expected refresh failure: {owner_result:?}"),
    }
    let committed = load_auth_dot_json(
        &home,
        AuthCredentialsStoreMode::Keyring,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load A's committed failure")
    .expect("stored managed pool");
    let committed_account = row(&committed, &identity).expect("A's committed account");
    assert!(committed_account.mutation_lease.is_none());
    assert_eq!(
        (
            &committed_account.credential_revision,
            &committed_account.tokens
        ),
        (&initial.credential_revision, &initial.tokens),
    );
    let failure = committed_account
        .refresh_failure
        .as_ref()
        .expect("A's durable failure");
    assert_eq!(
        failure.permanent,
        matches!(scenario, OwnerFailure::Permanent)
    );
    let expected_reason = match scenario {
        OwnerFailure::Permanent => "refresh_token_reused",
        OwnerFailure::Commit => "token_refresh_commit_failed",
        OwnerFailure::Transient => "token_refresh_unavailable",
    };
    assert_eq!(failure.reason_code.as_deref(), Some(expected_reason));
    assert_eq!(
        failure.operation_id.as_deref(),
        Some(lease.operation_id.as_str())
    );

    drop(policy_gate);
    let contender_result = contender_rx
        .recv_timeout(FIXTURE_WAIT)
        .expect("broken fixture: B must finish, including any accidental second POST");
    contender_thread.join().expect("contender thread");
    assert_eq!(
        posts.load(Ordering::SeqCst),
        if matches!(scenario, OwnerFailure::Transient) {
            2
        } else {
            1
        },
        "B may make a second OAuth POST only after an ordinary transient failure",
    );
    match (&owner_result, &contender_result) {
        (
            Err(RefreshTokenError::Permanent(owner)),
            Err(RefreshTokenError::Permanent(contender)),
        ) => {
            assert_eq!(contender, owner);
        }
        (
            Err(RefreshTokenError::Transient(owner)),
            Err(RefreshTokenError::Transient(contender)),
        ) => {
            assert_eq!(contender.kind(), owner.kind());
        }
        _ => panic!("B must return the expected refresh failure: {contender_result:?}"),
    }
    let after = load_auth_dot_json(
        &home,
        AuthCredentialsStoreMode::Keyring,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load final managed pool")
    .expect("stored managed pool");
    if matches!(scenario, OwnerFailure::Transient) {
        let after_account = row(&after, &identity).expect("B's committed retry failure");
        assert!(after_account.mutation_lease.is_none());
        assert_eq!(
            (&after_account.credential_revision, &after_account.tokens),
            (&initial.credential_revision, &initial.tokens),
        );
        let retry_failure = after_account.refresh_failure.as_ref().expect("B's failure");
        assert_eq!(retry_failure.reason_code.as_deref(), Some(expected_reason));
        assert_ne!(retry_failure.operation_id, failure.operation_id);
    } else {
        assert_eq!(after, committed, "B must not replace A's durable failure");
    }
}
