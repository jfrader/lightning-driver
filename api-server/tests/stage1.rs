use actix_web::{
    http::{header, StatusCode},
    test,
};
use api_server::{
    app::application,
    journal::{Claimed, Journal, JournalError, Resource},
    runtime::{Runtime, StartupError},
};
use chrono::Utc;
use lightning_client::{
    model::{Operation, OperationState},
    settings::Settings,
};
use rusqlite::Connection;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Output, Stdio},
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use uuid::Uuid;
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};
use zeroize::Zeroizing;

const HOST: &str = "manager.example.invalid";
const ORIGIN: &str = "https://manager.example.invalid";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(15);

struct Fixture {
    directory: tempfile::TempDir,
    config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp/opencode")
            .unwrap();
        let config = directory.path().join("synthetic config.toml");
        std::fs::write(
            &config,
            format!(
                r#"nodes = []
[api]
bind = "127.0.0.1:0"
public_origin = "{ORIGIN}"
rp_id = "{HOST}"
database = "state.sqlite"
invoice_key_file = "pending-invoice.key"
"#
            ),
        )
        .unwrap();
        Self { directory, config }
    }
    fn settings(&self) -> Settings {
        Settings::load(&self.config).unwrap()
    }
    fn database(&self) -> PathBuf {
        self.directory.path().join("state.sqlite")
    }
}

async fn cli(config: &Path, action: &str, confirmed: bool) -> Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_api-server"));
    command
        .kill_on_drop(true)
        .args(["auth", action, "--config"])
        .arg(config);
    if confirmed {
        command.arg("--confirm-reset-authentication");
    }
    tokio::time::timeout(PROCESS_TIMEOUT, command.output())
        .await
        .expect("CLI process exceeded deadline and was killed")
        .expect("CLI process could not start")
}

fn token(output: &Output) -> Zeroizing<String> {
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let text = std::str::from_utf8(&output.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    let token = text.trim_end_matches('\n');
    assert_eq!(token.len(), 64);
    assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
    Zeroizing::new(token.to_owned())
}

fn get(path: &str) -> test::TestRequest {
    test::TestRequest::get()
        .uri(path)
        .insert_header((header::HOST, HOST))
}
fn post(path: &str) -> test::TestRequest {
    test::TestRequest::post()
        .uri(path)
        .insert_header((header::HOST, HOST))
        .insert_header((header::ORIGIN, ORIGIN))
}
fn browser_json<T: Serialize>(credential: T) -> Value {
    let mut value = serde_json::to_value(credential).unwrap();
    let object = value.as_object_mut().unwrap();
    if let Some(extensions) = object.remove("extensions") {
        object.insert("clientExtensionResults".into(), extensions);
    }
    value
}

#[actix_web::test]
async fn host_cli_real_application_restart_and_recovery_share_one_persistent_identity() {
    let fixture = Fixture::new();
    let settings = fixture.settings();
    assert_eq!(settings.api.database, fixture.database());
    let runtime = Runtime::prepare(&settings).await.unwrap();
    assert!(matches!(
        Runtime::prepare(&settings).await,
        Err(StartupError::Instance)
    ));
    let identity = runtime.state.journal.authentication().await.unwrap();
    let app = test::init_service(application(runtime.state.clone())).await;
    let issued = cli(&fixture.config, "enrollment", false).await;
    let enrollment = token(&issued);
    let connection = Connection::open(fixture.database()).unwrap();
    let stored: Vec<u8> = connection
        .query_row("SELECT token_hash FROM enrollment", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stored, Sha256::digest(enrollment.as_bytes()).to_vec());
    assert_eq!(stored.len(), 32);
    drop(connection);
    let response = test::call_service(&app, get("/api/v1/auth/bootstrap").to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let guest = response
        .response()
        .cookies()
        .find(|cookie| cookie.name() == "__Host-ld_preauth")
        .unwrap()
        .into_owned();
    assert_eq!(guest.secure(), Some(true));
    assert_eq!(guest.http_only(), Some(true));
    let bootstrap: Value = test::read_body_json(response).await;
    assert_eq!(bootstrap["enrollment_available"], true);
    let response = test::call_service(
        &app,
        post("/api/v1/auth/enrollment/start")
            .cookie(guest.clone())
            .insert_header(("X-CSRF-Token", bootstrap["csrf_token"].as_str().unwrap()))
            .set_json(json!({"enrollment_token":enrollment.as_str()}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: Value = test::read_body_json(response).await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = authenticator
        .do_registration(
            ORIGIN.parse().unwrap(),
            serde_json::from_value::<CreationChallengeResponse>(challenge["options"].clone())
                .unwrap(),
        )
        .unwrap();
    let response=test::call_service(&app,post("/api/v1/auth/enrollment/finish").cookie(guest).insert_header(("X-CSRF-Token",bootstrap["csrf_token"].as_str().unwrap())).set_json(json!({"challenge_id":challenge["challenge_id"],"credential":browser_json(credential)})).to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let old_cookie = response
        .response()
        .cookies()
        .find(|cookie| cookie.name() == "__Host-ld_session")
        .unwrap()
        .into_owned();
    let session: Value = test::read_body_json(response).await;
    assert_eq!(session["authenticated"], true);
    assert!(matches!(
        runtime
            .state
            .journal
            .claim_enrollment(enrollment, Utc::now())
            .await,
        Err(JournalError::Revoked)
    ));
    let response = test::call_service(
        &app,
        get("/api/v1/config")
            .cookie(old_cookie.clone())
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let policy: Value = test::read_body_json(response).await;
    assert_eq!(policy["reauth"]["mode"], "every_operation");
    assert!(policy.get("database").is_none());
    assert!(policy.get("invoice_key_file").is_none());
    assert!(policy.get("nodes").is_none());
    let response = test::call_service(
        &app,
        get("/api/v1/nodes").cookie(old_cookie.clone()).to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let fleet: Value = test::read_body_json(response).await;
    assert_eq!(fleet["items"], json!([]));
    assert_eq!(fleet["stale"], false);

    let fixtures: Value = serde_json::from_str(include_str!("fixtures/api-examples.json")).unwrap();
    let mut operation: Operation =
        serde_json::from_value(fixtures["fixtures"]["operation_review"]["value"].clone()).unwrap();
    operation.id = Uuid::new_v4();
    operation.review.operation_id = operation.id;
    operation.review.expires_at = Utc::now() + chrono::Duration::minutes(5);
    runtime
        .state
        .journal
        .create(
            operation.clone(),
            Uuid::new_v4(),
            vec![Resource::Wallet],
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        runtime
            .state
            .journal
            .claim(
                operation.id,
                operation.node_id.clone(),
                operation.review.digest.clone(),
                operation.review.policy_revision.clone(),
                identity.1,
                Utc::now()
            )
            .await
            .unwrap(),
        Claimed::New(_)
    ));
    assert!(matches!(
        Runtime::prepare(&settings).await,
        Err(StartupError::Instance)
    ));
    assert_eq!(
        runtime.state.journal.get(operation.id).await.unwrap().state,
        OperationState::Dispatching
    );
    assert!(runtime.state.auth.manager.login_available().await.unwrap());
    drop(app);
    drop(runtime);

    let runtime = Runtime::prepare(&fixture.settings()).await.unwrap();
    assert_eq!(
        runtime.state.journal.authentication().await.unwrap(),
        identity
    );
    assert!(runtime.state.auth.manager.login_available().await.unwrap());
    assert_eq!(
        runtime.state.journal.get(operation.id).await.unwrap().state,
        OperationState::Unknown
    );
    let app = test::init_service(application(runtime.state.clone())).await;
    let response =
        test::call_service(&app, get("/api/v1/session").cookie(old_cookie).to_request()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = test::call_service(&app, get("/api/v1/auth/bootstrap").to_request()).await;
    let guest = response
        .response()
        .cookies()
        .find(|cookie| cookie.name() == "__Host-ld_preauth")
        .unwrap()
        .into_owned();
    let bootstrap: Value = test::read_body_json(response).await;
    assert_eq!(bootstrap["login_available"], true);
    let response = test::call_service(
        &app,
        post("/api/v1/auth/passkey/start")
            .cookie(guest.clone())
            .insert_header(("X-CSRF-Token", bootstrap["csrf_token"].as_str().unwrap()))
            .set_json(json!({}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: Value = test::read_body_json(response).await;
    let credential = authenticator
        .do_authentication(
            ORIGIN.parse().unwrap(),
            serde_json::from_value::<RequestChallengeResponse>(challenge["options"].clone())
                .unwrap(),
        )
        .unwrap();
    let response=test::call_service(&app,post("/api/v1/auth/passkey/finish").cookie(guest).insert_header(("X-CSRF-Token",bootstrap["csrf_token"].as_str().unwrap())).set_json(json!({"challenge_id":challenge["challenge_id"],"credential":browser_json(credential)})).to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let live_cookie = response
        .response()
        .cookies()
        .find(|cookie| cookie.name() == "__Host-ld_session")
        .unwrap()
        .into_owned();
    let _: Value = test::read_body_json(response).await;

    let response = test::call_service(&app, get("/api/v1/auth/bootstrap").to_request()).await;
    let guest = response
        .response()
        .cookies()
        .find(|cookie| cookie.name() == "__Host-ld_preauth")
        .unwrap()
        .into_owned();
    let bootstrap: Value = test::read_body_json(response).await;
    let response = test::call_service(
        &app,
        post("/api/v1/auth/passkey/start")
            .cookie(guest.clone())
            .insert_header(("X-CSRF-Token", bootstrap["csrf_token"].as_str().unwrap()))
            .set_json(json!({}))
            .to_request(),
    )
    .await;
    let pending: Value = test::read_body_json(response).await;
    let pending_credential = authenticator
        .do_authentication(
            ORIGIN.parse().unwrap(),
            serde_json::from_value::<RequestChallengeResponse>(pending["options"].clone()).unwrap(),
        )
        .unwrap();

    let refused = cli(&fixture.config, "recovery", false).await;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--confirm-reset-authentication"));
    assert_eq!(
        runtime.state.journal.authentication().await.unwrap(),
        identity
    );
    assert!(runtime.state.auth.manager.login_available().await.unwrap());
    let recovered = cli(&fixture.config, "recovery", true).await;
    let recovery_token = token(&recovered);
    let current = runtime.state.journal.authentication().await.unwrap();
    assert_eq!(current.0, identity.0);
    assert_eq!(current.1, identity.1 + 1);
    assert!(!runtime.state.auth.manager.login_available().await.unwrap());
    let response = test::call_service(
        &app,
        get("/api/v1/session").cookie(live_cookie).to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response=test::call_service(&app,post("/api/v1/auth/passkey/finish").cookie(guest).insert_header(("X-CSRF-Token",bootstrap["csrf_token"].as_str().unwrap())).set_json(json!({"challenge_id":pending["challenge_id"],"credential":browser_json(pending_credential)})).to_request()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.response().cookies().next().is_none());
    assert_eq!(
        runtime
            .state
            .journal
            .claim_enrollment(recovery_token.clone(), Utc::now())
            .await
            .unwrap(),
        current.1
    );
    assert!(matches!(
        runtime
            .state
            .journal
            .claim_enrollment(recovery_token, Utc::now())
            .await,
        Err(JournalError::Revoked)
    ));
    assert_eq!(
        runtime.state.journal.get(operation.id).await.unwrap().state,
        OperationState::Unknown
    );
}

#[actix_web::test]
async fn legacy_routes_and_unauthenticated_collections_cannot_grant_sessions_or_fake_success() {
    let fixture = Fixture::new();
    let runtime = Runtime::prepare(&fixture.settings()).await.unwrap();
    let app = test::init_service(application(runtime.state.clone())).await;
    for path in ["/login", "/api/pay", "/api/invoice", "/api/v1/session"] {
        let response = test::call_service(
            &app,
            post(path)
                .set_json(json!({"password":"SYNTHETIC_NOT_A_PASSWORD"}))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert!(response.response().cookies().next().is_none());
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["error"]["code"], "not_found");
        assert!(!body.to_string().contains("SYNTHETIC_NOT_A_PASSWORD"));
    }
    for path in ["/api/info", "/api/balance"] {
        let response = test::call_service(&app, get(path).to_request()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    for resource in [
        "info",
        "balances",
        "invoices",
        "payments",
        "peers",
        "channels",
        "transactions",
        "fee-estimates",
    ] {
        let response = test::call_service(
            &app,
            get(&format!("/api/v1/nodes/lnd-lab/{resource}")).to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["error"]["code"], "session_required");
    }
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/auth/bootstrap")
            .insert_header((header::HOST, "evil.example.invalid"))
            .insert_header(("X-Forwarded-Host", HOST))
            .insert_header(("X-Forwarded-Proto", "https"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = test::call_service(
        &app,
        get("/api/v1/auth/bootstrap")
            .insert_header((
                header::ORIGIN,
                header::HeaderValue::from_bytes(&[0xff]).unwrap(),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = test::call_service(
        &app,
        get("/api/v1/session")
            .cookie(actix_web::cookie::Cookie::new(
                "session",
                "SYNTHETIC_LEGACY_COOKIE",
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri("/logout")
            .insert_header((header::HOST, HOST))
            .insert_header((header::ORIGIN, ORIGIN))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response.response().cookies().next().is_none());
}

#[tokio::test]
async fn cli_rejects_invalid_configuration_without_creating_or_resetting_storage() {
    let fixture = Fixture::new();
    let invalid = std::fs::read_to_string(&fixture.config)
        .unwrap()
        .replace(ORIGIN, "http://manager.example.invalid");
    std::fs::write(&fixture.config, invalid).unwrap();
    let output = cli(&fixture.config, "enrollment", false).await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!fixture.database().exists());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("pending-invoice.key"));
}

#[tokio::test]
async fn legacy_password_configuration_is_not_a_supported_bootstrap() {
    let fixture = Fixture::new();
    let mut configuration = std::fs::read_to_string(&fixture.config).unwrap();
    configuration.push_str("password_hash = 'SYNTHETIC_LEGACY_HASH_NOT_SUPPORTED'\n");
    std::fs::write(&fixture.config, configuration).unwrap();
    let output = cli(&fixture.config, "enrollment", false).await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!fixture.database().exists());
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("SYNTHETIC_LEGACY_HASH_NOT_SUPPORTED")
    );
}

#[tokio::test]
async fn unsafe_state_directory_is_rejected_before_initializing_storage() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    std::fs::set_permissions(
        fixture.directory.path(),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let output = cli(&fixture.config, "enrollment", false).await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!fixture.database().exists());
    assert!(matches!(
        Runtime::prepare(&fixture.settings()).await,
        Err(StartupError::Storage)
    ));
    std::fs::set_permissions(
        fixture.directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
}

#[tokio::test]
async fn finite_binary_serve_smoke_and_parallel_host_cli_exit_without_leaking_a_server() {
    let fixture = Fixture::new();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_api-server"))
        .args(["serve", "--config"])
        .arg(&fixture.config)
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let line = tokio::time::timeout(PROCESS_TIMEOUT, lines.next_line())
        .await
        .expect("server readiness deadline")
        .unwrap()
        .expect("server exited before readiness");
    let address: SocketAddr = line
        .strip_prefix("API listening on ")
        .unwrap()
        .parse()
        .unwrap();
    assert!(address.ip().is_loopback());
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PROCESS_TIMEOUT)
        .build()
        .unwrap();
    let response = client
        .get(format!("http://{address}/api/v1/auth/bootstrap"))
        .header("Host", HOST)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .contains("Secure"));
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["login_available"], false);
    let output = cli(&fixture.config, "enrollment", false).await;
    let enrollment = token(&output);
    child.kill().await.unwrap();
    assert!(child.try_wait().unwrap().is_some());
    let journal = Journal::open(fixture.database()).await.unwrap();
    assert!(journal.enrollment_available(Utc::now()).await.unwrap());
    journal
        .claim_enrollment(enrollment, Utc::now())
        .await
        .unwrap();
    drop(lines);
}
