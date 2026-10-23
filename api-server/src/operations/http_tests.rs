use super::*;
use crate::{app::application, state::ApplicationState};
use actix_web::{
    cookie::Cookie,
    http::{header, StatusCode},
    test,
};
use lightning_client::settings::{NodeSettings, Settings};
use serde_json::{json, Value};

#[path = "journey_tests.rs"]
mod journeys;
#[path = "nostr_http_tests.rs"]
mod nostr;

const HOST: &str = "manager.example.invalid";
const ORIGIN: &str = "https://manager.example.invalid";
static EMITTED: AtomicUsize = AtomicUsize::new(0);

struct Browser {
    cookie: Cookie<'static>,
    csrf: String,
    authenticator: WebauthnAuthenticator<SoftPasskey>,
}
struct HttpFixture {
    _directory: tempfile::TempDir,
    settings: Settings,
    state: ApplicationState,
    fake: Arc<CountingFake>,
}

impl HttpFixture {
    async fn new() -> Self {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let examples: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/api-examples.json")).unwrap();
        let policy: NodePolicy =
            serde_json::from_value(examples["fixtures"]["node_policy"]["value"].clone()).unwrap();
        let node: NodeSettings = serde_json::from_value(json!({
            "id":"synthetic", "label":"Synthetic", "backend":"lnd_rest",
            "endpoint":"https://never-contact.example.invalid",
            "certificate_file":"SYNTHETIC_CERT_NEVER_OPENED", "credential_file":"SYNTHETIC_CREDENTIAL_NEVER_OPENED",
            "expected_pubkey":peer(), "network":"regtest", "read_only":false, "policy":policy.limits,
            "peer_policy":{"allowed_hosts":["peer.example.invalid"],"allowed_ports":[9735]}
        })).unwrap();
        let settings = Settings {
            api: ApiSettings {
                bind: "127.0.0.1:0".parse().unwrap(),
                public_origin: ORIGIN.parse().unwrap(),
                rp_id: HOST.into(),
                database: directory.path().join("journal.sqlite"),
                invoice_key_file: directory.path().join("invoice.key"),
                allow_insecure_loopback: false,
                client_identity: Default::default(),
                reauth: ReauthPolicy::default(),
                limits: Limits::default(),
            },
            nodes: vec![node],
        };
        let state = ApplicationState::new(
            &settings,
            Journal::open(settings.api.database.clone()).await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            state.engine.unavailable("synthetic"),
            Some(ErrorCode::NotConfigured)
        );
        let config = NodeConfig {
            binding: NodeBinding {
                node_id: "synthetic".into(),
                network: VerifiedNetwork::Regtest,
                identity_pubkey: peer(),
                identity_revision: "synthetic-verified-connection".into(),
            },
            generation: Uuid::new_v4(),
            backend: Backend::LndRest,
            policy: state.registry.get("synthetic").unwrap().policy.clone(),
            peer_policy: settings.nodes[0].peer_policy.clone().unwrap(),
            reauth_mode: ReauthMode::EveryOperation,
            capabilities: Capabilities::uniform(None),
            review_seconds: 300,
            freshness_seconds: 60,
        };
        let fake = Arc::new(CountingFake {
            mutations: AtomicUsize::new(0),
            observations: AtomicUsize::new(0),
            preparations: AtomicUsize::new(0),
            config,
            clock: Arc::new(TestClock(Mutex::new(Utc::now()))),
            execute: Mutex::new(Script::Success),
            scripts: Mutex::new(VecDeque::new()),
            effects: Mutex::new(HashMap::new()),
            execution_barrier: Mutex::new(None),
            prerequisites: Mutex::new(None),
        });
        let mut fixture = Self {
            _directory: directory,
            settings,
            state,
            fake,
        };
        fixture.inject();
        fixture
    }
    fn inject(&mut self) {
        let mut config = self.fake.config.clone();
        config.policy = self.state.registry.get("synthetic").unwrap().policy.clone();
        Arc::make_mut(&mut self.state.engine.unavailable).remove("synthetic");
        Arc::make_mut(&mut self.state.engine.nodes).insert(
            "synthetic".into(),
            Arc::new(Mutex::new(Some(PinnedNode {
                config,
                adapter: self.fake.clone(),
            }))),
        );
    }
    async fn reopen(&mut self) {
        self.state = ApplicationState::new(
            &self.settings,
            Journal::open(self.settings.api.database.clone())
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        self.inject();
        self.state.engine.recover().await.unwrap();
    }
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
fn authenticated(request: test::TestRequest, browser: &Browser) -> test::TestRequest {
    request
        .cookie(browser.cookie.clone())
        .insert_header(("X-CSRF-Token", browser.csrf.as_str()))
}
fn browser_json(credential: impl Serialize) -> Value {
    let mut value = serde_json::to_value(credential).unwrap();
    let object = value.as_object_mut().unwrap();
    if let Some(extensions) = object.remove("extensions") {
        object.insert("clientExtensionResults".into(), extensions);
    }
    value
}

async fn call(
    state: &ApplicationState,
    request: test::TestRequest,
    schema: &str,
) -> (StatusCode, Value, Option<Cookie<'static>>) {
    let app = test::init_service(application(state.clone())).await;
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let cookie = response
        .response()
        .cookies()
        .next()
        .map(|cookie| cookie.into_owned());
    let bytes = test::read_body(response).await;
    let value: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    let schema = if status.is_client_error() || status.is_server_error() {
        "ErrorResponse"
    } else {
        schema
    };
    if !value.is_null() {
        if let Ok(directory) = std::env::var("HTTP_EVIDENCE_DIR") {
            std::fs::create_dir_all(&directory).unwrap();
            let index = EMITTED.fetch_add(1, Ordering::SeqCst);
            std::fs::write(
                std::path::Path::new(&directory).join(format!("{index:04}.json")),
                serde_json::to_vec_pretty(&json!({"schema":schema,"value":value})).unwrap(),
            )
            .unwrap();
        }
    }
    (status, value, cookie)
}

async fn login(
    state: &ApplicationState,
    existing: Option<WebauthnAuthenticator<SoftPasskey>>,
) -> Browser {
    let (status, bootstrap, cookie) =
        call(state, get("/api/v1/auth/bootstrap"), "AuthBootstrap").await;
    assert_eq!(status, StatusCode::OK);
    let guest = cookie.unwrap();
    let csrf = bootstrap["csrf_token"].as_str().unwrap();
    let mut authenticator =
        existing.unwrap_or_else(|| WebauthnAuthenticator::new(SoftPasskey::new(true)));
    let available = state.auth.manager.login_available().await.unwrap();
    let (purpose, credential, challenge_id) = if available {
        let (status, challenge, _) = call(
            state,
            post("/api/v1/auth/passkey/start")
                .cookie(guest.clone())
                .insert_header(("X-CSRF-Token", csrf))
                .set_json(json!({})),
            "AuthenticationChallenge",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let credential = authenticator
            .do_authentication(
                ORIGIN.parse().unwrap(),
                serde_json::from_value(challenge["options"].clone()).unwrap(),
            )
            .unwrap();
        (
            "passkey",
            browser_json(credential),
            challenge["challenge_id"].clone(),
        )
    } else {
        let token = state
            .journal
            .issue_enrollment(Utc::now(), std::time::Duration::from_secs(60), false)
            .await
            .unwrap();
        let (status, challenge, _) = call(
            state,
            post("/api/v1/auth/enrollment/start")
                .cookie(guest.clone())
                .insert_header(("X-CSRF-Token", csrf))
                .set_json(json!({"enrollment_token":token.as_str()})),
            "RegistrationChallenge",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let credential = authenticator
            .do_registration(
                ORIGIN.parse().unwrap(),
                serde_json::from_value(challenge["options"].clone()).unwrap(),
            )
            .unwrap();
        (
            "enrollment",
            browser_json(credential),
            challenge["challenge_id"].clone(),
        )
    };
    let (status, session, cookie) = call(
        state,
        post(&format!("/api/v1/auth/{purpose}/finish"))
            .cookie(guest)
            .insert_header(("X-CSRF-Token", csrf))
            .set_json(json!({"challenge_id":challenge_id,"credential":credential})),
        "Session",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    Browser {
        cookie: cookie.unwrap(),
        csrf: session["csrf_token"].as_str().unwrap().into(),
        authenticator,
    }
}

fn path(operation: &Value, suffix: &str) -> String {
    format!(
        "/api/v1/nodes/synthetic/operations/{}{suffix}",
        operation["id"].as_str().unwrap()
    )
}
async fn create(f: &HttpFixture, browser: &Browser, kind: OperationKind, key: Uuid) -> Value {
    let (status, operation, _) = call(
        &f.state,
        authenticated(post("/api/v1/nodes/synthetic/operations"), browser)
            .insert_header(("Idempotency-Key", key.to_string()))
            .set_json(request(kind, Utc::now())),
        "Operation",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{operation}");
    operation
}

#[actix_web::test]
async fn one_list_request_observes_only_the_node_cap_and_cursor_never_observes() {
    let f = HttpFixture::new().await;
    let browser = login(&f.state, None).await;
    *f.fake.execute.lock().unwrap() = Script::Lost;
    for index in 0..LIST_RECONCILIATION_CAP + 2 {
        let mut input = request(OperationKind::CreateInvoice, Utc::now());
        if let OperationRequest::CreateInvoice(params) = &mut input {
            params.description = format!("list invoice {index}");
        }
        let (status, op, _) = call(
            &f.state,
            authenticated(post("/api/v1/nodes/synthetic/operations"), &browser)
                .insert_header(("Idempotency-Key", Uuid::new_v4().to_string()))
                .set_json(input),
            "Operation",
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{op}");
        confirm(&f.state, &browser, &op, Value::Null).await;
    }
    let (status, page, _) = call(
        &f.state,
        authenticated(get("/api/v1/nodes/synthetic/operations?limit=1"), &browser),
        "OperationsPage",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        f.fake.counts(),
        (LIST_RECONCILIATION_CAP + 2, LIST_RECONCILIATION_CAP)
    );
    let cursor = page["next_cursor"].as_str().unwrap();
    let url = url::Url::parse_with_params(
        "https://manager.example.invalid/api/v1/nodes/synthetic/operations",
        [("limit", "1"), ("cursor", cursor)],
    )
    .unwrap();
    let (status, page, _) = call(
        &f.state,
        authenticated(
            get(&format!("{}?{}", url.path(), url.query().unwrap())),
            &browser,
        ),
        "OperationsPage",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(f.fake.counts().1, LIST_RECONCILIATION_CAP);
}
async fn grant(state: &ApplicationState, browser: &mut Browser, operation: &Value) -> Value {
    let digest = &operation["review"]["digest"];
    let (status, start, _) = call(
        state,
        authenticated(post(&path(operation, "/authorize")), browser)
            .set_json(json!({"review_digest":digest})),
        "AuthorizationStart",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{start}");
    let credential = browser
        .authenticator
        .do_authentication(
            ORIGIN.parse().unwrap(),
            serde_json::from_value(start["challenge"]["options"].clone()).unwrap(),
        )
        .unwrap();
    let (status, authorization, _) = call(state, authenticated(post(&path(operation, "/authorize/finish")), browser).set_json(json!({"review_digest":digest,"challenge_id":start["challenge"]["challenge_id"],"credential":browser_json(credential)})), "OperationAuthorization").await;
    assert_eq!(status, StatusCode::OK, "{authorization}");
    authorization["authorization_id"].clone()
}
async fn confirm(
    state: &ApplicationState,
    browser: &Browser,
    operation: &Value,
    authorization: Value,
) -> (StatusCode, Value) {
    let (status, value, _) = call(
        state,
        authenticated(post(&path(operation, "/confirm")), browser).set_json(
            json!({"review_digest":operation["review"]["digest"],"authorization_id":authorization}),
        ),
        "Operation",
    )
    .await;
    (status, value)
}

#[actix_web::test]
async fn a_claim_that_reaches_the_node_drops_its_cached_reads() {
    let f = HttpFixture::new().await;
    let browser = login(&f.state, None).await;
    assert_eq!(
        f.state.registry.seed_read_for_test("synthetic", 64).await,
        64
    );

    let operation = create(&f, &browser, OperationKind::NewAddress, Uuid::new_v4()).await;
    let (status, confirmed) = confirm(&f.state, &browser, &operation, Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    assert_eq!(
        f.state.registry.retained_bytes(),
        0,
        "a claim that reached the node drops that node's cached reads"
    );
}

#[actix_web::test]
async fn sensitive_and_low_risk_use_production_factory_and_one_shot_claims() {
    let f = HttpFixture::new().await;
    let mut browser = login(&f.state, None).await;
    for kind in [OperationKind::SendOnchain, OperationKind::NewAddress] {
        let key = Uuid::new_v4();
        let operation = create(&f, &browser, kind, key).await;
        let (status, replay, _) = call(
            &f.state,
            authenticated(post("/api/v1/nodes/synthetic/operations"), &browser)
                .insert_header(("Idempotency-Key", key.to_string()))
                .set_json(request(kind, Utc::now())),
            "Operation",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay["id"], operation["id"]);
        if kind == OperationKind::SendOnchain {
            let mut changed = serde_json::to_value(request(kind, Utc::now())).unwrap();
            changed["params"]["amount_sat"] = json!("12345");
            let (status, error, _) = call(
                &f.state,
                authenticated(post("/api/v1/nodes/synthetic/operations"), &browser)
                    .insert_header(("Idempotency-Key", key.to_string()))
                    .set_json(changed),
                "Operation",
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(error["error"]["code"], "idempotency_conflict");
        }
        let authorization = if kind == OperationKind::SendOnchain {
            let (status, error) = confirm(&f.state, &browser, &operation, Value::Null).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(error["error"]["code"], "reauth_required");
            grant(&f.state, &mut browser, &operation).await
        } else {
            let (status, error) =
                confirm(&f.state, &browser, &operation, json!(Uuid::new_v4())).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(error["error"]["code"], "authorization_invalid");
            let (status, error, _) = call(
                &f.state,
                authenticated(post(&path(&operation, "/authorize")), &browser)
                    .set_json(json!({"review_digest":operation["review"]["digest"]})),
                "AuthorizationStart",
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(error["error"]["code"], "authorization_not_required");
            Value::Null
        };
        let before = f.fake.counts().0;
        assert_eq!(
            confirm(&f.state, &browser, &operation, authorization.clone())
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            confirm(&f.state, &browser, &operation, authorization)
                .await
                .0,
            StatusCode::OK
        );
        let (status, observed, _) = call(
            &f.state,
            authenticated(get(&path(&operation, "")), &browser),
            "Operation",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(observed["state"], "succeeded");
        assert_eq!(f.fake.counts().0, before + 1);
    }
}

#[actix_web::test]
async fn unknown_restart_removed_node_and_revoked_session_never_redispatch() {
    let mut f = HttpFixture::new().await;
    let mut browser = login(&f.state, None).await;
    *f.fake.execute.lock().unwrap() = Script::Lost;
    let operation = create(&f, &browser, OperationKind::SendOnchain, Uuid::new_v4()).await;
    let authorization = grant(&f.state, &mut browser, &operation).await;
    let (status, unknown) = confirm(&f.state, &browser, &operation, authorization).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(unknown["state"], "unknown");
    assert_eq!(
        confirm(&f.state, &browser, &operation, Value::Null).await.0,
        StatusCode::OK
    );
    let old_cookie = browser.cookie.clone();
    let old_csrf = browser.csrf.clone();
    f.reopen().await;
    let (status, _, _) = call(
        &f.state,
        get(&path(&operation, "")).cookie(old_cookie.clone()),
        "Operation",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    browser = login(&f.state, Some(browser.authenticator)).await;
    assert_eq!(
        confirm(&f.state, &browser, &operation, Value::Null).await.0,
        StatusCode::OK
    );
    f.fake.script(Script::Lost);
    let (status, observed, _) = call(
        &f.state,
        authenticated(get(&path(&operation, "")), &browser),
        "Operation",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(observed["state"], "unknown");
    assert_eq!(f.fake.counts().0, 1);
    assert!(f.fake.counts().1 > 0);
    f.settings.nodes.clear();
    f.state = ApplicationState::new(&f.settings, f.state.journal.clone())
        .await
        .unwrap();
    browser = login(&f.state, Some(browser.authenticator)).await;
    let before = f.fake.counts();
    assert_eq!(
        confirm(&f.state, &browser, &operation, Value::Null).await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &f.state,
            authenticated(get(&path(&operation, "")), &browser),
            "Operation"
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(f.fake.counts(), before);
    let app = test::init_service(application(f.state.clone())).await;
    let response = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri("/api/v1/session")
            .insert_header((header::HOST, HOST))
            .insert_header((header::ORIGIN, ORIGIN))
            .insert_header(("X-CSRF-Token", browser.csrf.as_str()))
            .cookie(browser.cookie.clone())
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        confirm(&f.state, &browser, &operation, Value::Null).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.fake.counts(), before);
    let (status, _, _) = call(
        &f.state,
        post(&path(&operation, "/confirm"))
            .cookie(old_cookie)
            .insert_header(("X-CSRF-Token", old_csrf))
            .set_json(
                json!({"review_digest":operation["review"]["digest"],"authorization_id":null}),
            ),
        "Operation",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn read_only_and_wire_boundaries_deny_before_mutation() {
    let mut f = HttpFixture::new().await;
    let browser = login(&f.state, None).await;
    let operation = create(&f, &browser, OperationKind::NewAddress, Uuid::new_v4()).await;
    let digest = &operation["review"]["digest"];
    for body in [
        json!({"review_digest":digest}),
        json!({"review_digest":digest,"authorization_id":null,"extra":true}),
        json!({"review_digest":"bad","authorization_id":null}),
    ] {
        assert_eq!(
            call(
                &f.state,
                authenticated(post(&path(&operation, "/confirm")), &browser).set_json(body),
                "Operation"
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let (status, error, _) = call(
        &f.state,
        post(&path(&operation, "/confirm"))
            .cookie(browser.cookie.clone())
            .set_json(json!({"review_digest":digest,"authorization_id":null})),
        "Operation",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error["error"]["code"], "csrf");
    for (name, value) in [
        (header::HOST, "evil.example.invalid"),
        (header::ORIGIN, "https://evil.example.invalid"),
    ] {
        let (status, error, _) = call(
            &f.state,
            authenticated(post(&path(&operation, "/confirm")), &browser)
                .insert_header((name, value))
                .set_json(json!({"review_digest":digest,"authorization_id":null})),
            "Operation",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(error["error"]["code"], "origin");
    }
    assert_eq!(
        call(
            &f.state,
            authenticated(
                test::TestRequest::put()
                    .uri("/api/v1/nodes/synthetic/operations")
                    .insert_header((header::HOST, HOST))
                    .insert_header((header::ORIGIN, ORIGIN)),
                &browser
            )
            .set_json(json!({})),
            "Operation"
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &f.state,
            authenticated(post("/api/v1/nodes/synthetic/operations"), &browser)
                .set_json(request(OperationKind::NewAddress, Utc::now())),
            "Operation"
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let oversized = "x".repeat(lightning_client::settings::MAX_JSON_REQUEST_BYTES + 1);
    assert_eq!(
        call(
            &f.state,
            authenticated(post("/api/v1/nodes/synthetic/operations"), &browser)
                .insert_header(("Idempotency-Key", Uuid::new_v4().to_string()))
                .set_payload(oversized)
                .insert_header((header::CONTENT_TYPE, "application/json")),
            "Operation"
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &f.state,
            authenticated(post(&path(&operation, "/retry")), &browser).set_json(json!({})),
            "Operation"
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(f.fake.counts().0, 0);
    f.settings.nodes[0].read_only = Some(true);
    f.state = ApplicationState::new(&f.settings, f.state.journal.clone())
        .await
        .unwrap();
    f.inject();
    let browser = login(&f.state, Some(browser.authenticator)).await;
    let (status, error) = confirm(&f.state, &browser, &operation, Value::Null).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error["error"]["code"], "read_only");
    let (status, error, _) = call(
        &f.state,
        authenticated(post("/api/v1/nodes/synthetic/operations"), &browser)
            .insert_header(("Idempotency-Key", Uuid::new_v4().to_string()))
            .set_json(request(OperationKind::NewAddress, Utc::now())),
        "Operation",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error["error"]["code"], "read_only");
    assert_eq!(
        call(
            &f.state,
            authenticated(get(&path(&operation, "")), &browser),
            "Operation"
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(f.fake.counts().0, 0);
}
