use actix_web::{
    cookie::Cookie,
    http::{header, StatusCode},
    test,
};
use api_server::{
    app::application,
    journal::{Journal, Resource},
    registry::Registry,
    runtime::open_application,
    state::ApplicationState,
};
use chrono::{Duration, Utc};
use lightning_client::{
    model::{AddressType, NewAddress, Operation, OperationRequest},
    settings::{ApiSettings, Limits, NodePolicy, NodeSettings, ReauthPolicy, Settings},
};
use serde_json::{json, Value};
use std::{os::unix::fs::PermissionsExt, sync::Arc};
use uuid::Uuid;
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};

const HOST: &str = "manager.example.invalid";
const ORIGIN: &str = "https://manager.example.invalid";

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/api-examples.json")).unwrap()
}
fn configured(id: &str, readonly: bool) -> NodeSettings {
    let policy: NodePolicy =
        serde_json::from_value(fixture()["fixtures"]["node_policy"]["value"].clone()).unwrap();
    let key = bitcoin::secp256k1::SecretKey::from_slice(&[9; 32]).unwrap();
    let public =
        bitcoin::secp256k1::PublicKey::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &key);
    serde_json::from_value(json!({"id":id,"label":id,"backend":"lnd_rest","endpoint":"https://never-contact.example.invalid",
        "certificate_file":"SYNTHETIC_CERT_NEVER_OPENED","credential_file":"SYNTHETIC_CREDENTIAL_NEVER_OPENED",
        "expected_pubkey":public.to_string(),"network":"regtest","read_only":readonly,"policy":policy.limits,"peer_policy":{"allowed_hosts":[],"allowed_ports":[]}})).unwrap()
}

async fn setup() -> (tempfile::TempDir, Settings, ApplicationState) {
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let mut limits = Limits::default();
    limits.pagination.default_limit = 1;
    limits.pagination.max_limit = 3;
    limits.pagination.snapshot_max_items = 3;
    limits.snapshot_per_session = 16;
    let settings = Settings {
        api: ApiSettings {
            bind: "127.0.0.1:0".parse().unwrap(),
            public_origin: ORIGIN.parse().unwrap(),
            rp_id: HOST.into(),
            database: directory.path().join("history.sqlite"),
            invoice_key_file: directory.path().join("unused.key"),
            allow_insecure_loopback: false,
            client_identity: Default::default(),
            reauth: ReauthPolicy::default(),
            limits,
        },
        nodes: vec![
            configured("zeta", false),
            configured("alpha", true),
            configured("beta", false),
            configured("delta", false),
        ],
    };
    let auth = open_application(&settings).await.unwrap();
    (directory, settings, auth)
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

async fn login(auth: &ApplicationState) -> (Cookie<'static>, String) {
    let app = test::init_service(application(auth.clone())).await;
    let response = test::call_service(&app, get("/api/v1/auth/bootstrap").to_request()).await;
    let cookie = response.response().cookies().next().unwrap().into_owned();
    let bootstrap: Value = test::read_body_json(response).await;
    let csrf = bootstrap["csrf_token"].as_str().unwrap();
    let token = auth
        .journal
        .issue_enrollment(Utc::now(), std::time::Duration::from_secs(60), false)
        .await
        .unwrap();
    let response = test::call_service(
        &app,
        post("/api/v1/auth/enrollment/start")
            .cookie(cookie.clone())
            .insert_header(("X-CSRF-Token", csrf))
            .set_json(json!({"enrollment_token":token.as_str()}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: Value = test::read_body_json(response).await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = authenticator
        .do_registration(
            ORIGIN.parse().unwrap(),
            serde_json::from_value(challenge["options"].clone()).unwrap(),
        )
        .unwrap();
    let response = test::call_service(
        &app,
        post("/api/v1/auth/enrollment/finish")
            .cookie(cookie)
            .insert_header(("X-CSRF-Token", csrf))
            .set_json(json!({"challenge_id":challenge["challenge_id"],"credential":credential}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .response()
        .cookies()
        .find(|cookie| cookie.name() == "__Host-ld_session")
        .unwrap()
        .into_owned();
    let session: Value = test::read_body_json(response).await;
    (cookie, session["csrf_token"].as_str().unwrap().into())
}

fn evidence(name: &str, schema: &str, value: &Value) {
    if let Some(path) = std::env::var_os("STAGE2A_EVIDENCE_DIR") {
        let path = std::path::PathBuf::from(path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(
            path.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&json!({"schema":schema,"value":value})).unwrap(),
        )
        .unwrap();
    }
}

async fn seed(
    journal: &Journal,
    node: &str,
    kind: bool,
    time: chrono::DateTime<Utc>,
    id: u128,
) -> Operation {
    let mut operation: Operation =
        serde_json::from_value(fixture()["fixtures"]["operation_review"]["value"].clone()).unwrap();
    operation.id = Uuid::from_u128(id);
    operation.review.operation_id = operation.id;
    operation.node_id = node.into();
    operation.review.node.node_id = node.into();
    operation.created_at = time;
    operation.updated_at = time;
    operation.review.expires_at = Utc::now() + Duration::hours(1);
    if kind {
        operation.request = OperationRequest::NewAddress(NewAddress {
            address_type: AddressType::P2wpkh,
        });
        operation.review.sensitive = false;
    }
    journal
        .create(
            operation.clone(),
            Uuid::new_v4(),
            vec![Resource::Intent(operation.id.to_string())],
            None,
        )
        .await
        .unwrap();
    operation
}

#[actix_web::test]
async fn sanitized_sorted_registry_snapshot_filters_and_strict_queries() {
    let (_directory, settings, auth) = setup().await;
    let (cookie, _) = login(&auth).await;
    let app = test::init_service(application(auth.clone())).await;
    let response = test::call_service(&app, get("/api/v1/nodes").to_request()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = test::call_service(
        &app,
        get("/api/v1/nodes").cookie(cookie.clone()).to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let first: Value = test::read_body_json(response).await;
    evidence("nodes_first", "NodesPage", &first);
    assert_eq!(first["items"][0]["id"], "alpha");
    assert_eq!(first["stale"], false);
    assert_eq!(first["truncated"], true);
    assert_eq!(first["items"][0]["identity_pubkey"], Value::Null);
    assert_eq!(first["items"][0]["identity_revision"], Value::Null);
    assert_eq!(first["items"][0]["network"], "unknown");
    assert_eq!(first["items"][0]["status"]["observed_at"], Value::Null);
    for capability in first["items"][0]["capabilities"]
        .as_object()
        .unwrap()
        .values()
    {
        assert_eq!(*capability, json!({"enabled":false,"reason":"read_only"}));
    }
    let token = first["next_cursor"].as_str().unwrap();
    // A journal mutation cannot shift the existing immutable registry snapshot.
    seed(&auth.journal, "beta", false, Utc::now(), 1).await;
    let response = test::call_service(
        &app,
        get(&format!("/api/v1/nodes?cursor={token}"))
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    let second: Value = test::read_body_json(response).await;
    assert_eq!(second["items"][0]["id"], "beta");
    assert_eq!(second["items"][0]["unresolved_operation_count"], "0");
    assert_eq!(second["observed_at"], first["observed_at"]);
    let last = second["next_cursor"].as_str().unwrap();
    let response = test::call_service(
        &app,
        get(&format!("/api/v1/nodes?cursor={last}"))
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    let last: Value = test::read_body_json(response).await;
    assert_eq!(last["next_cursor"], Value::Null);
    assert_eq!(last["truncated"], true);
    for path in [
        format!("/api/v1/nodes?cursor={token}&limit=2"),
        format!("/api/v1/nodes?cursor={token}&network=unknown"),
    ] {
        let response =
            test::call_service(&app, get(&path).cookie(cookie.clone()).to_request()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: Value = test::read_body_json(response).await;
        assert_eq!(error["error"]["code"], "invalid_cursor");
        evidence("invalid_cursor", "ErrorResponse", &error);
    }
    for query in [
        "limit=",
        "limit=0",
        "limit=01",
        "limit=4",
        "limit=-1",
        "limit=1&limit=1",
        "network=regtest&network=regtest",
        "wat=1",
        "network=bogus",
    ] {
        let response = test::call_service(
            &app,
            get(&format!("/api/v1/nodes?{query}"))
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
    }
    for (path, schema) in [
        ("/api/v1/nodes/beta", "NodeSummary"),
        ("/api/v1/nodes/beta/status", "NodeStatus"),
        ("/api/v1/nodes/beta/policy", "NodePolicy"),
    ] {
        let response =
            test::call_service(&app, get(path).cookie(cookie.clone()).to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value = test::read_body_json(response).await;
        evidence(schema, schema, &value);
        let text = value.to_string();
        for secret in [
            "never-contact",
            "SYNTHETIC_CERT",
            "SYNTHETIC_CREDENTIAL",
            "expected_pubkey",
            "certificate_file",
            "endpoint",
        ] {
            assert!(!text.contains(secret));
        }
        if schema == "NodeSummary" {
            assert_eq!(value["unresolved_operation_count"], "1");
            assert_eq!(
                value["capabilities"]["pay_invoice"]["reason"],
                "not_configured"
            );
            assert_eq!(value["status"]["status"], "config_error");
        }
    }
    let mut empty = auth.clone();
    empty.registry = Arc::new(Registry::default());
    let empty = test::init_service(application(empty)).await;
    let response = test::call_service(
        &empty,
        get("/api/v1/nodes").cookie(cookie.clone()).to_request(),
    )
    .await;
    let value: Value = test::read_body_json(response).await;
    assert_eq!(value["items"], json!([]));
    assert_eq!(value["stale"], false);
    evidence("empty_nodes", "NodesPage", &value);
    let response = test::call_service(
        &app,
        get("/api/v1/nodes?network=regtest")
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    let value: Value = test::read_body_json(response).await;
    assert_eq!(value["items"], json!([]));
    let before = Registry::new(&settings).unwrap();
    let mut changed = settings.clone();
    changed.api.reauth.recent_auth_seconds = Some(120);
    changed.api.reauth.mode = lightning_client::model::ReauthMode::Recent;
    assert_ne!(
        before
            .get("alpha")
            .unwrap()
            .policy
            .as_ref()
            .unwrap()
            .revision,
        Registry::new(&changed)
            .unwrap()
            .get("alpha")
            .unwrap()
            .policy
            .as_ref()
            .unwrap()
            .revision
    );
    changed = settings.clone();
    changed.nodes[0].endpoint = "https://different.example.invalid".parse().unwrap();
    assert_ne!(
        before.get("zeta").unwrap().binding_revision,
        Registry::new(&changed)
            .unwrap()
            .get("zeta")
            .unwrap()
            .binding_revision
    );
    changed = settings.clone();
    changed.nodes[0].tls_verification = lightning_client::settings::TlsVerification::Pinned;
    assert_ne!(
        before.get("zeta").unwrap().binding_revision,
        Registry::new(&changed)
            .unwrap()
            .get("zeta")
            .unwrap()
            .binding_revision
    );
}

#[actix_web::test]
async fn filtered_durable_history_removed_nodes_exact_counts_sort_and_immutable_pages() {
    let (_directory, _settings, auth) = setup().await;
    let (cookie, _) = login(&auth).await;
    let now = Utc::now();
    for id in 1..=6 {
        seed(&auth.journal, "alpha", false, now, id).await;
    }
    let oldest = seed(
        &auth.journal,
        "alpha",
        true,
        now - Duration::seconds(10),
        10,
    )
    .await;
    let former = seed(&auth.journal, "removed", false, now, 20).await;
    let app = test::init_service(application(auth.clone())).await;
    let response = test::call_service(
        &app,
        get("/api/v1/nodes/alpha")
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    let summary: Value = test::read_body_json(response).await;
    assert_eq!(summary["unresolved_operation_count"], "7");
    let response = test::call_service(
        &app,
        get("/api/v1/nodes/alpha/operations?kind=new_address&state=nonterminal")
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    let filtered: Value = test::read_body_json(response).await;
    assert_eq!(filtered["items"][0]["id"], oldest.id.to_string());
    assert_eq!(filtered["truncated"], false);
    evidence("filtered_history", "OperationsPage", &filtered);
    let response = test::call_service(
        &app,
        get("/api/v1/nodes/alpha/operations")
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    let first: Value = test::read_body_json(response).await;
    assert_eq!(first["items"][0]["id"], Uuid::from_u128(1).to_string());
    assert_eq!(first["truncated"], true);
    let token = first["next_cursor"].as_str().unwrap();
    seed(
        &auth.journal,
        "alpha",
        false,
        now + Duration::seconds(1),
        30,
    )
    .await;
    let response = test::call_service(
        &app,
        get(&format!("/api/v1/nodes/alpha/operations?cursor={token}"))
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    let second: Value = test::read_body_json(response).await;
    assert_eq!(second["items"][0]["id"], Uuid::from_u128(2).to_string());
    assert_eq!(second["observed_at"], first["observed_at"]);
    for suffix in ["&state=nonterminal", "&kind=pay_invoice", "&limit=2"] {
        let response = test::call_service(
            &app,
            get(&format!(
                "/api/v1/nodes/alpha/operations?cursor={token}{suffix}"
            ))
            .cookie(cookie.clone())
            .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    for path in [
        format!("/api/v1/nodes/removed/operations?cursor={token}"),
        format!("/api/v1/nodes?cursor={token}"),
    ] {
        let response =
            test::call_service(&app, get(&path).cookie(cookie.clone()).to_request()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let response = test::call_service(
        &app,
        get("/api/v1/nodes/removed/operations")
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let history: Value = test::read_body_json(response).await;
    assert_eq!(
        history["items"][0]["review"],
        serde_json::to_value(&former.review).unwrap()
    );
    evidence("removed_history", "OperationsPage", &history);
    for path in [
        "/api/v1/nodes/absent/operations",
        "/api/v1/nodes/removed",
        "/api/v1/nodes/removed/policy",
    ] {
        let response =
            test::call_service(&app, get(path).cookie(cookie.clone()).to_request()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    for path in [
        format!("/api/v1/nodes/alpha/operations/{}", former.id),
        "/api/v1/nodes/removed/operations/00000000-0000-0000-0000-000000000099".into(),
    ] {
        let response =
            test::call_service(&app, get(&path).cookie(cookie.clone()).to_request()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    for tail in [
        "operations/not-a-uuid",
        "operations?kind=bogus",
        "operations?state=bogus",
        "operations?kind=pay_invoice&kind=new_address",
    ] {
        let response = test::call_service(
            &app,
            get(&format!("/api/v1/nodes/alpha/{tail}"))
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let response = test::call_service(
        &app,
        get(&format!("/api/v1/nodes/removed/operations/{}", former.id))
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    let detail: Value = test::read_body_json(response).await;
    evidence("operation_detail", "Operation", &detail);
    assert_eq!(
        detail["review"],
        serde_json::to_value(&former.review).unwrap()
    );
    // A same-ID retargeted configuration does not relabel or reconcile old rows.
    let mut retarget = auth.clone();
    let mut settings = Settings {
        api: ApiSettings {
            bind: "127.0.0.1:0".parse().unwrap(),
            public_origin: ORIGIN.parse().unwrap(),
            rp_id: HOST.into(),
            database: "unused".into(),
            invoice_key_file: "unused".into(),
            allow_insecure_loopback: false,
            client_identity: Default::default(),
            reauth: ReauthPolicy::default(),
            limits: Limits::default(),
        },
        nodes: vec![configured("removed", true)],
    };
    settings.nodes[0].network = lightning_client::model::Network::Mainnet;
    retarget.registry = Arc::new(Registry::new(&settings).unwrap());
    let retarget = test::init_service(application(retarget)).await;
    let response = test::call_service(
        &retarget,
        get(&format!("/api/v1/nodes/removed/operations/{}", former.id))
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    let detail: Value = test::read_body_json(response).await;
    assert_eq!(
        detail["review"],
        serde_json::to_value(&former.review).unwrap()
    );
    let count = auth.journal.unresolved_counts().await.unwrap();
    assert_eq!(count["alpha"].to_string(), "8");
    let (a, b) = tokio::join!(
        auth.journal
            .history("alpha".into(), Some("nonterminal".into()), None, 3),
        auth.journal.history("removed".into(), None, None, 3)
    );
    assert!(a.unwrap().1);
    assert_eq!(b.unwrap().0.len(), 1);
    let mut mixed = former.clone();
    mixed.id = Uuid::from_u128(40);
    mixed.review.operation_id = mixed.id;
    mixed.review.node.network = lightning_client::model::VerifiedNetwork::Mainnet;
    mixed.review.node.identity_revision = "historical-retargeted-identity".into();
    auth.journal
        .create(mixed, Uuid::new_v4(), vec![], None)
        .await
        .unwrap();
    let response = test::call_service(
        &app,
        get("/api/v1/nodes/removed/operations?limit=3")
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    let mixed: Value = test::read_body_json(response).await;
    assert_eq!(mixed["network"], "unknown");
    assert_eq!(
        mixed["items"][0]["review"],
        serde_json::to_value(former.review).unwrap()
    );
    evidence("mixed_history", "OperationsPage", &mixed);
}

#[actix_web::test]
async fn cursors_bind_sessions_expire_restart_and_reclaim_bounded_allocations() {
    use api_server::pagination::{Paged, Rows, Selector, Snapshots};
    use lightning_client::{model::ErrorCode, money::Decimal};
    let (_directory, settings, auth) = setup().await;
    let (cookie, csrf) = login(&auth).await;
    let context = auth
        .auth
        .manager
        .context(cookie.value(), true, Utc::now())
        .await
        .unwrap();
    let (other_cookie, _) = login(&auth).await;
    let other = auth
        .auth
        .manager
        .context(other_cookie.value(), true, Utc::now())
        .await
        .unwrap();
    let rows: Vec<_> = auth
        .registry
        .entries()
        .take(3)
        .map(|(_, entry)| entry.summary(Utc::now(), Decimal::ZERO))
        .collect();
    let mut limits = settings.api.limits.clone();
    limits.snapshot_per_session = 1;
    limits.snapshot_max_entries = 1;
    let cache = Snapshots::new(limits.clone());
    let selector = Selector {
        resource: "nodes",
        node: None,
        scope: auth.registry.scope(),
        filters: vec![],
        limit: 1,
    };
    let now = Utc::now();
    let Paged::Nodes(page) = cache
        .begin(
            &context,
            selector.clone(),
            Rows::Nodes(rows.clone()),
            None,
            false,
            now,
        )
        .unwrap()
    else {
        panic!("wrong resource")
    };
    let token = page.next_cursor.unwrap();
    assert_eq!(
        cache
            .next(&other, &selector, &token, now)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidCursor
    );
    let mut changed = selector.clone();
    changed.scope.push_str("retargeted");
    assert_eq!(
        cache
            .next(&context, &changed, &token, now)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidCursor
    );
    assert_eq!(
        cache
            .next(&context, &selector, "bad-cursor", now)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidCursor
    );
    assert_eq!(
        cache
            .begin(
                &context,
                selector.clone(),
                Rows::Nodes(rows.clone()),
                None,
                false,
                now
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::RateLimited
    );
    assert_eq!(
        cache
            .begin(
                &other,
                selector.clone(),
                Rows::Nodes(rows.clone()),
                None,
                false,
                now
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::RateLimited
    );
    let restarted = Snapshots::new(limits.clone());
    assert_eq!(
        restarted
            .next(&context, &selector, &token, now)
            .err()
            .unwrap()
            .code,
        ErrorCode::CursorExpired
    );
    let later = now + Duration::seconds(i64::from(limits.pagination.snapshot_ttl_seconds));
    assert_eq!(
        cache
            .next(&context, &selector, &token, later)
            .err()
            .unwrap()
            .code,
        ErrorCode::CursorExpired
    );
    assert!(cache
        .begin(
            &context,
            selector.clone(),
            Rows::Nodes(rows.clone()),
            None,
            false,
            later
        )
        .is_ok());
    limits.snapshot_cache_bytes = 1;
    assert_eq!(
        Snapshots::new(limits)
            .begin(&context, selector, Rows::Nodes(rows), None, false, now)
            .err()
            .unwrap()
            .code,
        ErrorCode::RateLimited
    );

    let app = test::init_service(application(auth.clone())).await;
    let response = test::call_service(
        &app,
        get("/api/v1/nodes").cookie(cookie.clone()).to_request(),
    )
    .await;
    let page: Value = test::read_body_json(response).await;
    let token = page["next_cursor"].as_str().unwrap();
    let response = test::call_service(
        &app,
        actix_web::test::TestRequest::delete()
            .uri("/api/v1/session")
            .insert_header((header::HOST, HOST))
            .insert_header((header::ORIGIN, ORIGIN))
            .insert_header(("X-CSRF-Token", csrf))
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = test::call_service(
        &app,
        get(&format!("/api/v1/nodes?cursor={token}"))
            .cookie(cookie)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = test::call_service(
        &app,
        get(&format!("/api/v1/nodes?cursor={token}"))
            .cookie(other_cookie)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let mut restarted = auth.clone();
    restarted.snapshots = Snapshots::new(settings.api.limits.clone());
    let restarted = test::init_service(application(restarted)).await;
    let (new_cookie, _) = login(&auth).await;
    let response = test::call_service(
        &restarted,
        get(&format!("/api/v1/nodes?cursor={token}"))
            .cookie(new_cookie)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::GONE);
    let error: Value = test::read_body_json(response).await;
    assert_eq!(error["error"]["code"], "cursor_expired");
    evidence("cursor_expired", "ErrorResponse", &error);
}

#[actix_web::test]
async fn history_sort_is_exact_to_nanoseconds_filters_before_bound_and_unknown_retains_claims() {
    use lightning_client::model::{OperationStage, OperationState};
    let (_directory, _settings, auth) = setup().await;
    let time = chrono::DateTime::from_timestamp(1000, 0).unwrap();
    let a = seed(&auth.journal, "alpha", false, time, 60).await;
    let b = seed(
        &auth.journal,
        "alpha",
        false,
        time + Duration::nanoseconds(1),
        59,
    )
    .await;
    let c = seed(
        &auth.journal,
        "alpha",
        false,
        time + Duration::nanoseconds(2),
        58,
    )
    .await;
    let rows = auth
        .journal
        .history("alpha".into(), None, None, 3)
        .await
        .unwrap()
        .0;
    assert_eq!(
        rows.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![c.id, b.id, a.id]
    );
    let generation = auth.journal.authentication().await.unwrap().1;
    auth.journal
        .claim(
            a.id,
            a.node_id.clone(),
            a.review.digest.clone(),
            a.review.policy_revision.clone(),
            generation,
            Utc::now(),
        )
        .await
        .unwrap();
    auth.journal
        .record(
            a.id,
            OperationState::Unknown,
            OperationStage::Reconciling,
            None,
            None,
            Utc::now(),
        )
        .await
        .unwrap();
    let (filtered, truncated) = auth
        .journal
        .history(
            "alpha".into(),
            Some("unknown".into()),
            Some("pay_invoice".into()),
            1,
        )
        .await
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].id, a.id);
    assert!(!truncated);
    assert_eq!(
        auth.journal.unresolved_counts().await.unwrap()["alpha"].to_string(),
        "3"
    );
    // The read did not terminalize uncertain work or release its resource claim.
    let mut conflict = b.clone();
    conflict.id = Uuid::new_v4();
    conflict.review.operation_id = conflict.id;
    let result = auth
        .journal
        .create(
            conflict,
            Uuid::new_v4(),
            vec![Resource::Intent(a.id.to_string())],
            None,
        )
        .await;
    assert!(matches!(result,Err(api_server::journal::JournalError::ResourceBusy(id)) if id==a.id));
}

#[actix_web::test]
async fn stored_scope_matches_legacy_hash_and_concurrent_reads_do_not_mutate() {
    use sha2::{Digest, Sha256};
    let (_directory, settings, auth) = setup().await;
    let now = Utc::now();
    let original = seed(&auth.journal, "alpha", false, now, 701).await;
    let first = auth.journal.history_scope("alpha".into()).await.unwrap();
    assert_eq!(
        first.revision,
        hex::encode(Sha256::digest(
            serde_json::to_vec(&original.review.node).unwrap()
        ))
    );
    seed(&auth.journal, "alpha", true, now, 702).await;
    assert_eq!(
        auth.journal
            .history_scope("alpha".into())
            .await
            .unwrap()
            .revision,
        first.revision
    );
    let mut changed = original.clone();
    changed.id = Uuid::from_u128(703);
    changed.review.operation_id = changed.id;
    changed
        .review
        .node
        .identity_revision
        .push_str("-new-binding");
    auth.journal
        .create(changed, Uuid::new_v4(), vec![], None)
        .await
        .unwrap();
    let scope = auth.journal.history_scope("alpha".into()).await.unwrap();
    assert_ne!(scope.revision, first.revision);
    assert_eq!(scope.network, lightning_client::model::Network::Unknown);
    let observer = rusqlite::Connection::open(&settings.api.database).unwrap();
    let mut hash = Sha256::new();
    for binding in observer.prepare("SELECT DISTINCT json_extract(body,'$.review.node') FROM operations WHERE node_id='alpha' ORDER BY json_extract(body,'$.review.node')").unwrap().query_map([], |row| row.get::<_, String>(0)).unwrap() {
        let binding: lightning_client::model::NodeBinding = serde_json::from_str(&binding.unwrap()).unwrap();
        hash.update(serde_json::to_vec(&binding).unwrap());
    }
    assert_eq!(scope.revision, hex::encode(hash.finalize()));
    let version: i64 = observer
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .unwrap();
    let (a, b, c, d) = tokio::join!(
        auth.journal.history_scope("alpha".into()),
        auth.journal.history_scope("alpha".into()),
        auth.journal.history("alpha".into(), None, None, 3),
        auth.journal
            .history("alpha".into(), Some("nonterminal".into()), None, 3),
    );
    assert_eq!(a.unwrap().revision, scope.revision);
    assert_eq!(b.unwrap().revision, scope.revision);
    assert_eq!(c.unwrap().0.len(), 3);
    assert_eq!(d.unwrap().0.len(), 3);
    assert_eq!(
        observer
            .pragma_query_value(None, "data_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        version
    );
}

#[actix_web::test]
async fn oversized_record_and_multi_record_page_return_static_internal_error_without_items() {
    use api_server::journal::JournalError;
    let (_directory, mut settings, mut auth) = setup().await;
    let now = Utc::now();
    let operation = seed(&auth.journal, "alpha", false, now, 801).await;
    seed(&auth.journal, "alpha", false, now, 802).await;
    let record_bytes = serde_json::to_vec(&operation).unwrap().len();
    assert!(matches!(
        auth.journal
            .history_observation_bounded("alpha".into(), None, None, 3, record_bytes - 1)
            .await,
        Err(JournalError::ResponseTooLarge)
    ));
    settings.api.limits.max_response_bytes = record_bytes + 512;
    auth = ApplicationState::new(&settings, auth.journal.clone())
        .await
        .unwrap();
    let (cookie, _) = login(&auth).await;
    let app = test::init_service(application(auth.clone())).await;
    let response = test::call_service(
        &app,
        get("/api/v1/nodes/alpha/operations?limit=1")
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response_bytes = test::read_body(response).await;
    assert!(response_bytes.len() <= settings.api.limits.max_response_bytes);
    let first: Value = serde_json::from_slice(&response_bytes).unwrap();
    let token = first["next_cursor"].as_str().unwrap();
    let response = test::call_service(
        &app,
        get(&format!(
            "/api/v1/nodes/alpha/operations?limit=1&cursor={token}"
        ))
        .cookie(cookie.clone())
        .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let last: Value = test::read_body_json(response).await;
    assert_eq!(last["items"][0]["id"], Uuid::from_u128(802).to_string());
    let response = test::call_service(
        &app,
        get("/api/v1/nodes/alpha/operations?limit=2")
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let error: Value = test::read_body_json(response).await;
    assert_eq!(error["error"]["code"], "internal_error");
    assert!(error.get("items").is_none());
    let mut huge = operation;
    huge.id = Uuid::from_u128(803);
    huge.review.operation_id = huge.id;
    huge.review.destination = Some("SYNTHETIC_OVERSIZED_CANARY".repeat(record_bytes));
    auth.journal
        .create(huge, Uuid::new_v4(), vec![], None)
        .await
        .unwrap();
    let response = test::call_service(
        &app,
        get("/api/v1/nodes/alpha/operations?limit=3")
            .cookie(cookie)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let oversized: Value = test::read_body_json(response).await;
    assert_eq!(oversized["error"]["message"], error["error"]["message"]);
    assert!(!oversized.to_string().contains("SYNTHETIC_OVERSIZED_CANARY"));
    assert!(oversized.get("items").is_none());
}

fn signed_invoice() -> String {
    use bitcoin::{
        hashes::{sha256, Hash},
        secp256k1::{Secp256k1, SecretKey},
    };
    use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
    InvoiceBuilder::new(Currency::Regtest)
        .description("signed synthetic invoice".into())
        .payment_hash(sha256::Hash::hash(&[5; 32]))
        .payment_secret(PaymentSecret([6; 32]))
        .duration_since_epoch(std::time::Duration::from_secs(1000))
        .min_final_cltv_expiry_delta(18)
        .amount_milli_satoshis(1001)
        .build_signed(|hash| {
            Secp256k1::new().sign_ecdsa_recoverable(hash, &SecretKey::from_slice(&[7; 32]).unwrap())
        })
        .unwrap()
        .to_string()
}

#[actix_web::test]
async fn local_decode_readonly_unverified_strict_body_and_security_boundaries() {
    let (_directory, _settings, auth) = setup().await;
    let (cookie, csrf) = login(&auth).await;
    let app = test::init_service(application(auth.clone())).await;
    let invoice = signed_invoice();
    let response = test::call_service(
        &app,
        post("/api/v1/nodes/alpha/decode")
            .cookie(cookie.clone())
            .insert_header(("X-CSRF-Token", csrf.clone()))
            .set_json(json!({"bolt11":invoice}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let decoded: Value = test::read_body_json(response).await;
    evidence("decoded_signed_invoice", "DecodedInvoice", &decoded);
    assert_eq!(decoded["amount_msat"], "1001");
    assert_eq!(decoded["network_matches_node"], Value::Null);
    assert_eq!(decoded["expired"], true);
    for (body, status) in [
        (
            r#"{"bolt11":"a","bolt11":"b"}"#.to_string(),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"bolt11":invoice,"extra":true}).to_string(),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"bolt11":"x".repeat(16385)}).to_string(),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"bolt11":"bad"}).to_string(),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let response = test::call_service(
            &app,
            post("/api/v1/nodes/alpha/decode")
                .cookie(cookie.clone())
                .insert_header(("X-CSRF-Token", csrf.clone()))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(body)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), status);
    }
    let response = test::call_service(
        &app,
        post("/api/v1/nodes/alpha/decode")
            .cookie(cookie.clone())
            .set_json(json!({"bolt11":invoice}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = test::call_service(
        &app,
        post("/api/v1/nodes/alpha/decode")
            .set_json(json!({"bolt11":invoice}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = test::call_service(
        &app,
        post("/api/v1/nodes/alpha/decode")
            .cookie(cookie.clone())
            .insert_header((header::ORIGIN, "https://evil.example.invalid"))
            .insert_header(("X-CSRF-Token", csrf))
            .set_json(json!({"bolt11":invoice}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(auth.journal.unresolved_counts().await.unwrap().is_empty());
    let (operations, truncated) = auth
        .journal
        .history("alpha".into(), None, None, 3)
        .await
        .unwrap();
    assert!(operations.is_empty());
    assert!(!truncated);
}
