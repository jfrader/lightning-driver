//! Production factory, durable engine and real adapters over disposable TLS nodes.
use super::*;
use synthetic_node_harness::{Fault, Harness, PEER, POINT};

struct Journey {
    harness: Harness,
    settings: Settings,
    state: ApplicationState,
}

#[path = "collection_tests.rs"]
mod collections;
impl Journey {
    async fn new(backend: Backend, read_only: bool) -> Self {
        let harness = Harness::start(backend, "127.0.0.1:0".parse().unwrap(), 45, Utc::now())
            .await
            .unwrap();
        let mut node = harness.node("synthetic");
        node.read_only = Some(read_only);
        let settings = Settings {
            api: ApiSettings {
                bind: "127.0.0.1:0".parse().unwrap(),
                public_origin: ORIGIN.parse().unwrap(),
                rp_id: HOST.into(),
                database: harness.directory().join("journal.sqlite"),
                invoice_key_file: harness.directory().join("invoice.key"),
                allow_insecure_loopback: false,
                client_identity: Default::default(),
                reauth: ReauthPolicy::default(),
                limits: Limits {
                    rpc_seconds: 1,
                    ..Default::default()
                },
            },
            nodes: vec![node],
        };
        let state = ApplicationState::new(
            &settings,
            Journal::open(settings.api.database.clone()).await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(state.engine.unavailable("synthetic"), None);
        Self {
            harness,
            settings,
            state,
        }
    }
    fn request(&self, kind: OperationKind) -> Value {
        let mut value = serde_json::to_value(request(kind, Utc::now())).unwrap();
        match kind {
            OperationKind::PayInvoice => {
                value["params"]["bolt11"] =
                    json!(self.harness.scenario.lock().unwrap().payment_invoice())
            }
            OperationKind::ConnectPeer | OperationKind::DisconnectPeer => {
                value["params"]["pubkey"] = json!(PEER)
            }
            OperationKind::OpenChannel => value["params"]["peer_pubkey"] = json!(PEER),
            OperationKind::CloseChannel => value["params"]["channel_id"] = json!(POINT),
            _ => {}
        }
        value
    }
    async fn create(&self, browser: &Browser, kind: OperationKind) -> (StatusCode, Value) {
        self.create_request(browser, kind, self.request(kind)).await
    }
    async fn create_request(
        &self,
        browser: &Browser,
        kind: OperationKind,
        request: Value,
    ) -> (StatusCode, Value) {
        self.harness
            .scenario
            .lock()
            .unwrap()
            .expect_mutations(&[method(self.settings.nodes[0].backend, kind)]);
        let (status, value, _) = call(
            &self.state,
            authenticated(post("/api/v1/nodes/synthetic/operations"), browser)
                .insert_header(("Idempotency-Key", Uuid::new_v4().to_string()))
                .set_json(request),
            "Operation",
        )
        .await;
        (status, value)
    }
    async fn observe(&self, browser: &Browser, op: &Value) -> Value {
        let (status, value, _) = call(
            &self.state,
            authenticated(get(&path(op, "")), browser),
            "Operation",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        value
    }
    async fn restart(&mut self) {
        self.state = ApplicationState::new(
            &self.settings,
            Journal::open(self.settings.api.database.clone())
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        self.state.engine.recover().await.unwrap();
    }
}

#[actix_web::test]
async fn cln_browser_can_pay_the_invoice_created_by_its_real_adapter() {
    let f = Journey::new(Backend::ClnRest, false).await;
    let mut browser = login(&f.state, None).await;
    let (status, invoice) = f.create(&browser, OperationKind::CreateInvoice).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, created) = confirm(&f.state, &browser, &invoice, Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created["state"], "succeeded");
    let mut request = f.request(OperationKind::PayInvoice);
    request["params"]["bolt11"] = created["result"]["bolt11"].clone();
    let (status, payment) = f
        .create_request(&browser, OperationKind::PayInvoice, request)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{payment}");
    assert_eq!(
        payment["review"]["payment_hash"],
        created["result"]["payment_hash"]
    );
    let authorization = grant(&f.state, &mut browser, &payment).await;
    let (status, paid) = confirm(&f.state, &browser, &payment, authorization).await;
    assert_eq!(status, StatusCode::OK, "{paid}");
    assert_eq!(paid["state"], "succeeded");
    assert_eq!(f.observe(&browser, &payment).await["state"], "succeeded");
    let scenario = f.harness.scenario.lock().unwrap();
    assert_eq!(scenario.calls("invoice"), 1);
    assert_eq!(scenario.calls("xpay"), 1);
    scenario.assert_no_unexpected_calls();
}
fn method(backend: Backend, kind: OperationKind) -> &'static str {
    match (backend == Backend::ClnRest, kind) {
        (false, OperationKind::CreateInvoice) => "AddInvoice",
        (true, OperationKind::CreateInvoice) => "invoice",
        (false, OperationKind::PayInvoice) => "SendPaymentV2",
        (true, OperationKind::PayInvoice) => "xpay",
        (false, OperationKind::ConnectPeer) => "ConnectPeer",
        (true, OperationKind::ConnectPeer) => "connect",
        (false, OperationKind::DisconnectPeer) => "DisconnectPeer",
        (true, OperationKind::DisconnectPeer) => "disconnect",
        (false, OperationKind::OpenChannel) => "OpenChannelSync",
        (true, OperationKind::OpenChannel) => "fundchannel",
        (false, OperationKind::CloseChannel) => "CloseChannel",
        (true, OperationKind::CloseChannel) => "close",
        (false, OperationKind::NewAddress) => "NewAddress",
        (true, OperationKind::NewAddress) => "newaddr",
        (false, OperationKind::SendOnchain) => "SendCoins",
        (true, OperationKind::SendOnchain) => "withdraw",
    }
}
async fn journey(backend: Backend, kind: OperationKind) {
    let mut f = Journey::new(backend, false).await;
    let mut browser = login(&f.state, None).await;
    let (status, op) = f.create(&browser, kind).await;
    assert_eq!(status, StatusCode::CREATED, "{backend:?} {kind:?}: {op}");
    assert_eq!(op["state"], "awaiting_confirmation");
    assert_eq!(
        f.harness
            .scenario
            .lock()
            .unwrap()
            .calls(method(backend, kind)),
        0
    );
    let authorization = if op["review"]["sensitive"] == true {
        let (status, error) = confirm(&f.state, &browser, &op, Value::Null).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(error["error"]["code"], "reauth_required");
        grant(&f.state, &mut browser, &op).await
    } else {
        Value::Null
    };
    let (status, mut result) = confirm(&f.state, &browser, &op, authorization.clone()).await;
    assert!(
        matches!(status, StatusCode::OK | StatusCode::ACCEPTED),
        "{backend:?} {kind:?}: {result}"
    );
    if kind == OperationKind::PayInvoice && backend != Backend::ClnRest {
        assert_eq!(result["state"], "pending");
    }
    if kind == OperationKind::OpenChannel {
        assert_eq!(result["state"], "pending");
    }
    let clock = Arc::new(TestClock(Mutex::new(Utc::now())));
    f.state.engine.clock = clock.clone();
    for _ in 0..4 {
        if result["state"] == "succeeded" {
            break;
        }
        result = f.observe(&browser, &op).await;
        if let Some(next) = result["reconciliation"]["next_attempt_at"].as_str() {
            *clock.0.lock().unwrap() = next.parse().unwrap();
        }
    }
    assert_eq!(
        result["state"], "succeeded",
        "{backend:?} {kind:?}: {result}"
    );
    assert_eq!(f.observe(&browser, &op).await["state"], "succeeded");
    assert_eq!(result["review"], op["review"]);
    let (status, duplicate) = confirm(&f.state, &browser, &op, authorization).await;
    assert_eq!(status, StatusCode::OK, "{duplicate}");
    assert_eq!(duplicate["id"], op["id"]);
    let script = f.harness.scenario.lock().unwrap();
    assert_eq!(script.calls(method(backend, kind)), 1);
    assert_eq!(script.effects(method(backend, kind)), 1);
    let args = &script.mutation_arguments(method(backend, kind))[0];
    if kind == OperationKind::CreateInvoice && backend != Backend::ClnRest {
        use base64::Engine;
        use sha2::Digest;
        let preimage = base64::engine::general_purpose::STANDARD
            .decode(args["r_preimage"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            op["review"]["payment_hash"],
            hex::encode(sha2::Sha256::digest(preimage))
        );
        assert_eq!(args["value_msat"], "1001");
    }
    if kind == OperationKind::CreateInvoice && backend == Backend::ClnRest {
        assert_eq!(args["label"], format!("ld-{}", op["id"].as_str().unwrap()));
    }
    if kind == OperationKind::CloseChannel && backend == Backend::ClnRest {
        // CLN `close` rejects an outpoint; the durable target is the channel id.
        assert_eq!(
            args["id"],
            "2222222222222222222222222222222222222222222222222222222222222222"
        );
        // `unilateraltimeout: 0` means force close now; a cooperative close omits it.
        assert!(args.get("unilateraltimeout").is_none());
    }
    if kind == OperationKind::CloseChannel && backend == Backend::LndGrpc {
        assert_eq!(args["force"], false);
    }
    script.assert_no_unexpected_calls();
}

#[actix_web::test]
async fn scripted_faults_use_real_adapters_and_never_retry() {
    for backend in [Backend::ClnRest, Backend::LndRest, Backend::LndGrpc] {
        for fault in [
            Fault::Reject,
            Fault::PermissionDenied,
            Fault::TimeoutBeforeEffect,
            Fault::Malformed,
            Fault::Oversized,
        ] {
            let f = Journey::new(backend, false).await;
            let browser = login(&f.state, None).await;
            let (_, op) = f.create(&browser, OperationKind::NewAddress).await;
            let method = method(backend, OperationKind::NewAddress);
            f.harness
                .scenario
                .lock()
                .unwrap()
                .fault(method, fault.clone());
            let (status, result) = confirm(&f.state, &browser, &op, Value::Null).await;
            let rejection = matches!(fault, Fault::Reject | Fault::PermissionDenied);
            assert_eq!(
                result["state"],
                if rejection { "failed" } else { "unknown" },
                "{backend:?} {fault:?}: {result}"
            );
            assert_eq!(
                status,
                if rejection {
                    StatusCode::OK
                } else {
                    StatusCode::ACCEPTED
                }
            );
            let observed = f.observe(&browser, &op).await;
            assert_eq!(observed["state"], result["state"]);
            let _ = confirm(&f.state, &browser, &op, Value::Null).await;
            let script = f.harness.scenario.lock().unwrap();
            assert_eq!(script.calls(method), 1);
            assert_eq!(
                script.effects(method),
                usize::from(matches!(fault, Fault::Malformed | Fault::Oversized))
            );
        }
    }
}

#[actix_web::test]
async fn late_stream_error_is_not_a_failure_or_a_retry() {
    for backend in [Backend::LndRest, Backend::LndGrpc] {
        let f = Journey::new(backend, false).await;
        let mut browser = login(&f.state, None).await;
        let (_, op) = f.create(&browser, OperationKind::PayInvoice).await;
        let authorization = grant(&f.state, &mut browser, &op).await;
        f.harness
            .scenario
            .lock()
            .unwrap()
            .fault("SendPaymentV2", Fault::StreamError);
        let (status, result) = confirm(&f.state, &browser, &op, authorization.clone()).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(
            matches!(result["state"].as_str(), Some("pending" | "unknown")),
            "{result}"
        );
        assert_eq!(f.observe(&browser, &op).await["state"], "succeeded");
        assert_eq!(
            confirm(&f.state, &browser, &op, authorization).await.0,
            StatusCode::OK
        );
        assert_eq!(f.harness.scenario.lock().unwrap().calls("SendPaymentV2"), 1);
    }
}

#[actix_web::test]
async fn lost_lnd_invoice_response_recovers_by_preknown_hash_after_authentication_recovery() {
    for backend in [Backend::LndRest, Backend::LndGrpc] {
        let mut f = Journey::new(backend, false).await;
        let browser = login(&f.state, None).await;
        let (_, op) = f.create(&browser, OperationKind::CreateInvoice).await;
        assert!(op["review"]["payment_hash"].as_str().is_some());
        f.harness
            .scenario
            .lock()
            .unwrap()
            .fault("AddInvoice", Fault::TimeoutAfterEffect);
        let (status, result) = confirm(&f.state, &browser, &op, Value::Null).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(result["state"], "unknown");
        let secrets = || {
            f.state.journal.run(|connection| {
                Ok(connection.query_row(
                    "SELECT COUNT(*) FROM pending_invoice_secrets",
                    [],
                    |r| r.get::<_, i64>(0),
                )?)
            })
        };
        assert_eq!(secrets().await.unwrap(), 1);
        f.state
            .journal
            .issue_enrollment(Utc::now(), std::time::Duration::from_secs(60), true)
            .await
            .unwrap();
        assert_eq!(
            confirm(&f.state, &browser, &op, Value::Null).await.0,
            StatusCode::UNAUTHORIZED
        );
        f.restart().await;
        let browser = login(&f.state, None).await;
        let recovered = f.observe(&browser, &op).await;
        assert_eq!(recovered["state"], "succeeded", "{recovered}");
        assert_eq!(recovered["review"], op["review"]);
        assert_eq!(
            f.state
                .journal
                .run(|connection| Ok(connection.query_row(
                    "SELECT COUNT(*) FROM pending_invoice_secrets",
                    [],
                    |r| r.get::<_, i64>(0)
                )?))
                .await
                .unwrap(),
            0
        );
        assert_eq!(f.harness.scenario.lock().unwrap().calls("AddInvoice"), 1);
        assert_eq!(f.harness.scenario.lock().unwrap().calls("LookupInvoice"), 1);
    }
}

#[actix_web::test]
async fn lnd_rest_all_eight_mutations_over_real_tls_adapter() {
    for kind in KINDS {
        journey(Backend::LndRest, kind).await;
    }
}
#[actix_web::test]
async fn lnd_grpc_all_eight_mutations_over_real_tls_adapter() {
    for kind in KINDS {
        journey(Backend::LndGrpc, kind).await;
    }
}
#[actix_web::test]
async fn cln_rest_all_eight_mutations_over_real_tls_adapter() {
    for kind in KINDS {
        journey(Backend::ClnRest, kind).await;
    }
}

#[actix_web::test]
async fn real_adapters_deny_read_only_and_revoked_sessions_before_wire_dispatch() {
    for backend in [Backend::ClnRest, Backend::LndRest, Backend::LndGrpc] {
        let f = Journey::new(backend, true).await;
        let browser = login(&f.state, None).await;
        for kind in KINDS {
            let (status, error) = f.create(&browser, kind).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{error}");
            assert_eq!(error["error"]["code"], "read_only");
            assert_eq!(
                f.harness
                    .scenario
                    .lock()
                    .unwrap()
                    .calls(method(backend, kind)),
                0
            );
        }
        let f = Journey::new(backend, false).await;
        let mut browser = login(&f.state, None).await;
        let (_, op) = f.create(&browser, OperationKind::SendOnchain).await;
        let authorization = grant(&f.state, &mut browser, &op).await;
        let (status, _, _) = call(
            &f.state,
            authenticated(
                test::TestRequest::delete()
                    .uri("/api/v1/session")
                    .insert_header((header::HOST, HOST))
                    .insert_header((header::ORIGIN, ORIGIN)),
                &browser,
            ),
            "Session",
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            confirm(&f.state, &browser, &op, authorization).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            f.harness
                .scenario
                .lock()
                .unwrap()
                .calls(method(backend, OperationKind::SendOnchain)),
            0
        );
    }
}

#[actix_web::test]
async fn lost_address_response_remains_unknown_across_restart_without_redispatch() {
    for backend in [Backend::ClnRest, Backend::LndRest, Backend::LndGrpc] {
        let mut f = Journey::new(backend, false).await;
        let browser = login(&f.state, None).await;
        let (_, op) = f.create(&browser, OperationKind::NewAddress).await;
        let method = method(backend, OperationKind::NewAddress);
        f.harness
            .scenario
            .lock()
            .unwrap()
            .fault(method, Fault::TimeoutAfterEffect);
        let (status, result) = confirm(&f.state, &browser, &op, Value::Null).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(result["state"], "unknown");
        f.restart().await;
        assert_eq!(
            confirm(&f.state, &browser, &op, Value::Null).await.0,
            StatusCode::OK
        );
        assert_eq!(f.observe(&browser, &op).await["state"], "unknown");
        assert_eq!(
            confirm(&f.state, &browser, &op, Value::Null).await.0,
            StatusCode::OK
        );
        let script = f.harness.scenario.lock().unwrap();
        assert_eq!(script.calls(method), 1);
        assert_eq!(script.effects(method), 1);
        script.assert_no_unexpected_calls();
    }
}

#[actix_web::test]
async fn a_denied_macaroon_permission_refuses_the_review_before_dispatch() {
    for backend in [Backend::LndRest, Backend::LndGrpc] {
        let f = Journey::new(backend, false).await;
        let browser = login(&f.state, None).await;
        // LND answers the permission check with InvalidArgument rather than valid=false.
        // Review creation asks the node for facts twice; a real denied macaroon refuses both.
        {
            let mut script = f.harness.scenario.lock().unwrap();
            script.fault("CheckMacaroonPermissions", Fault::Reject);
            script.fault("CheckMacaroonPermissions", Fault::Reject);
        }
        let (status, value, _) = call(
            &f.state,
            authenticated(post("/api/v1/nodes/synthetic/operations"), &browser)
                .insert_header(("Idempotency-Key", Uuid::new_v4().to_string()))
                .set_json(f.request(OperationKind::CreateInvoice)),
            "ErrorResponse",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{backend:?} {value}"
        );
        assert_eq!(value["error"]["code"], "node_auth_error", "{backend:?}");
        let script = f.harness.scenario.lock().unwrap();
        assert_eq!(script.calls("AddInvoice"), 0, "{backend:?}");
        assert_eq!(script.effects("AddInvoice"), 0, "{backend:?}");
    }
}
