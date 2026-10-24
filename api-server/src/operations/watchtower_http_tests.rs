use super::*;
use synthetic_node_harness::{Fault, Harness, WatchtowerRole, PEER};

struct Fixture {
    harness: Harness,
    state: ApplicationState,
}
impl Fixture {
    async fn new(backend: Backend, role: WatchtowerRole, sessions: usize) -> Self {
        Self::with_faults(backend, role, sessions, &[]).await
    }
    async fn with_faults(
        backend: Backend,
        role: WatchtowerRole,
        sessions: usize,
        faults: &[(&str, Fault)],
    ) -> Self {
        let harness = Harness::start(backend, "127.0.0.1:0".parse().unwrap(), 45, Utc::now())
            .await
            .unwrap();
        {
            let mut scenario = harness.scenario.lock().unwrap();
            scenario.seed_watchtower(role, sessions);
            scenario.expect_mutations(&[]);
            for (method, fault) in faults {
                scenario.fault(method, fault.clone());
            }
        }
        let mut node = harness.node("synthetic");
        node.read_only = Some(true);
        let settings = Settings {
            api: ApiSettings {
                bind: "127.0.0.1:0".parse().unwrap(),
                public_origin: ORIGIN.parse().unwrap(),
                rp_id: HOST.into(),
                database: harness.directory().join("watchtower.sqlite"),
                invoice_key_file: harness.directory().join("invoice.key"),
                allow_insecure_loopback: false,
                client_identity: Default::default(),
                reauth: Default::default(),
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
        Self { harness, state }
    }
    fn availability(&self) -> ReadAvailability {
        self.state
            .registry
            .get("synthetic")
            .unwrap()
            .read_availability
            .clone()
    }
    fn no_mutations(&self) {
        let s = self.harness.scenario.lock().unwrap();
        for method in [
            "AddTower",
            "RemoveTower",
            "DeactivateTower",
            "TerminateSession",
        ] {
            assert_eq!(s.calls(method), 0);
            assert_eq!(s.effects(method), 0);
        }
        s.assert_no_unexpected_calls();
    }
}
const BACKENDS: [Backend; 2] = [Backend::LndGrpc, Backend::LndRest];
const SERVER: &str = "/api/v1/nodes/synthetic/watchtower/server";
const CLIENT: &str = "/api/v1/nodes/synthetic/watchtower/client";
const TOWERS: &str = "/api/v1/nodes/synthetic/watchtower/client/towers";

#[actix_web::test]
async fn server_read_has_no_active_field_or_clients() {
    for backend in BACKENDS {
        let f = Fixture::new(backend, WatchtowerRole::ServerOnly, 0).await;
        let browser = login(&f.state, None).await;
        assert!(f.availability().watchtower_server.enabled);
        assert_eq!(
            f.availability().watchtower_client.reason,
            Some(CapabilityReason::Unsupported)
        );
        let (status, value, _) = call(
            &f.state,
            authenticated(get(SERVER), &browser),
            "WatchtowerServerInfo",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        let _: WatchtowerServerInfo = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(value["pubkey"], PEER);
        assert!(value.get("active").is_none());
        assert!(value.get("clients").is_none());
        assert!(value.get("session_info").is_none());
        f.no_mutations();
    }
}

#[actix_web::test]
async fn client_policies_omit_unregistered_types_and_stats_are_since_startup() {
    for backend in BACKENDS {
        let f = Fixture::new(backend, WatchtowerRole::ClientOnly, 1).await;
        let browser = login(&f.state, None).await;
        assert_eq!(
            f.availability().watchtower_server.reason,
            Some(CapabilityReason::Unsupported)
        );
        assert!(f.availability().watchtower_client.enabled);
        let (status, value, _) = call(
            &f.state,
            authenticated(get(CLIENT), &browser),
            "WatchtowerClientInfo",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(
            value["policies"],
            json!([{"policy_type":"anchor","max_updates":"1024","sweep_sat_per_vbyte":"5"}])
        );
        assert_eq!(value["stats"]["scope"], "since_startup");
        assert_eq!(value["stats"]["num_ineligible_backups"], "3");
        // Three type-discovery calls at registration; reads only ask for anchor.
        assert_eq!(f.harness.scenario.lock().unwrap().calls("Policy"), 4);
        call(
            &f.state,
            authenticated(get(CLIENT), &browser),
            "WatchtowerClientInfo",
        )
        .await;
        assert_eq!(f.harness.scenario.lock().unwrap().calls("Policy"), 4);
        f.no_mutations();
    }
}

#[actix_web::test]
async fn tower_detail_caps_sessions_and_marks_truncation_without_list_sessions() {
    for backend in BACKENDS {
        let f = Fixture::new(backend, WatchtowerRole::Both, 260).await;
        let browser = login(&f.state, None).await;
        let (status, page, _) = call(
            &f.state,
            authenticated(get(&format!("{TOWERS}?limit=1")), &browser),
            "WatchtowerTowersPage",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let page: Page<WatchtowerTower> = serde_json::from_value(page.clone()).unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].session_info[0].num_sessions.get(), 260);
        let (status, detail, _) = call(
            &f.state,
            authenticated(get(&format!("{TOWERS}/{PEER}")), &browser),
            "WatchtowerTowerDetail",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        let detail: WatchtowerTowerDetail = serde_json::from_value(detail).unwrap();
        let info = &detail.session_info[0];
        assert_eq!(info.sessions.len(), 256);
        assert!(info.sessions_truncated);
        assert_eq!(info.num_sessions.get(), 260);
        use base64::Engine as _;
        for session in &info.sessions {
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(&session.id)
                    .unwrap()
                    .len(),
                33
            );
        }
        f.no_mutations();
    }
}

#[actix_web::test]
async fn denied_watchtower_macaroon_preserves_node_status_and_reports_permission_denied() {
    for backend in BACKENDS {
        let f = Fixture::new(backend, WatchtowerRole::DeniedMacaroon, 0).await;
        f.state.refresh_node("synthetic").await.unwrap();
        let entry = f.state.registry.get("synthetic").unwrap();
        // Hold summary time constant: these reads must not alter node status,
        // but wall-clock aging alone can mark the observation stale.
        let now = Utc::now();
        let before = serde_json::to_value(entry.summary(now, Decimal::ZERO).status).unwrap();
        assert_eq!(before["status"], "online");
        let browser = login(&f.state, None).await;
        for path in [
            SERVER.to_owned(),
            CLIENT.to_owned(),
            TOWERS.to_owned(),
            format!("{TOWERS}/{PEER}"),
        ] {
            let (status, error, _) = call(
                &f.state,
                authenticated(get(&path), &browser),
                "ErrorResponse",
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT, "{error}");
            assert_eq!(error["error"]["code"], "unsupported");
            assert_eq!(error["error"]["message"], "permission_denied");
        }
        assert_eq!(
            before,
            serde_json::to_value(entry.summary(now, Decimal::ZERO).status).unwrap()
        );
        assert_eq!(f.harness.scenario.lock().unwrap().calls("Stats"), 1);
        assert_eq!(f.harness.scenario.lock().unwrap().calls("TowerGetInfo"), 1);
        f.no_mutations();
    }
}

#[actix_web::test]
async fn inactive_server_reports_not_configured_without_failing_registration() {
    for backend in BACKENDS {
        let f = Fixture::new(backend, WatchtowerRole::InactiveServer, 0).await;
        assert_eq!(
            f.availability().watchtower_server.reason,
            Some(CapabilityReason::NotConfigured)
        );
        assert!(f.availability().channels.enabled);
        let browser = login(&f.state, None).await;
        let (status, error, _) = call(
            &f.state,
            authenticated(get(SERVER), &browser),
            "ErrorResponse",
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(error["error"]["code"], "unsupported");
        assert_eq!(error["error"]["message"], "not_configured");
        f.state.refresh_node("synthetic").await.unwrap();
        assert_eq!(
            f.state
                .registry
                .get("synthetic")
                .unwrap()
                .summary(Utc::now(), Decimal::ZERO)
                .status
                .status,
            NodeConnection::Online
        );
        f.no_mutations();
    }
}

#[actix_web::test]
async fn read_only_node_serves_all_client_reads_and_both_roles() {
    for backend in BACKENDS {
        let f = Fixture::new(backend, WatchtowerRole::Both, 1).await;
        let browser = login(&f.state, None).await;
        assert!(
            f.state
                .registry
                .get("synthetic")
                .unwrap()
                .policy
                .as_ref()
                .unwrap()
                .read_only
        );
        assert!(f.availability().watchtower_client.enabled);
        assert!(f.availability().watchtower_server.enabled);
        for (path, schema) in [
            (CLIENT.to_owned(), "WatchtowerClientInfo"),
            (TOWERS.to_owned(), "WatchtowerTowersPage"),
            (format!("{TOWERS}/{PEER}"), "WatchtowerTowerDetail"),
        ] {
            let (status, value, _) =
                call(&f.state, authenticated(get(&path), &browser), schema).await;
            assert_eq!(status, StatusCode::OK, "{value}");
        }
        f.no_mutations();
    }
}

#[actix_web::test]
async fn watchtower_probe_failures_are_cached_and_do_not_mark_node_offline() {
    for backend in BACKENDS {
        let f = Fixture::with_faults(
            backend,
            WatchtowerRole::Both,
            0,
            &[
                ("TowerGetInfo", Fault::Malformed),
                ("Stats", Fault::Malformed),
            ],
        )
        .await;
        assert_eq!(
            f.availability().watchtower_server.reason,
            Some(CapabilityReason::NotConfigured)
        );
        assert_eq!(
            f.availability().watchtower_client.reason,
            Some(CapabilityReason::NotConfigured)
        );
        assert!(f.availability().channels.enabled);
        f.state.refresh_node("synthetic").await.unwrap();
        assert_eq!(
            f.state
                .registry
                .get("synthetic")
                .unwrap()
                .summary(Utc::now(), Decimal::ZERO)
                .status
                .status,
            NodeConnection::Online
        );
        let browser = login(&f.state, None).await;
        for path in [SERVER, CLIENT, SERVER, CLIENT] {
            let (status, error, _) = call(
                &f.state,
                authenticated(get(path), &browser),
                "ErrorResponse",
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(error["error"]["message"], "not_configured");
        }
        assert_eq!(f.harness.scenario.lock().unwrap().calls("Stats"), 1);
        assert_eq!(f.harness.scenario.lock().unwrap().calls("TowerGetInfo"), 1);
        f.no_mutations();
    }
}

#[actix_web::test]
async fn watchtower_snapshots_mark_stale_but_expired_tower_detail_fails_closed() {
    for backend in BACKENDS {
        let f = Fixture::new(backend, WatchtowerRole::Both, 1).await;
        let browser = login(&f.state, None).await;
        let detail = format!("{TOWERS}/{PEER}");
        let reads = [
            (SERVER, "WatchtowerServerInfo", "TowerGetInfo"),
            (CLIENT, "WatchtowerClientInfo", "Stats"),
            (TOWERS, "WatchtowerTowersPage", "ListTowers"),
            (detail.as_str(), "WatchtowerTowerDetail", "GetTowerInfo"),
        ];
        for (path, schema, method) in reads {
            let (status, value, _) =
                call(&f.state, authenticated(get(path), &browser), schema).await;
            assert_eq!(status, StatusCode::OK, "{value}");
            f.harness
                .scenario
                .lock()
                .unwrap()
                .fault(method, Fault::Reject);
        }
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        for (path, schema, _) in reads {
            let (status, value, _) =
                call(&f.state, authenticated(get(path), &browser), schema).await;
            if path == detail {
                assert_eq!(status, StatusCode::CONFLICT, "{value}");
                assert_eq!(value["error"]["code"], "upstream_rejected");
            } else {
                assert_eq!(status, StatusCode::OK, "{value}");
                assert_eq!(value["stale"], true);
            }
        }
        f.no_mutations();
    }
}

#[actix_web::test]
async fn watchtower_permission_revocation_is_reported_without_new_probes() {
    for backend in BACKENDS {
        let f = Fixture::new(backend, WatchtowerRole::Both, 1).await;
        let browser = login(&f.state, None).await;
        f.state.refresh_node("synthetic").await.unwrap();
        let entry = f.state.registry.get("synthetic").unwrap();
        // Compare at one instant so only changes caused by the reads are visible.
        let now = Utc::now();
        let before = serde_json::to_value(entry.summary(now, Decimal::ZERO).status).unwrap();
        // Exercise an explicit PermissionDenied status as well as LND's plain error.
        f.harness
            .scenario
            .lock()
            .unwrap()
            .fault("Stats", Fault::PermissionDenied);
        let (status, error, _) = call(
            &f.state,
            authenticated(get(CLIENT), &browser),
            "ErrorResponse",
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(error["error"]["message"], "permission_denied");
        f.harness
            .scenario
            .lock()
            .unwrap()
            .seed_watchtower(WatchtowerRole::DeniedMacaroon, 1);
        for path in [
            SERVER.to_owned(),
            CLIENT.to_owned(),
            TOWERS.to_owned(),
            format!("{TOWERS}/{PEER}"),
        ] {
            let (status, error, _) = call(
                &f.state,
                authenticated(get(&path), &browser),
                "ErrorResponse",
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT, "{error}");
            assert_eq!(error["error"]["message"], "permission_denied");
        }
        assert_eq!(
            before,
            serde_json::to_value(entry.summary(now, Decimal::ZERO).status).unwrap()
        );
        assert_eq!(f.harness.scenario.lock().unwrap().calls("Policy"), 3);
        assert!(f.availability().watchtower_client.enabled);
        f.no_mutations();
    }
}
