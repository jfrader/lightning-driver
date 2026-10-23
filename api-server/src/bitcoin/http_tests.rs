use super::*;
use lightning_client::money::Decimal;
use synthetic_node_harness::{BitcoinFault, BitcoinHarness};

struct Fixture {
    _directory: tempfile::TempDir,
    harness: BitcoinHarness,
    state: ApplicationState,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_limits(Limits::default()).await
    }
    async fn with_limits(limits: Limits) -> Self {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let harness = BitcoinHarness::start().await.unwrap();
        let settings = Settings {
            api: ApiSettings {
                bind: "127.0.0.1:0".parse().unwrap(),
                public_origin: ORIGIN.parse().unwrap(),
                rp_id: HOST.into(),
                database: directory.path().join("journal.sqlite"),
                invoice_key_file: directory.path().join("invoice.key"),
                allow_insecure_loopback: false,
                client_identity: Default::default(),
                reauth: Default::default(),
                limits,
            },
            nodes: vec![harness.settings()],
        };
        let state = ApplicationState::new(
            &settings,
            Journal::open(settings.api.database.clone()).await.unwrap(),
        )
        .await
        .unwrap();
        Self {
            _directory: directory,
            harness,
            state,
        }
    }
}
#[actix_web::test]
async fn synced_node_serves_contract_shape() {
    let f = Fixture::new().await;
    let browser = login(&f.state, None).await;
    let (status, value, _) = call(
        &f.state,
        authenticated(get("/api/v1/nodes/bitcoin-lab/bitcoin"), &browser),
        "BitcoinNodeInfo",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let info: BitcoinNodeInfo = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(info.network, Network::Regtest);
    assert_eq!(info.verification_progress_bp.get(), 10000);
    assert!(!info.stale);
    assert!(!info.initial_block_download);
    assert!(value["prune_height"].is_null());
    let (status, peers, _) = call(
        &f.state,
        authenticated(
            get("/api/v1/nodes/bitcoin-lab/bitcoin/peers?limit=1"),
            &browser,
        ),
        "BitcoinPeersPage",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let page: Page<BitcoinPeer> = serde_json::from_value(peers).unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.network, Some(Network::Regtest));
    assert_eq!(page.items[0].ping_ms.unwrap().get(), 12);
    let (status, summary, _) = call(
        &f.state,
        authenticated(get("/api/v1/nodes/bitcoin-lab"), &browser),
        "NodeSummary",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(summary["kind"], "bitcoin");
    assert!(summary["identity_pubkey"].is_null());
    assert!(!summary["identity_revision"].as_str().unwrap().is_empty());
    assert_eq!(
        summary["read_availability"]["bitcoin"],
        json!({"enabled":true,"reason":null})
    );
    for capability in summary["capabilities"].as_object().unwrap().values() {
        assert_eq!(
            capability,
            &json!({"enabled":false,"reason":"monitor_only"})
        );
    }
    assert!(f.state.engine.nodes.is_empty());
    assert!(f
        .state
        .registry
        .get("bitcoin-lab")
        .unwrap()
        .policy
        .is_none());
    assert_eq!(f.harness.scenario.lock().unwrap().wallet_sentinel_calls, 0);
}
#[actix_web::test]
async fn oversized_body_fails_closed_without_poisoning_node_status() {
    let f = Fixture::new().await;
    let browser = login(&f.state, None).await;
    f.state.refresh_node("bitcoin-lab").await.unwrap();
    let before = f
        .state
        .registry
        .get("bitcoin-lab")
        .unwrap()
        .summary(Utc::now(), Decimal::ZERO)
        .status;
    for (method, path, schema) in [
        (
            "getpeerinfo",
            "/api/v1/nodes/bitcoin-lab/bitcoin/peers",
            "BitcoinPeersPage",
        ),
        (
            "getblockchaininfo",
            "/api/v1/nodes/bitcoin-lab/bitcoin",
            "BitcoinNodeInfo",
        ),
    ] {
        for chunked in [false, true] {
            {
                let mut state = f.harness.scenario.lock().unwrap();
                let size = f.state.limits().max_response_bytes + 1;
                state.fault = if chunked {
                    BitcoinFault::ChunkedOversized(size)
                } else {
                    BitcoinFault::Oversized(size)
                };
                state.fault_method = Some(method.into());
            }
            let (status, error, _) =
                call(&f.state, authenticated(get(path), &browser), schema).await;
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            assert_eq!(error["error"]["code"], "upstream_invalid_response");
            let after = f
                .state
                .registry
                .get("bitcoin-lab")
                .unwrap()
                .summary(Utc::now(), Decimal::ZERO)
                .status;
            assert_eq!(
                serde_json::to_value(&before).unwrap(),
                serde_json::to_value(after).unwrap()
            );
        }
    }
}
#[actix_web::test]
async fn identity_change_is_not_hidden_by_a_stale_bitcoin_snapshot() {
    let f = Fixture::with_limits(Limits {
        rpc_seconds: 1,
        ..Limits::default()
    })
    .await;
    let browser = login(&f.state, None).await;
    f.state
        .observed("bitcoin-lab", "bitcoin", ReadQuery::Bitcoin)
        .await
        .unwrap();
    assert!(f.state.registry.retained_bytes() > 0);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    f.harness.scenario.lock().unwrap().wrong_genesis = true;
    let (status, error, _) = call(
        &f.state,
        authenticated(get("/api/v1/nodes/bitcoin-lab/bitcoin"), &browser),
        "ErrorResponse",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"]["code"], "identity_changed");
    assert_eq!(f.state.registry.retained_bytes(), 0);
}
#[actix_web::test]
async fn bitcoin_reads_keep_the_previous_snapshot_marked_stale_on_rpc_failure() {
    let f = Fixture::with_limits(Limits {
        rpc_seconds: 1,
        ..Limits::default()
    })
    .await;
    let browser = login(&f.state, None).await;
    f.state
        .observed("bitcoin-lab", "bitcoin", ReadQuery::Bitcoin)
        .await
        .unwrap();
    f.state
        .observed("bitcoin-lab", "bitcoin-peers", ReadQuery::BitcoinPeers)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    f.harness.scenario.lock().unwrap().fault = BitcoinFault::Auth;
    for (path, schema) in [
        ("/api/v1/nodes/bitcoin-lab/bitcoin", "BitcoinNodeInfo"),
        (
            "/api/v1/nodes/bitcoin-lab/bitcoin/peers",
            "BitcoinPeersPage",
        ),
    ] {
        let (status, value, _) = call(&f.state, authenticated(get(path), &browser), schema).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["stale"], true);
    }
}
#[actix_web::test]
async fn unsupported_bitcoin_surface_returns_availability_reason() {
    let f = HttpFixture::new().await;
    let browser = login(&f.state, None).await;
    for path in [
        "/api/v1/nodes/synthetic/bitcoin",
        "/api/v1/nodes/synthetic/bitcoin/peers",
    ] {
        let (status, error, _) = call(
            &f.state,
            authenticated(get(path), &browser),
            "ErrorResponse",
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(error["error"]["code"], "unsupported");
        assert_eq!(error["error"]["message"], "unsupported");
    }
}
