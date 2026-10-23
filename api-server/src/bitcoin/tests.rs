use super::*;
use crate::operations::{ReadQuery, ReadResult, Reads};
use lightning_client::{model::ErrorCode, settings::Limits};
use synthetic_node_harness::{BitcoinFault, BitcoinHarness};

async fn adapter(harness: &BitcoinHarness) -> BitcoinReads {
    BitcoinReads::connect(&harness.settings(), &Limits::default())
        .await
        .unwrap()
}
#[tokio::test]
async fn loaded_wallet_sentinel_is_never_called() {
    let harness = BitcoinHarness::start().await.unwrap();
    let reads = adapter(&harness).await;
    for query in [ReadQuery::Info, ReadQuery::Bitcoin, ReadQuery::BitcoinPeers] {
        reads.read(query).await.unwrap();
    }
    assert_eq!(
        reads.read(ReadQuery::Balances).await.err().unwrap().code(),
        ErrorCode::Unsupported
    );
    let state = harness.scenario.lock().unwrap();
    assert_eq!(state.wallet_sentinel_calls, 0);
    assert!(state.calls.iter().all(|method| [
        "getblockhash",
        "getblockchaininfo",
        "getnetworkinfo",
        "getmempoolinfo",
        "getpeerinfo",
        "uptime"
    ]
    .contains(&method.as_str())));
    assert_eq!(
        state
            .calls
            .iter()
            .filter(|method| *method == "getpeerinfo")
            .count(),
        1
    );
}
#[tokio::test]
async fn wrong_genesis_is_identity_changed() {
    let harness = BitcoinHarness::start().await.unwrap();
    harness.scenario.lock().unwrap().wrong_genesis = true;
    let reads = adapter(&harness).await;
    for query in [ReadQuery::Info, ReadQuery::Bitcoin, ReadQuery::BitcoinPeers] {
        assert_eq!(
            reads.read(query).await.err().unwrap().code(),
            ErrorCode::IdentityChanged
        );
    }
    assert!(harness
        .scenario
        .lock()
        .unwrap()
        .calls
        .iter()
        .all(|method| method == "getblockhash"));
}
#[tokio::test]
async fn auth_failure_is_node_auth_error() {
    let harness = BitcoinHarness::start().await.unwrap();
    harness.scenario.lock().unwrap().fault = BitcoinFault::Auth;
    assert_eq!(
        adapter(&harness)
            .await
            .read(ReadQuery::Bitcoin)
            .await
            .err()
            .unwrap()
            .code(),
        ErrorCode::NodeAuthError
    );
}
#[tokio::test]
async fn cookie_rotation_is_observed_without_reconstructing_transport() {
    let harness = BitcoinHarness::start().await.unwrap();
    let reads = adapter(&harness).await;
    reads.read(ReadQuery::Bitcoin).await.unwrap();
    harness.rotate_cookie().unwrap();
    reads.read(ReadQuery::Bitcoin).await.unwrap();
    assert_eq!(
        harness
            .scenario
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|method| *method == "uptime")
            .count(),
        1
    );
}
#[tokio::test]
async fn rpc_errors_on_http_500_are_parsed_and_ids_and_redirects_fail_closed() {
    let harness = BitcoinHarness::start().await.unwrap();
    let reads = adapter(&harness).await;
    for (fault, code) in [
        (BitcoinFault::Rpc500, ErrorCode::NodeAuthError),
        (BitcoinFault::WrongId, ErrorCode::UpstreamInvalidResponse),
        (BitcoinFault::Redirect, ErrorCode::NodeOffline),
    ] {
        harness.scenario.lock().unwrap().fault = fault;
        assert_eq!(
            reads.read(ReadQuery::Bitcoin).await.err().unwrap().code(),
            code
        );
    }
}
#[tokio::test]
async fn ibd_pruning_warnings_and_absent_peer_values_are_projected() {
    let harness = BitcoinHarness::start().await.unwrap();
    let reads = adapter(&harness).await;
    for legacy in [false, true] {
        {
            let mut state = harness.scenario.lock().unwrap();
            state.ibd = true;
            state.pruned = true;
            state.legacy_warnings = legacy;
        }
        let ReadResult::Bitcoin(info) = reads.read(ReadQuery::Bitcoin).await.unwrap() else {
            panic!("Bitcoin info expected")
        };
        assert!(info.initial_block_download);
        assert!(info.pruned);
        assert_eq!(info.prune_height.unwrap().get(), 100);
        assert_eq!(info.verification_progress_bp.get(), 5000);
        assert_eq!(info.warnings, vec!["Chain warning", "Network warning"]);
        assert!(info.connections_in.is_none());
        assert!(info.connections_out.is_none());
    }
    let ReadResult::BitcoinPeers(peers) = reads.read(ReadQuery::BitcoinPeers).await.unwrap() else {
        panic!("Bitcoin peers expected")
    };
    assert_eq!(peers.items[0].ping_ms.unwrap().get(), 12);
    assert!(peers.items[0].synced_blocks.is_none());
    assert!(peers.items[0].synced_headers.is_none());
}
#[tokio::test]
async fn plaintext_remote_addresses_are_rejected_before_rpc_contact() {
    let harness = BitcoinHarness::start().await.unwrap();
    let mut settings = harness.settings();
    settings.endpoint = "http://192.0.2.1".parse().unwrap();
    assert_eq!(
        BitcoinReads::connect(&settings, &Limits::default())
            .await
            .err()
            .unwrap()
            .code(),
        ErrorCode::NotConfigured
    );
    assert!(harness.scenario.lock().unwrap().calls.is_empty());
}
