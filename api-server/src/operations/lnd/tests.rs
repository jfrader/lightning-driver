use super::*;
use hyper::{service::service_fn, Body, Request, Response};
use lightning_client::{
    money::Sat,
    settings::{Limits, NodeSettings},
};
use lnd_grpc_rust::{lnrpc as ln, prost::Message, routerrpc as router};
use std::{collections::VecDeque, os::unix::fs::PermissionsExt, time::Duration};
use tokio::{net::TcpListener, task::JoinHandle};
use transport::{CallError, Rest};

const FIXTURE: &str = include_str!("../../../tests/fixtures/lnd-v0.18.5-beta/synthetic.json");
const MAC: &[u8] = b"SYNTHETIC_BINARY_MACAROON\x00\xff";
fn fixture() -> Value {
    serde_json::from_str(FIXTURE).unwrap()
}
fn peer() -> String {
    fixture()["info"]["identity_pubkey"]
        .as_str()
        .unwrap()
        .into()
}
fn hash() -> String {
    fixture()["payments"]["payments"][0]["payment_hash"]
        .as_str()
        .unwrap()
        .into()
}
fn txid() -> String {
    fixture()["send"]["txid"].as_str().unwrap().into()
}
fn point() -> String {
    format!("{}:1", txid())
}
fn d(n: u64) -> Decimal {
    Decimal::new(n).unwrap()
}
fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_750_000_000, 0).unwrap()
}
fn config(backend: Backend) -> NodeConfig {
    let examples: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/api-examples.json")).unwrap();
    let mut policy: NodePolicy =
        serde_json::from_value(examples["fixtures"]["node_policy"]["value"].clone()).unwrap();
    policy.node_id = "synthetic".into();
    policy.read_only = false;
    NodeConfig {
        binding: NodeBinding {
            node_id: "synthetic".into(),
            network: VerifiedNetwork::Regtest,
            identity_pubkey: peer(),
            identity_revision: "synthetic-revision".into(),
        },
        generation: Uuid::new_v4(),
        backend,
        policy,
        peer_policy: PeerPolicy {
            allowed_hosts: vec!["peer.invalid".into()],
            allowed_ports: vec![9735],
        },
        reauth_mode: ReauthMode::EveryOperation,
        capabilities: Capabilities::uniform(None),
        review_seconds: 300,
        freshness_seconds: 30,
    }
}
fn address() -> String {
    bitcoin::Address::p2wpkh(
        &bitcoin::CompressedPublicKey(peer().parse().unwrap()),
        bitcoin::Network::Regtest,
    )
    .to_string()
}
fn invoice() -> String {
    use bitcoin::{
        hashes::{sha256, Hash},
        secp256k1::{Secp256k1, SecretKey},
    };
    lightning_invoice::InvoiceBuilder::new(lightning_invoice::Currency::Regtest)
        .description("Synthetic invoice".into())
        .payment_hash(sha256::Hash::hash(&[77; 32]))
        .payment_secret(lightning_invoice::PaymentSecret([44; 32]))
        .duration_since_epoch(Duration::from_secs(now().timestamp() as u64))
        .expiry_time(Duration::from_secs(3600))
        .min_final_cltv_expiry_delta(18)
        .amount_milli_satoshis(1001)
        .build_signed(|h| {
            Secp256k1::new().sign_ecdsa_recoverable(h, &SecretKey::from_slice(&[42; 32]).unwrap())
        })
        .unwrap()
        .to_string()
}
fn request(kind: OperationKind) -> OperationRequest {
    match kind {
        OperationKind::CreateInvoice => OperationRequest::CreateInvoice(CreateInvoice {
            amount_msat: Msat(d(1001)),
            description: "Synthetic invoice".into(),
            expiry_seconds: 3600,
        }),
        OperationKind::PayInvoice => OperationRequest::PayInvoice(PayInvoice {
            bolt11: invoice(),
            amount_msat: None,
            max_fee_msat: Msat(d(1000)),
            description: None,
        }),
        OperationKind::ConnectPeer => OperationRequest::ConnectPeer(ConnectPeer {
            pubkey: peer(),
            host: "peer.invalid".into(),
            port: 9735,
        }),
        OperationKind::DisconnectPeer => {
            OperationRequest::DisconnectPeer(DisconnectPeer { pubkey: peer() })
        }
        OperationKind::OpenChannel => OperationRequest::OpenChannel(OpenChannel {
            peer_pubkey: peer(),
            amount_sat: Sat(d(100000)),
            private: true,
            fee_rate_sat_vbyte: d(1),
        }),
        OperationKind::CloseChannel => OperationRequest::CloseChannel(CloseChannel {
            channel_id: point(),
            fee_rate_sat_vbyte: d(1),
        }),
        OperationKind::NewAddress => OperationRequest::NewAddress(NewAddress {
            address_type: AddressType::P2wpkh,
        }),
        OperationKind::SendOnchain => OperationRequest::SendOnchain(SendOnchain {
            address: address(),
            amount_sat: Sat(d(10000)),
            fee_rate_sat_vbyte: d(1),
        }),
    }
}
fn reviewed(kind: OperationKind, c: &NodeConfig) -> ReviewedIntent {
    let f = ReadFacts {
        binding: c.binding.clone(),
        generation: c.generation,
        observed_at: now(),
        connection: NodeConnection::Online,
        sync_usable: true,
        permission: true,
        peer_connected: true,
        close_target: Some(point()),
        close_peer: Some(peer()),
    };
    let mut intent = ReviewedIntent::build(request(kind), c, &f, now())
        .unwrap()
        .0;
    // A deterministic synthetic protected preimage replaces engine RNG solely in
    // this fixture. Production generation remains owned by ReviewedIntent.
    if kind == OperationKind::CreateInvoice {
        intent.operation.review.payment_hash = Some(hash());
    }
    intent
}
fn permit(intent: ReviewedIntent) -> ClaimPermit {
    ClaimPermit {
        claim_id: Uuid::new_v4(),
        secret: (intent.operation.request.kind() == OperationKind::CreateInvoice)
            .then(|| zeroize::Zeroizing::new([77; 32])),
        intent,
    }
}
fn query(intent: &ReviewedIntent, reference: RecoveryReference) -> ObservationQuery {
    ObservationQuery {
        request: intent.operation.request.clone(),
        operation_id: intent.operation.id,
        binding: intent.operation.review.node.clone(),
        generation: intent.connection_generation,
        kind: intent.operation.request.kind(),
        claim_id: Uuid::new_v4(),
        sequence: 1,
        reference,
        close_type: None,
        close_txids: vec![],
    }
}
fn settings(dir: &std::path::Path, endpoint: url::Url, backend: Backend) -> NodeSettings {
    let cert = dir.join("synthetic-ca.pem");
    let mac = dir.join("synthetic-binary-macaroon");
    std::fs::write(
        &cert,
        include_bytes!("../../../tests/fixtures/cln-v25.02/synthetic-ca.pem"),
    )
    .unwrap();
    std::fs::write(&mac, MAC).unwrap();
    std::fs::set_permissions(&mac, std::fs::Permissions::from_mode(0o600)).unwrap();
    NodeSettings {
        id: "synthetic".into(),
        label: "Synthetic".into(),
        backend,
        endpoint,
        certificate_file: cert,
        credential_file: mac,
        expected_pubkey: peer(),
        network: Network::Regtest,
        read_only: false,
        policy: config(backend).policy.limits,
        peer_policy: PeerPolicy::default(),
    }
}
fn grpc_frame<M: Message>(m: M) -> Vec<u8> {
    let b = m.encode_to_vec();
    let mut frame = vec![0];
    frame.extend_from_slice(&(b.len() as u32).to_be_bytes());
    frame.extend_from_slice(&b);
    frame
}
struct Step {
    method: &'static str,
    path: String,
    status: u16,
    chunks: Vec<Vec<u8>>,
    grpc_code: Option<i32>,
    location: Option<String>,
    delay: Duration,
}
impl Step {
    fn rest(method: &'static str, path: &str, v: Value) -> Self {
        Self::raw(method, path, serde_json::to_vec(&v).unwrap())
    }
    fn raw(method: &'static str, path: &str, b: Vec<u8>) -> Self {
        Self {
            method,
            path: path.into(),
            status: 200,
            chunks: b.chunks(7).map(|b| b.to_vec()).collect(),
            grpc_code: None,
            location: None,
            delay: Duration::ZERO,
        }
    }
    fn grpc(rpc: Rpc, frames: Vec<Vec<u8>>) -> Self {
        Self {
            method: "POST",
            path: rpc.method().into(),
            status: 200,
            chunks: frames
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .chunks(7)
                .map(|b| b.to_vec())
                .collect(),
            grpc_code: Some(0),
            location: None,
            delay: Duration::ZERO,
        }
    }
}
#[derive(Clone)]
struct Captured {
    method: String,
    path: String,
    headers: hyper::HeaderMap,
    body: Vec<u8>,
}
struct Server {
    endpoint: url::Url,
    task: JoinHandle<()>,
    captures: Arc<Mutex<Vec<Captured>>>,
    steps: Arc<Mutex<VecDeque<Step>>>,
}
impl Server {
    async fn start(grpc: bool, steps: Vec<Step>) -> Self {
        use tokio_rustls::{
            rustls::{Certificate, PrivateKey, ServerConfig},
            TlsAcceptor,
        };
        let mut cfg = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(
                vec![Certificate(
                    include_bytes!("../../../tests/fixtures/cln-v25.02/synthetic-cert.der")
                        .to_vec(),
                )],
                PrivateKey(
                    include_bytes!("../../../tests/fixtures/cln-v25.02/synthetic-key.der").to_vec(),
                ),
            )
            .unwrap();
        cfg.alpn_protocols = if grpc {
            vec![b"h2".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let acceptor = TlsAcceptor::from(Arc::new(cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "https://localhost:{}/",
            listener.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();
        let captures = Arc::new(Mutex::new(Vec::new()));
        let steps = Arc::new(Mutex::new(VecDeque::from(steps)));
        let cap = captures.clone();
        let queue = steps.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let cap = cap.clone();
                let queue = queue.clone();
                connections.spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = service_fn(move |req: Request<Body>| {
                        let cap = cap.clone();
                        let queue = queue.clone();
                        async move {
                            let (parts, body) = req.into_parts();
                            let body = hyper::body::to_bytes(body).await.unwrap().to_vec();
                            let step = queue
                                .lock()
                                .unwrap()
                                .pop_front()
                                .expect("unexpected invocation/retry");
                            assert_eq!(parts.method.as_str(), step.method);
                            assert_eq!(parts.uri.path(), step.path);
                            cap.lock().unwrap().push(Captured {
                                method: parts.method.to_string(),
                                path: parts.uri.to_string(),
                                headers: parts.headers,
                                body,
                            });
                            tokio::time::sleep(step.delay).await;
                            let (mut sender, body) = Body::channel();
                            tokio::spawn(async move {
                                for chunk in step.chunks {
                                    if sender.send_data(chunk.into()).await.is_err() {
                                        return;
                                    }
                                }
                                if let Some(code) = step.grpc_code {
                                    let mut trailers = hyper::HeaderMap::new();
                                    trailers
                                        .insert("grpc-status", code.to_string().parse().unwrap());
                                    trailers.insert(
                                        "grpc-message",
                                        "UPSTREAM_SENTENCE_CANARY".parse().unwrap(),
                                    );
                                    let _ = sender.send_trailers(trailers).await;
                                }
                            });
                            let mut response = Response::builder().status(step.status).header(
                                "content-type",
                                if grpc {
                                    "application/grpc"
                                } else {
                                    "application/json"
                                },
                            );
                            if let Some(location) = step.location {
                                response = response.header("location", location);
                            }
                            Ok::<_, std::convert::Infallible>(response.body(body).unwrap())
                        }
                    });
                    let mut http = hyper::server::conn::Http::new();
                    http.http2_only(grpc);
                    let _ = http.serve_connection(tls, service).await;
                });
            }
        });
        Self {
            endpoint,
            task,
            captures,
            steps,
        }
    }
    async fn stop(self, expected: usize) -> Vec<Captured> {
        self.task.abort();
        let _ = self.task.await;
        let captures = self.captures.lock().unwrap().clone();
        assert_eq!(captures.len(), expected);
        if expected > 0 {
            assert!(
                self.steps.lock().unwrap().is_empty(),
                "unused scripted calls"
            );
        }
        captures
    }
}
fn rest_adapter(transport: Rest, c: NodeConfig) -> LndRestAdapter {
    LndAdapter {
        transport,
        config: c,
        max_items: 100,
    }
}
fn grpc_adapter(transport: grpc::Grpc, c: NodeConfig) -> LndGrpcAdapter {
    LndAdapter {
        transport,
        config: c,
        max_items: 100,
    }
}
fn rpc_info() -> ln::GetInfoResponse {
    ln::GetInfoResponse {
        identity_pubkey: peer(),
        alias: "Synthetic".into(),
        version: "0.18.5-beta synthetic".into(),
        chains: vec![ln::Chain {
            network: "regtest".into(),
            ..Default::default()
        }],
        synced_to_chain: true,
        synced_to_graph: false,
        block_height: 100,
        ..Default::default()
    }
}
fn rpc_payment(status: i32) -> ln::Payment {
    ln::Payment {
        payment_hash: hash(),
        value_msat: 1001,
        fee_msat: 2,
        creation_time_ns: 1_750_000_000_123_456_789,
        payment_index: 7,
        status,
        payment_preimage: "PREIMAGE_CANARY".into(),
        ..Default::default()
    }
}
fn rpc_invoice() -> ln::Invoice {
    ln::Invoice {
        r_hash: hex::decode(hash()).unwrap(),
        value_msat: 1001,
        amt_paid_msat: 1002,
        state: 1,
        creation_date: 1_750_000_000,
        settle_date: 1_750_000_020,
        expiry: 3600,
        payment_request: invoice(),
        memo: "Synthetic invoice".into(),
        r_preimage: vec![77; 32],
        ..Default::default()
    }
}
fn no_secrets(value: impl Serialize) {
    let text = serde_json::to_string(&value).unwrap();
    for canary in [
        "PREIMAGE_CANARY",
        "HTLC_PREIMAGE_CANARY",
        "RAW_TX_CANARY",
        "PSBT_CANARY",
        "UPSTREAM_SENTENCE_CANARY",
        "SYNTHETIC_BINARY_MACAROON",
        "https://localhost",
        &hex::encode(MAC),
        &hex::encode([77; 32]),
    ] {
        assert!(!text.contains(canary), "leaked {canary}");
    }
}
fn emit(name: &str, schema: &str, value: impl Serialize) {
    no_secrets(&value);
    if let Ok(dir) = std::env::var("LND_EVIDENCE_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            std::path::Path::new(&dir).join(format!("{name}.json")),
            serde_json::to_vec_pretty(&json!({"schema":schema,"value":value})).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn tagged_read_mappings_preserve_units_presence_states_and_timestamps() {
    let f = fixture();
    let info = reads::info(&f["info"]).unwrap();
    assert_eq!(info.network, Network::Regtest);
    assert_eq!(info.graph_synced, Some(false));
    let b = reads::balances(
        &f["wallet"],
        &f["channel_balance"],
        "synthetic",
        Network::Regtest,
        now(),
    )
    .unwrap();
    assert_eq!(b.onchain_confirmed_sat, Some(Sat(d(9_007_199_254_740_993))));
    assert_eq!(b.onchain_spendable_sat, Some(Sat(d(9_007_199_254_740_988))));
    assert_eq!(b.onchain_unconfirmed_sat, Some(Sat(d(0))));
    assert_eq!(b.channel_local_msat, Some(Msat(d(1001))));
    assert!(b.channel_spendable_msat.is_none());
    emit("balances", "Balances", b);
    let invoices = reads::invoices(&f["invoices"], 100).unwrap();
    assert_eq!(invoices.items[0].state, InvoiceState::Paid);
    assert_eq!(invoices.items[0].received_msat, Some(Msat(d(1002))));
    assert_eq!(
        invoices.items[0].expires_at.unwrap().timestamp(),
        1_750_003_600
    );
    for (state, expected) in [
        ("OPEN", InvoiceState::Unpaid),
        ("SETTLED", InvoiceState::Paid),
        ("CANCELED", InvoiceState::Canceled),
        ("ACCEPTED", InvoiceState::Accepted),
        ("FUTURE", InvoiceState::Unknown),
    ] {
        let mut v = f["invoices"].clone();
        v["invoices"][0]["state"] = json!(state);
        v["invoices"][0]["value_msat"] = json!("0");
        v["invoices"][0]["amt_paid_msat"] = json!("0");
        let row = reads::invoices(&v, 100).unwrap().items.remove(0);
        assert_eq!(row.state, expected);
        assert!(row.amount_msat.is_none());
        assert_eq!(
            row.received_msat.is_some(),
            matches!(expected, InvoiceState::Paid | InvoiceState::Accepted)
        );
    }
    let p = reads::payments(&f["payments"], 100).unwrap();
    assert_eq!(p.items[0].created_at.timestamp_subsec_nanos(), 123_456_789);
    assert!(p.items[0].destination.is_none());
    assert!(p.items[0].completed_at.is_none());
    assert_eq!(p.items[0].amount_msat, Some(Msat(d(1001))));
    no_secrets(&p.items);
    for (state, expected) in [
        ("INITIATED", PaymentState::Pending),
        ("IN_FLIGHT", PaymentState::Pending),
        ("SUCCEEDED", PaymentState::Succeeded),
        ("FAILED", PaymentState::Failed),
        ("UNKNOWN", PaymentState::Unknown),
    ] {
        let mut v = f["payments"].clone();
        v["payments"][0]["status"] = json!(state);
        assert_eq!(reads::payments(&v, 100).unwrap().items[0].state, expected);
    }
    let peers = reads::peers(&f["peers"], 100).unwrap();
    assert!(peers.items[0].connected);
    assert_eq!(peers.items[0].inbound, Some(true));
    let channels = reads::channels(&f["channels"], &f["pending"], &f["closed"], 100).unwrap();
    assert_eq!(channels.items[0].local_msat, Some(Msat(d(1000))));
    assert!(channels.items[0].spendable_msat.is_none());
    let tx = reads::transactions(&f["transactions"], 100).unwrap();
    assert_eq!(tx.items[0].direction, Direction::Outgoing);
    assert_eq!(tx.items[0].amount_sat, Some(Sat(d(10002))));
    assert_eq!(tx.items[0].confirmations, Some(d(0)));
    assert!(tx.items[0].block_height.is_none());
    no_secrets(&tx.items);
    emit("fees", "FeeEstimates", reads::fees("synthetic", now()));
    for (name, schema, items) in [
        (
            "invoices",
            "Invoice",
            serde_json::to_value(invoices.items).unwrap(),
        ),
        (
            "payments",
            "Payment",
            serde_json::to_value(p.items).unwrap(),
        ),
        ("peers", "Peer", serde_json::to_value(peers.items).unwrap()),
        (
            "channels",
            "Channel",
            serde_json::to_value(channels.items).unwrap(),
        ),
        (
            "transactions",
            "Transaction",
            serde_json::to_value(tx.items).unwrap(),
        ),
    ] {
        for (i, item) in items.as_array().unwrap().iter().enumerate() {
            emit(&format!("{name}-{i}"), schema, item);
        }
    }
}

#[test]
fn null_zero_overflow_encoding_duplicates_and_missing_times_are_not_coerced() {
    for n in ["1", "1000", "9007199254740993", "9223372036854775807"] {
        assert_eq!(
            reads::amount(&json!({"n":n}), "n")
                .unwrap()
                .unwrap()
                .to_string(),
            n
        );
    }
    for v in [
        json!({}),
        json!({"n":null}),
        json!({"n":"9223372036854775808"}),
        json!({"n":"18446744073709551616"}),
    ] {
        assert!(reads::amount(&v, "n").unwrap().is_none());
    }
    assert_eq!(reads::amount(&json!({"n":"0"}), "n").unwrap(), Some(d(0)));
    for n in [
        json!(1),
        json!(1.5),
        json!("01"),
        json!("1e3"),
        json!("-1"),
        json!("+1"),
    ] {
        assert!(reads::amount(&json!({"n":n}), "n").is_err());
    }
    let mut f = fixture();
    f["wallet"]
        .as_object_mut()
        .unwrap()
        .remove("locked_balance");
    assert!(reads::balances(
        &f["wallet"],
        &json!({}),
        "synthetic",
        Network::Regtest,
        now()
    )
    .unwrap()
    .onchain_spendable_sat
    .is_none());
    f["wallet"]["locked_balance"] = json!("9223372036854775807");
    assert!(reads::balances(
        &f["wallet"],
        &json!({}),
        "synthetic",
        Network::Regtest,
        now()
    )
    .unwrap()
    .onchain_spendable_sat
    .is_none());
    f["invoices"]["invoices"][0]["creation_date"] = json!("0");
    let c = reads::invoices(&f["invoices"], 100).unwrap();
    assert!(c.items.is_empty() && c.truncated);
    let mut v = f["payments"].clone();
    let duplicate = v["payments"][0].clone();
    v["payments"].as_array_mut().unwrap().push(duplicate);
    let p = reads::payments(&v, 100).unwrap();
    assert_eq!(p.items.len(), 1);
    assert_eq!(p.items[0].state, PaymentState::Unknown);
    assert!(p.items[0].amount_msat.is_none() && p.items[0].fee_msat.is_none());
    let mut tx = f["transactions"].clone();
    tx["transactions"][0]["amount"] = json!(i64::MIN.to_string());
    assert!(reads::transactions(&tx, 100).unwrap().items[0]
        .amount_sat
        .is_none());
    for field in ["invoices", "payments", "peers", "transactions"] {
        let result = json!({field:[]});
        match field {
            "invoices" => assert!(reads::invoices(&result, 1).unwrap().items.is_empty()),
            "payments" => assert!(reads::payments(&result, 1).unwrap().items.is_empty()),
            "peers" => assert!(reads::peers(&result, 1).unwrap().items.is_empty()),
            _ => assert!(reads::transactions(&result, 1).unwrap().items.is_empty()),
        }
    }
}

#[test]
fn nonpalindromic_internal_txid_bytes_are_reversed_only_for_txids() {
    let f = fixture();
    assert_eq!(
        reads::channel_point(&f["open"]).unwrap(),
        format!("{}:1", hex::encode((0u8..32).rev().collect::<Vec<_>>()))
    );
    let mut point = f["open"].clone();
    point["funding_txid_str"] = json!(txid());
    assert_eq!(
        reads::channel_point(&point).unwrap(),
        format!("{}:1", txid())
    );
    assert_eq!(reads::bytes_hash(&json!({"hash":base64::engine::general_purpose::STANDARD.encode((0u8..32).collect::<Vec<_>>())}),"hash").unwrap(),txid());
}

#[tokio::test]
async fn verified_tls_and_binary_file_credentials_on_both_transports() {
    for grpc in [false, true] {
        let backend = if grpc {
            Backend::LndGrpc
        } else {
            Backend::LndRest
        };
        let step = if grpc {
            Step::grpc(Rpc::Info, vec![grpc_frame(rpc_info())])
        } else {
            Step::rest("GET", "/v1/getinfo", fixture()["info"].clone())
        };
        let server = Server::start(grpc, vec![step]).await;
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path(), server.endpoint.clone(), backend);
        if grpc {
            LndGrpcAdapter::connect(&s, &Limits::default(), config(backend))
                .await
                .unwrap()
                .read(ReadQuery::Info)
                .await
                .unwrap();
        } else {
            LndRestAdapter::connect(&s, &Limits::default(), config(backend))
                .await
                .unwrap()
                .read(ReadQuery::Info)
                .await
                .unwrap();
        }
        let cap = server.stop(1).await;
        let key = if grpc {
            "macaroon"
        } else {
            "grpc-metadata-macaroon"
        };
        assert_eq!(cap[0].headers[key].to_str().unwrap(), hex::encode(MAC));
        assert!(!cap[0].headers.contains_key(if grpc {
            "grpc-metadata-macaroon"
        } else {
            "macaroon"
        }));
        let server = Server::start(grpc, vec![]).await;
        let mut wrong = server.endpoint.clone();
        wrong.set_host(Some("127.0.0.1")).unwrap();
        let s = settings(dir.path(), wrong, backend);
        let error = if grpc {
            LndGrpcAdapter::connect(&s, &Limits::default(), config(backend))
                .await
                .unwrap()
                .read(ReadQuery::Info)
                .await
                .err()
                .unwrap()
        } else {
            LndRestAdapter::connect(&s, &Limits::default(), config(backend))
                .await
                .unwrap()
                .read(ReadQuery::Info)
                .await
                .err()
                .unwrap()
        };
        assert_eq!(error.code, ErrorCode::NodeOffline);
        server.stop(0).await;
    }
}

#[tokio::test]
async fn configuration_and_identity_fail_closed_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = settings(
        dir.path(),
        "https://localhost:1/".parse().unwrap(),
        Backend::LndRest,
    );
    for endpoint in [
        "http://localhost/",
        "https://user:secret@localhost/",
        "https://localhost/?secret=x",
        "https://localhost/#x",
        "https://localhost/v1/",
    ] {
        s.endpoint = endpoint.parse().unwrap();
        assert!(Rest::connect(&s, &Limits::default()).is_err());
    }
    s.endpoint = "https://localhost:1/".parse().unwrap();
    std::fs::write(&s.certificate_file, b"").unwrap();
    assert!(Rest::connect(&s, &Limits::default()).is_err());
    assert!(grpc::Grpc::connect(&s, &Limits::default()).await.is_err());
    let mut wrong = fixture()["info"].clone();
    wrong["identity_pubkey"] =
        json!("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
    let server = Server::start(false, vec![Step::rest("GET", "/v1/getinfo", wrong)]).await;
    let s = settings(dir.path(), server.endpoint.clone(), Backend::LndRest);
    assert_eq!(
        LndRestAdapter::connect(&s, &Limits::default(), config(Backend::LndRest))
            .await
            .unwrap()
            .read(ReadQuery::Info)
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::IdentityChanged
    );
    server.stop(1).await;
    std::fs::set_permissions(&s.credential_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Rest::connect(&s, &Limits::default()).is_err());
}

const KINDS: [OperationKind; 8] = [
    OperationKind::CreateInvoice,
    OperationKind::PayInvoice,
    OperationKind::ConnectPeer,
    OperationKind::DisconnectPeer,
    OperationKind::OpenChannel,
    OperationKind::CloseChannel,
    OperationKind::NewAddress,
    OperationKind::SendOnchain,
];
fn response(kind: OperationKind) -> Value {
    match kind {
        OperationKind::CreateInvoice => {
            json!({"r_hash":fixture()["invoices"]["invoices"][0]["r_hash"],"payment_request":invoice()})
        }
        OperationKind::PayInvoice => fixture()["payments"]["payments"][0].clone(),
        OperationKind::ConnectPeer | OperationKind::DisconnectPeer => json!({}),
        OperationKind::OpenChannel => fixture()["open"].clone(),
        OperationKind::CloseChannel => fixture()["close"].clone(),
        OperationKind::NewAddress => json!({"address":address()}),
        OperationKind::SendOnchain => fixture()["send"].clone(),
    }
}
fn rest_step(kind: OperationKind) -> Step {
    match kind {
        OperationKind::CreateInvoice => Step::rest("POST", "/v1/invoices", response(kind)),
        OperationKind::PayInvoice => Step::raw(
            "POST",
            "/v2/router/send",
            serde_json::to_vec(&json!({"result":response(kind)})).unwrap(),
        ),
        OperationKind::ConnectPeer => Step::rest("POST", "/v1/peers", response(kind)),
        OperationKind::DisconnectPeer => {
            Step::rest("DELETE", &format!("/v1/peers/{}", peer()), response(kind))
        }
        OperationKind::OpenChannel => Step::rest("POST", "/v1/channels", response(kind)),
        OperationKind::CloseChannel => Step::raw(
            "DELETE",
            &format!("/v1/channels/{}/1", txid()),
            serde_json::to_vec(&json!({"result":response(kind)})).unwrap(),
        ),
        OperationKind::NewAddress => Step::rest("GET", "/v1/newaddress", response(kind)),
        OperationKind::SendOnchain => Step::rest("POST", "/v1/transactions", response(kind)),
    }
}
fn grpc_step(kind: OperationKind) -> Step {
    let msg = match kind {
        OperationKind::CreateInvoice => grpc_frame(ln::AddInvoiceResponse {
            r_hash: hex::decode(hash()).unwrap(),
            payment_request: invoice(),
            ..Default::default()
        }),
        OperationKind::PayInvoice => grpc_frame(rpc_payment(2)),
        OperationKind::ConnectPeer => grpc_frame(ln::ConnectPeerResponse::default()),
        OperationKind::DisconnectPeer => grpc_frame(ln::DisconnectPeerResponse::default()),
        OperationKind::OpenChannel => grpc_frame(ln::ChannelPoint {
            output_index: 1,
            funding_txid: Some(ln::channel_point::FundingTxid::FundingTxidBytes(
                (0u8..32).collect(),
            )),
        }),
        OperationKind::CloseChannel => grpc_frame(ln::CloseStatusUpdate {
            update: Some(ln::close_status_update::Update::ClosePending(
                ln::PendingUpdate {
                    txid: (0u8..32).collect(),
                    ..Default::default()
                },
            )),
        }),
        OperationKind::NewAddress => grpc_frame(ln::NewAddressResponse { address: address() }),
        OperationKind::SendOnchain => grpc_frame(ln::SendCoinsResponse { txid: txid() }),
    };
    Step::grpc(mutation_rpc(&request(kind)), vec![msg])
}
fn decode<M: Message + Default>(c: &Captured) -> M {
    assert_eq!(c.body[0], 0);
    let n = u32::from_be_bytes(c.body[1..5].try_into().unwrap()) as usize;
    assert_eq!(c.body.len(), n + 5);
    M::decode(&c.body[5..]).unwrap()
}
#[allow(deprecated)] // Assert deprecated aliases remain absent/default on the wire.
fn assert_command(c: &Captured, kind: OperationKind, grpc: bool) {
    assert_eq!(
        c.headers[if grpc {
            "macaroon"
        } else {
            "grpc-metadata-macaroon"
        }]
        .to_str()
        .unwrap(),
        hex::encode(MAC)
    );
    if grpc {
        match kind {
            OperationKind::CreateInvoice => {
                let p: ln::Invoice = decode(c);
                assert_eq!(p.value_msat, 1001);
                assert_eq!(p.value, 0);
                assert_eq!(p.expiry, 3600);
                assert_eq!(p.r_preimage, vec![77; 32]);
            }
            OperationKind::PayInvoice => {
                let p: router::SendPaymentRequest = decode(c);
                assert_eq!(p.payment_request, invoice());
                assert_eq!(p.fee_limit_msat, 1000);
                assert_eq!(p.amt_msat, 0);
                assert_eq!(p.amt, 0);
                assert_eq!(p.fee_limit_sat, 0);
                assert!(p.timeout_seconds > 0);
            }
            OperationKind::ConnectPeer => {
                let p: ln::ConnectPeerRequest = decode(c);
                assert_eq!(p.addr.unwrap().host, "peer.invalid:9735");
            }
            OperationKind::DisconnectPeer => {
                let p: ln::DisconnectPeerRequest = decode(c);
                assert_eq!(p.pub_key, peer());
            }
            OperationKind::OpenChannel => {
                let p: ln::OpenChannelRequest = decode(c);
                assert_eq!(p.local_funding_amount, 100000);
                assert_eq!(p.sat_per_vbyte, 1);
                assert_eq!(p.sat_per_byte, 0);
                assert!(!p.fund_max);
                assert_eq!(p.push_sat, 0);
                assert!(p.funding_shim.is_none());
                assert!(p.private);
            }
            OperationKind::CloseChannel => {
                let p: ln::CloseChannelRequest = decode(c);
                assert!(!p.force && !p.no_wait);
                assert_eq!(p.sat_per_vbyte, 1);
                assert_eq!(p.sat_per_byte, 0);
            }
            OperationKind::NewAddress => {
                let p: ln::NewAddressRequest = decode(c);
                assert_eq!(p.r#type, ln::AddressType::WitnessPubkeyHash as i32);
            }
            OperationKind::SendOnchain => {
                let p: ln::SendCoinsRequest = decode(c);
                assert_eq!(p.addr, address());
                assert_eq!(p.amount, 10000);
                assert_eq!(p.sat_per_vbyte, 1);
                assert_eq!(p.sat_per_byte, 0);
                assert!(!p.send_all);
            }
        }
    } else {
        let p: Value = if c.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&c.body).unwrap()
        };
        match kind {
            OperationKind::CreateInvoice => {
                assert_eq!(p["value_msat"], "1001");
                assert_eq!(p["expiry"], "3600");
                assert!(p.get("value").is_none());
                assert_eq!(reads::bytes(&p, "r_preimage").unwrap(), vec![77; 32]);
            }
            OperationKind::PayInvoice => {
                assert_eq!(p["fee_limit_msat"], "1000");
                assert!(
                    p.get("fee_limit_sat").is_none()
                        && p.get("amt_msat").is_none()
                        && p.get("amt").is_none()
                );
                assert!(p["timeout_seconds"].as_i64().unwrap() > 0);
            }
            OperationKind::ConnectPeer => assert_eq!(p["addr"]["host"], "peer.invalid:9735"),
            OperationKind::DisconnectPeer => assert!(c.body.is_empty()),
            OperationKind::OpenChannel => {
                assert_eq!(p["local_funding_amount"], "100000");
                assert_eq!(p["sat_per_vbyte"], "1");
                for key in [
                    "fund_max",
                    "funding_shim",
                    "push_sat",
                    "node_pubkey_string",
                    "sat_per_byte",
                ] {
                    assert!(p.get(key).is_none());
                }
            }
            OperationKind::CloseChannel => {
                assert_eq!(c.method, "DELETE");
                assert!(c.body.is_empty());
                let url = url::Url::parse(&format!("https://localhost{}", c.path)).unwrap();
                let q: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
                assert_eq!(q["force"], "false");
                assert_eq!(q["no_wait"], "false");
                assert_eq!(q["sat_per_vbyte"], "1");
                assert!(!q.contains_key("max_fee_per_vbyte"));
            }
            OperationKind::NewAddress => {
                assert_eq!(c.method, "GET");
                assert!(c.body.is_empty());
                assert!(c.path.contains("type=WITNESS_PUBKEY_HASH"));
            }
            OperationKind::SendOnchain => {
                assert_eq!(p["amount"], "10000");
                assert_eq!(p["sat_per_vbyte"], "1");
                assert_eq!(p["send_all"], false);
                assert!(p.get("sat_per_byte").is_none());
            }
        }
    }
}
#[tokio::test]
async fn all_eight_kinds_use_one_claim_one_exact_invocation_and_emit_schema_projections() {
    for grpc in [false, true] {
        for kind in KINDS {
            let backend = if grpc {
                Backend::LndGrpc
            } else {
                Backend::LndRest
            };
            let c = config(backend);
            let intent = reviewed(kind, &c);
            let p = permit(intent.clone());
            let claim_id = p.claim_id;
            let server = Server::start(
                grpc,
                vec![if grpc {
                    grpc_step(kind)
                } else {
                    rest_step(kind)
                }],
            )
            .await;
            let dir = tempfile::tempdir().unwrap();
            let s = settings(dir.path(), server.endpoint.clone(), backend);
            let e = if grpc {
                grpc_adapter(
                    grpc::Grpc::connect(&s, &Limits::default()).await.unwrap(),
                    c,
                )
                .execute_once(p)
                .await
            } else {
                rest_adapter(Rest::connect(&s, &Limits::default()).unwrap(), c)
                    .execute_once(p)
                    .await
            };
            assert!(matches!(e.class, Class::Positive), "{backend:?} {kind:?}");
            no_secrets(&e);
            let cap = server.stop(1).await;
            assert_command(&cap[0], kind, grpc);
            let mut op = intent.operation.clone();
            op.state = OperationState::Dispatching;
            op.stage = OperationStage::Submitted;
            op.authorization.status = if op.review.sensitive {
                AuthorizationState::Consumed
            } else {
                AuthorizationState::NotRequired
            };
            let transition = evidence::transition(
                &intent,
                op,
                Knowledge::new(&intent),
                e,
                evidence::ObservationContext {
                    claim_id,
                    allocated_sequence: 0,
                    read: false,
                    now: now(),
                },
            )
            .unwrap();
            assert_eq!(
                transition.operation.state,
                if matches!(
                    kind,
                    OperationKind::OpenChannel | OperationKind::CloseChannel
                ) {
                    OperationState::Pending
                } else {
                    OperationState::Succeeded
                }
            );
            emit(
                &format!("{backend:?}-{kind:?}"),
                "Operation",
                transition.operation,
            );
        }
    }
}

#[tokio::test]
async fn rest_hostile_bodies_redirects_permission_and_late_stream_errors_never_retry() {
    let kind = OperationKind::PayInvoice;
    for (status, body, expected) in [
        (
            403,
            b"{\"code\":7,\"message\":\"UPSTREAM_SENTENCE_CANARY\"}".to_vec(),
            "auth",
        ),
        (400, b"{\"code\":3}".to_vec(), "rejected"),
        (500, b"{\"code\":null}".to_vec(), "invalid"),
        (200, b"{\"result\":".to_vec(), "invalid"),
        (200, b"{\"error\":{\"code\":7}}".to_vec(), "auth"),
    ] {
        let mut step = Step::raw("POST", "/v2/router/send", body);
        step.status = status;
        let server = Server::start(false, vec![step]).await;
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path(), server.endpoint.clone(), Backend::LndRest);
        let c = config(Backend::LndRest);
        let e = rest_adapter(Rest::connect(&s, &Limits::default()).unwrap(), c.clone())
            .execute_once(permit(reviewed(kind, &c)))
            .await;
        match expected {
            "auth" => assert!(matches!(e.class, Class::Rejected(Rejection::Auth))),
            "rejected" => assert!(matches!(e.class, Class::Rejected(Rejection::Refused))),
            _ => assert!(matches!(e.class, Class::Partial)),
        }
        no_secrets(e);
        server.stop(1).await;
    }
    for succeeded in [false, true] {
        let mut payment = response(kind);
        if !succeeded {
            payment["status"] = json!("IN_FLIGHT");
        }
        let body = format!(
            "{}\n{{\"error\":{{\"code\":7,\"message\":\"PREIMAGE_CANARY\"}}}}",
            json!({"result":payment})
        )
        .into_bytes();
        let server = Server::start(false, vec![Step::raw("POST", "/v2/router/send", body)]).await;
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path(), server.endpoint.clone(), Backend::LndRest);
        let c = config(Backend::LndRest);
        let e = rest_adapter(Rest::connect(&s, &Limits::default()).unwrap(), c.clone())
            .execute_once(permit(reviewed(kind, &c)))
            .await;
        assert_eq!(matches!(e.class, Class::Positive), succeeded);
        assert_eq!(e.reference.attempt.as_deref(), Some("lnd-payment:7"));
        if !succeeded {
            assert!(matches!(e.class, Class::Lost));
        }
        no_secrets(e);
        server.stop(1).await;
    }
    let target = Server::start(false, vec![]).await;
    let mut redirect = rest_step(OperationKind::SendOnchain);
    redirect.status = 307;
    redirect.location = Some(target.endpoint.to_string());
    let server = Server::start(false, vec![redirect]).await;
    let dir = tempfile::tempdir().unwrap();
    let s = settings(dir.path(), server.endpoint.clone(), Backend::LndRest);
    let c = config(Backend::LndRest);
    let e = rest_adapter(Rest::connect(&s, &Limits::default()).unwrap(), c.clone())
        .execute_once(permit(reviewed(OperationKind::SendOnchain, &c)))
        .await;
    assert!(matches!(e.class, Class::Lost));
    server.stop(1).await;
    target.stop(0).await;
}

#[tokio::test]
async fn grpc_stream_statuses_truncation_and_late_errors_preserve_only_proven_evidence() {
    for (status, frame, code, expected) in [
        (2, true, 7, "success"),
        (1, true, 7, "unknown"),
        (0, false, 7, "auth"),
        (0, false, 3, "rejected"),
        (0, false, 14, "unknown"),
        (3, true, 0, "failed"),
    ] {
        let mut msg = rpc_payment(status);
        msg.failure_reason = 2;
        let mut step = Step::grpc(Rpc::Pay, if frame { vec![grpc_frame(msg)] } else { vec![] });
        step.grpc_code = Some(code);
        let server = Server::start(true, vec![step]).await;
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path(), server.endpoint.clone(), Backend::LndGrpc);
        let c = config(Backend::LndGrpc);
        let e = grpc_adapter(
            grpc::Grpc::connect(&s, &Limits::default()).await.unwrap(),
            c.clone(),
        )
        .execute_once(permit(reviewed(OperationKind::PayInvoice, &c)))
        .await;
        match expected {
            "success" => assert!(matches!(e.class, Class::Positive)),
            "auth" => assert!(matches!(e.class, Class::Rejected(Rejection::Auth))),
            "rejected" => assert!(matches!(e.class, Class::Rejected(Rejection::Refused))),
            "failed" => assert!(matches!(e.class, Class::Rejected(Rejection::NoRoute))),
            _ => assert!(matches!(e.class, Class::Lost)),
        }
        no_secrets(e);
        server.stop(1).await;
    }
    let mut step = grpc_step(OperationKind::SendOnchain);
    step.chunks.last_mut().unwrap().pop();
    let server = Server::start(true, vec![step]).await;
    let dir = tempfile::tempdir().unwrap();
    let s = settings(dir.path(), server.endpoint.clone(), Backend::LndGrpc);
    let c = config(Backend::LndGrpc);
    let e = grpc_adapter(
        grpc::Grpc::connect(&s, &Limits::default()).await.unwrap(),
        c.clone(),
    )
    .execute_once(permit(reviewed(OperationKind::SendOnchain, &c)))
    .await;
    assert!(!matches!(e.class, Class::Positive | Class::Rejected(_)));
    server.stop(1).await;
}

fn read_query(i: usize) -> ReadQuery {
    match i {
        0 => ReadQuery::Info,
        1 => ReadQuery::Balances,
        2 => ReadQuery::Invoices,
        3 => ReadQuery::Payments,
        4 => ReadQuery::Peers,
        5 => ReadQuery::Channels,
        6 => ReadQuery::Transactions,
        _ => ReadQuery::Fees,
    }
}
fn read_steps(i: usize, grpc: bool) -> Vec<Step> {
    let f = fixture();
    let mut steps = vec![if grpc {
        Step::grpc(Rpc::Info, vec![grpc_frame(rpc_info())])
    } else {
        Step::rest("GET", "/v1/getinfo", f["info"].clone())
    }];
    if grpc {
        let mut push = |rpc, msg| steps.push(Step::grpc(rpc, vec![msg]));
        match i {
            1 => {
                push(
                    Rpc::Wallet,
                    grpc_frame(ln::WalletBalanceResponse {
                        confirmed_balance: 9_007_199_254_740_993,
                        unconfirmed_balance: 0,
                        locked_balance: 2,
                        reserved_balance_anchor_chan: 3,
                        ..Default::default()
                    }),
                );
                push(
                    Rpc::ChannelBalance,
                    grpc_frame(ln::ChannelBalanceResponse {
                        local_balance: Some(ln::Amount { msat: 1001, sat: 1 }),
                        remote_balance: Some(ln::Amount { msat: 2000, sat: 2 }),
                        ..Default::default()
                    }),
                );
            }
            2 => push(
                Rpc::Invoices,
                grpc_frame(ln::ListInvoiceResponse {
                    invoices: vec![rpc_invoice()],
                    ..Default::default()
                }),
            ),
            3 => push(
                Rpc::Payments,
                grpc_frame(ln::ListPaymentsResponse {
                    payments: vec![rpc_payment(2)],
                    ..Default::default()
                }),
            ),
            4 => push(
                Rpc::Peers,
                grpc_frame(ln::ListPeersResponse {
                    peers: vec![ln::Peer {
                        pub_key: peer(),
                        address: "192.0.2.1:9735".into(),
                        inbound: true,
                        ..Default::default()
                    }],
                }),
            ),
            5 => {
                push(
                    Rpc::Channels,
                    grpc_frame(ln::ListChannelsResponse {
                        channels: vec![ln::Channel {
                            remote_pubkey: peer(),
                            channel_point: point(),
                            chan_id: 9_007_199_254_740_993,
                            capacity: 3,
                            local_balance: 1,
                            remote_balance: 2,
                            active: true,
                            private: true,
                            ..Default::default()
                        }],
                    }),
                );
                push(
                    Rpc::PendingChannels,
                    grpc_frame(ln::PendingChannelsResponse::default()),
                );
                push(
                    Rpc::ClosedChannels,
                    grpc_frame(ln::ClosedChannelsResponse::default()),
                );
            }
            6 => push(
                Rpc::Transactions,
                grpc_frame(ln::TransactionDetails {
                    transactions: vec![ln::Transaction {
                        tx_hash: txid(),
                        amount: -10002,
                        total_fees: 2,
                        num_confirmations: 0,
                        block_height: 0,
                        time_stamp: 1_750_000_000,
                        output_details: vec![ln::OutputDetail {
                            output_index: 0,
                            address: "SYNTHETIC_ADDRESS".into(),
                            amount: 10000,
                            is_our_address: false,
                            ..Default::default()
                        }],
                        raw_tx_hex: "RAW_TX_CANARY".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            ),
            _ => {}
        }
    } else {
        for (path, key) in match i {
            1 => vec![
                ("/v1/balance/blockchain", "wallet"),
                ("/v1/balance/channels", "channel_balance"),
            ],
            2 => vec![("/v1/invoices", "invoices")],
            3 => vec![("/v1/payments", "payments")],
            4 => vec![("/v1/peers", "peers")],
            5 => vec![
                ("/v1/channels", "channels"),
                ("/v1/channels/pending", "pending"),
                ("/v1/channels/closed", "closed"),
            ],
            6 => vec![("/v1/transactions", "transactions")],
            _ => vec![],
        } {
            let mut value = f[key].clone();
            if key == "invoices" {
                value["invoices"][0]["payment_request"] = json!(invoice());
            }
            steps.push(Step::rest("GET", path, value));
        }
    }
    steps
}
fn read_projection(result: ReadResult) -> Value {
    match result {
        ReadResult::Info(info) => {
            assert_eq!(info.identity_pubkey, peer());
            assert_eq!(info.status.synced_to_chain, Some(true));
            assert_eq!(info.status.synced_to_graph, Some(false));
            emit("node-status", "NodeStatus", &info.status);
            json!({"pubkey":info.identity_pubkey,"network":info.network,"height":info.status.block_height,"alias":info.alias,"version":info.version})
        }
        ReadResult::Balances(mut b) => {
            b.observed_at = now();
            serde_json::to_value(b).unwrap()
        }
        ReadResult::Invoices(c) => {
            assert!(!c.truncated);
            serde_json::to_value(c.items).unwrap()
        }
        ReadResult::Payments(c) => {
            assert!(!c.truncated);
            serde_json::to_value(c.items).unwrap()
        }
        ReadResult::Peers(c) => {
            assert!(!c.truncated);
            serde_json::to_value(c.items).unwrap()
        }
        ReadResult::Channels(c) => {
            assert!(!c.truncated);
            serde_json::to_value(c.items).unwrap()
        }
        ReadResult::Transactions(c) => {
            assert!(!c.truncated);
            serde_json::to_value(c.items).unwrap()
        }
        ReadResult::Fees(mut f) => {
            f.observed_at = Some(now());
            assert!(f.economy.is_none() && f.normal.is_none() && f.priority.is_none());
            serde_json::to_value(f).unwrap()
        }
    }
}
#[tokio::test]
async fn both_synthetic_servers_produce_identical_normalized_reads_and_modern_requests() {
    for i in 0..8 {
        let mut outputs = Vec::new();
        for grpc in [false, true] {
            let backend = if grpc {
                Backend::LndGrpc
            } else {
                Backend::LndRest
            };
            let steps = read_steps(i, grpc);
            let count = steps.len();
            let server = Server::start(grpc, steps).await;
            let dir = tempfile::tempdir().unwrap();
            let s = settings(dir.path(), server.endpoint.clone(), backend);
            let output = if grpc {
                grpc_adapter(
                    grpc::Grpc::connect(&s, &Limits::default()).await.unwrap(),
                    config(backend),
                )
                .read(read_query(i))
                .await
                .unwrap()
            } else {
                rest_adapter(
                    Rest::connect(&s, &Limits::default()).unwrap(),
                    config(backend),
                )
                .read(read_query(i))
                .await
                .unwrap()
            };
            outputs.push(read_projection(output));
            no_secrets(&outputs);
            let cap = server.stop(count).await;
            if i == 3 {
                if grpc {
                    let p: ln::ListPaymentsRequest = decode(&cap[1]);
                    assert!(p.include_incomplete);
                    assert_eq!(p.max_payments, 101);
                    assert!(p.reversed);
                } else {
                    assert!(cap[1].path.contains("include_incomplete=true"));
                    assert!(cap[1].path.contains("max_payments=101"));
                }
            }
            if i == 2 {
                if grpc {
                    let p: ln::ListInvoiceRequest = decode(&cap[1]);
                    assert_eq!(p.num_max_invoices, 101);
                    assert!(p.reversed);
                } else {
                    assert!(cap[1].path.contains("num_max_invoices=101"));
                }
            }
        }
        assert_eq!(
            outputs[0], outputs[1],
            "read {i} transport normalization drifted"
        );
    }
}

#[tokio::test]
async fn permission_preparation_is_read_only_and_checks_tagged_method_permissions() {
    for grpc in [false, true] {
        for kind in KINDS {
            let backend = if grpc {
                Backend::LndGrpc
            } else {
                Backend::LndRest
            };
            let rpc = mutation_rpc(&request(kind));
            let mut steps = vec![
                if grpc {
                    Step::grpc(Rpc::Info, vec![grpc_frame(rpc_info())])
                } else {
                    Step::rest("GET", "/v1/getinfo", fixture()["info"].clone())
                },
                if grpc {
                    Step::grpc(
                        Rpc::CheckPermissions,
                        vec![grpc_frame(ln::CheckMacPermResponse { valid: true })],
                    )
                } else {
                    Step::rest(
                        "POST",
                        "/v1/macaroon/checkpermissions",
                        json!({"valid":true}),
                    )
                },
            ];
            if kind == OperationKind::OpenChannel {
                steps.extend(read_steps(4, grpc).into_iter().skip(1));
            }
            if kind == OperationKind::CloseChannel {
                steps.extend(read_steps(5, grpc).into_iter().skip(1));
            }
            let count = steps.len();
            let server = Server::start(grpc, steps).await;
            let dir = tempfile::tempdir().unwrap();
            let s = settings(dir.path(), server.endpoint.clone(), backend);
            let facts = if grpc {
                grpc_adapter(
                    grpc::Grpc::connect(&s, &Limits::default()).await.unwrap(),
                    config(backend),
                )
                .prepare(&request(kind))
                .await
                .unwrap()
            } else {
                rest_adapter(
                    Rest::connect(&s, &Limits::default()).unwrap(),
                    config(backend),
                )
                .prepare(&request(kind))
                .await
                .unwrap()
            };
            assert!(facts.permission && facts.sync_usable);
            if kind == OperationKind::OpenChannel {
                assert!(facts.peer_connected);
            }
            if kind == OperationKind::CloseChannel {
                assert_eq!(facts.close_target, Some(point()));
            }
            let cap = server.stop(count).await;
            if grpc {
                let p: ln::CheckMacPermRequest = decode(&cap[1]);
                assert_eq!(p.macaroon, MAC);
                assert_eq!(p.full_method, rpc.method());
                assert_eq!(p.permissions.len(), rpc.permissions().len());
                for perm in p.permissions {
                    assert_eq!(perm.action, "write");
                }
            } else {
                let p: Value = serde_json::from_slice(&cap[1].body).unwrap();
                assert_eq!(reads::bytes(&p, "macaroon").unwrap(), MAC);
                assert_eq!(p["full_method"], rpc.method());
                assert_eq!(p["permissions"], json!(rpc.permissions()));
            }
        }
    }
}

#[tokio::test]
async fn response_bytes_total_deadlines_and_error_classes_are_bounded() {
    for grpc in [false, true] {
        let backend = if grpc {
            Backend::LndGrpc
        } else {
            Backend::LndRest
        };
        let server = Server::start(
            grpc,
            vec![if grpc {
                Step::grpc(Rpc::Info, vec![grpc_frame(rpc_info())])
            } else {
                Step::rest("GET", "/v1/getinfo", fixture()["info"].clone())
            }],
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path(), server.endpoint.clone(), backend);
        let limits = Limits {
            max_response_bytes: 32,
            ..Limits::default()
        };
        let result = if grpc {
            grpc_adapter(
                grpc::Grpc::connect(&s, &limits).await.unwrap(),
                config(backend),
            )
            .read(ReadQuery::Info)
            .await
        } else {
            rest_adapter(Rest::connect(&s, &limits).unwrap(), config(backend))
                .read(ReadQuery::Info)
                .await
        };
        assert_eq!(result.err().unwrap().code, ErrorCode::NodeOffline);
        server.stop(1).await;
        let mut step = if grpc {
            grpc_step(OperationKind::SendOnchain)
        } else {
            rest_step(OperationKind::SendOnchain)
        };
        step.delay = Duration::from_secs(3);
        let server = Server::start(grpc, vec![step]).await;
        let s = settings(dir.path(), server.endpoint.clone(), backend);
        let limits = Limits {
            rpc_seconds: 1,
            ..Limits::default()
        };
        let c = config(backend);
        let e = if grpc {
            grpc_adapter(grpc::Grpc::connect(&s, &limits).await.unwrap(), c.clone())
                .execute_once(permit(reviewed(OperationKind::SendOnchain, &c)))
                .await
        } else {
            rest_adapter(Rest::connect(&s, &limits).unwrap(), c.clone())
                .execute_once(permit(reviewed(OperationKind::SendOnchain, &c)))
                .await
        };
        assert!(matches!(e.class, Class::Lost));
        server.stop(1).await;
    }
    for (code, expected) in [
        (tonic::Code::Unauthenticated, ErrorCode::NodeAuthError),
        (tonic::Code::PermissionDenied, ErrorCode::NodeAuthError),
        (tonic::Code::NotFound, ErrorCode::NotFound),
        (tonic::Code::ResourceExhausted, ErrorCode::RateLimited),
        (tonic::Code::InvalidArgument, ErrorCode::UpstreamRejected),
        (tonic::Code::FailedPrecondition, ErrorCode::UpstreamRejected),
        (tonic::Code::Unimplemented, ErrorCode::Unsupported),
        (tonic::Code::Unavailable, ErrorCode::NodeOffline),
    ] {
        assert_eq!(CallError::Status(code).read_code(), expected);
    }
}

#[test]
fn channel_lifecycles_closure_types_fee_units_and_stable_order_are_exact() {
    let f = fixture();
    for (key, state, expected_type) in [
        ("pending_open_channels", ChannelState::Opening, None),
        ("pending_closing_channels", ChannelState::Closing, None),
        ("waiting_close_channels", ChannelState::Closing, None),
        (
            "pending_force_closing_channels",
            ChannelState::Closing,
            Some(CloseType::Unilateral),
        ),
    ] {
        let mut pending = f["pending"].clone();
        let mut row = f["channels"]["channels"][0].clone();
        row["remote_node_pub"] = json!(peer());
        pending[key] = json!([{"channel":row,"closing_tx_hex":"RAW_TX_CANARY"}]);
        let result = reads::channels(&json!({"channels":[]}), &pending, &f["closed"], 100).unwrap();
        assert_eq!(result.items[0].state, state);
        assert_eq!(result.items[0].close_type, expected_type);
        no_secrets(result.items);
    }
    for (raw, expected) in [
        ("COOPERATIVE_CLOSE", CloseType::Cooperative),
        ("LOCAL_FORCE_CLOSE", CloseType::Unilateral),
        ("REMOTE_FORCE_CLOSE", CloseType::Unilateral),
        ("BREACH_CLOSE", CloseType::Unilateral),
        ("FUNDING_CANCELED", CloseType::Unknown),
        ("ABANDONED", CloseType::Unknown),
        ("FUTURE", CloseType::Unknown),
    ] {
        let row = json!({"remote_pubkey":peer(),"channel_point":point(),"capacity":"3","chan_id":"7","close_type":raw});
        let result = reads::channels(
            &json!({"channels":[]}),
            &f["pending"],
            &json!({"channels":[row]}),
            100,
        )
        .unwrap();
        assert_eq!(result.items[0].state, ChannelState::Closed);
        assert_eq!(result.items[0].close_type, Some(expected));
    }
    for (perkw, pervb) in [
        (0, 0),
        (249, 1),
        (250, 1),
        (253, 2),
        (501, 3),
        (i64::MAX as u64, (i64::MAX as u64).div_ceil(250)),
    ] {
        assert_eq!(
            reads::fee_rate(&json!({"sat_per_kw":perkw.to_string()})).unwrap(),
            Some(d(pervb))
        );
    }
    assert!(reads::fee_rate(&json!({})).unwrap().is_none());
    let mut invoices = f["invoices"].clone();
    let mut newer = invoices["invoices"][0].clone();
    newer["r_hash"] = json!(base64::engine::general_purpose::STANDARD.encode([9; 32]));
    newer["creation_date"] = json!("1750000001");
    invoices["invoices"].as_array_mut().unwrap().push(newer);
    let newest = reads::invoices(&invoices, 1).unwrap();
    assert!(newest.truncated);
    assert_eq!(newest.items[0].payment_hash, hex::encode([9; 32]));
    invoices["invoices"].as_array_mut().unwrap().reverse();
    assert_eq!(
        reads::invoices(&invoices, 1).unwrap().items[0].payment_hash,
        newest.items[0].payment_hash
    );
}

async fn observe_script(
    grpc: bool,
    kind: OperationKind,
    reference: RecoveryReference,
    last: Step,
) -> (ReviewedIntent, Evidence) {
    let backend = if grpc {
        Backend::LndGrpc
    } else {
        Backend::LndRest
    };
    let c = config(backend);
    let intent = reviewed(kind, &c);
    let server = Server::start(
        grpc,
        vec![
            if grpc {
                Step::grpc(Rpc::Info, vec![grpc_frame(rpc_info())])
            } else {
                Step::rest("GET", "/v1/getinfo", fixture()["info"].clone())
            },
            last,
        ],
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let s = settings(dir.path(), server.endpoint.clone(), backend);
    let q = query(&intent, reference);
    let e = if grpc {
        grpc_adapter(
            grpc::Grpc::connect(&s, &Limits::default()).await.unwrap(),
            c,
        )
        .observe_exact(q)
        .await
    } else {
        rest_adapter(Rest::connect(&s, &Limits::default()).unwrap(), c)
            .observe_exact(q)
            .await
    };
    server.stop(2).await;
    (intent, e)
}
fn apply_observation(intent: &ReviewedIntent, e: Evidence) -> evidence::Transition {
    let mut operation = intent.operation.clone();
    operation.state = OperationState::Unknown;
    operation.stage = OperationStage::Reconciling;
    let mut knowledge = Knowledge::new(intent);
    knowledge.reference = e.reference.clone();
    let claim_id = e.claim_id;
    evidence::transition(
        intent,
        operation,
        knowledge,
        e,
        evidence::ObservationContext {
            claim_id,
            allocated_sequence: 1,
            read: true,
            now: now(),
        },
    )
    .unwrap()
}
#[tokio::test]
async fn missing_pruned_and_wrong_exact_transaction_never_release_or_prove_failure() {
    for grpc in [false, true] {
        for found in [false, true] {
            let step = if grpc {
                Step::grpc(
                    Rpc::Transactions,
                    vec![grpc_frame(ln::TransactionDetails {
                        transactions: if found {
                            vec![ln::Transaction {
                                tx_hash: "11".repeat(32),
                                amount: -10002,
                                total_fees: 2,
                                ..Default::default()
                            }]
                        } else {
                            vec![]
                        },
                        ..Default::default()
                    })],
                )
            } else {
                let mut v = fixture()["transactions"].clone();
                if found {
                    v["transactions"][0]["tx_hash"] = json!("11".repeat(32));
                } else {
                    v["transactions"] = json!([]);
                }
                Step::rest("GET", "/v1/transactions", v)
            };
            let (intent, e) = observe_script(
                grpc,
                OperationKind::SendOnchain,
                RecoveryReference {
                    txid: Some(txid()),
                    ..Default::default()
                },
                step,
            )
            .await;
            assert!(matches!(e.class, Class::NotFound));
            assert!(e.facts.is_none());
            let t = apply_observation(&intent, e);
            assert!(!t.release);
            assert_eq!(t.operation.state, OperationState::Unknown);
            assert_eq!(t.operation.error.unwrap().outcome, ErrorOutcome::Unknown);
        }
    }
}
#[tokio::test]
async fn exact_send_refresh_uses_reviewed_amount_not_wallet_net_and_preserves_zero_fees() {
    for grpc in [false, true] {
        let step = if grpc {
            Step::grpc(
                Rpc::Transactions,
                vec![grpc_frame(ln::TransactionDetails {
                    transactions: vec![ln::Transaction {
                        tx_hash: txid(),
                        amount: -10000,
                        total_fees: 0,
                        num_confirmations: 1,
                        block_height: 100,
                        ..Default::default()
                    }],
                    ..Default::default()
                })],
            )
        } else {
            let mut v = fixture()["transactions"].clone();
            v["transactions"][0]["amount"] = json!("-10000");
            v["transactions"][0]["total_fees"] = json!("0");
            v["transactions"][0]["num_confirmations"] = json!(1);
            v["transactions"][0]["block_height"] = json!(100);
            Step::rest("GET", "/v1/transactions", v)
        };
        let (intent, e) = observe_script(
            grpc,
            OperationKind::SendOnchain,
            RecoveryReference {
                txid: Some(txid()),
                ..Default::default()
            },
            step,
        )
        .await;
        assert!(matches!(e.class, Class::Positive));
        let t = apply_observation(&intent, e);
        assert_eq!(t.operation.state, OperationState::Succeeded);
        assert_eq!(t.operation.stage, OperationStage::Confirmed);
        match t.operation.result.as_ref().unwrap() {
            OperationResult::SendOnchain {
                amount_sat,
                fee_sat,
                confirmations,
                ..
            } => {
                assert_eq!(*amount_sat, Sat(d(10000)));
                assert_eq!(*fee_sat, Some(Sat(d(0))));
                assert_eq!(*confirmations, Some(d(1)));
            }
            _ => panic!("wrong result"),
        };
        emit(&format!("send-confirmed-{grpc}"), "Operation", t.operation);
    }
}
#[tokio::test]
async fn payment_observation_requires_hash_and_persisted_payment_index_for_failure_or_attribution()
{
    for grpc in [false, true] {
        for (status, index, same_hash, expected) in [
            (3, 7, true, "rejected"),
            (3, 8, true, "unknown"),
            (2, 7, false, "unknown"),
            (2, 7, true, "success"),
            (2, 8, true, "elsewhere"),
        ] {
            let mut msg = rpc_payment(status);
            msg.payment_index = index;
            msg.failure_reason = 2;
            if !same_hash {
                msg.payment_hash = "11".repeat(32);
            }
            let path = format!(
                "/v2/router/track/{}",
                base64::engine::general_purpose::URL_SAFE.encode(hex::decode(hash()).unwrap())
            );
            let step = if grpc {
                Step::grpc(Rpc::TrackPayment, vec![grpc_frame(msg)])
            } else {
                let mut value = response(OperationKind::PayInvoice);
                value["status"] = json!(if status == 3 { "FAILED" } else { "SUCCEEDED" });
                value["payment_index"] = json!(index.to_string());
                value["failure_reason"] = json!("FAILURE_REASON_NO_ROUTE");
                if !same_hash {
                    value["payment_hash"] = json!("11".repeat(32));
                }
                Step::raw(
                    "GET",
                    &path,
                    serde_json::to_vec(&json!({"result":value})).unwrap(),
                )
            };
            let (intent, e) = observe_script(
                grpc,
                OperationKind::PayInvoice,
                RecoveryReference {
                    payment_hash: Some(hash()),
                    attempt: Some("lnd-payment:7".into()),
                    peer: None,
                    ..Default::default()
                },
                step,
            )
            .await;
            match expected {
                "rejected" => assert!(matches!(e.class, Class::Rejected(Rejection::NoRoute))),
                "success" => assert!(matches!(e.class, Class::Positive)),
                "elsewhere" => assert!(matches!(e.class, Class::PaidElsewhere)),
                _ => assert!(matches!(e.class, Class::NotFound)),
            }
            let t = apply_observation(&intent, e);
            if matches!(expected, "unknown" | "elsewhere") {
                assert!(!t.release);
                assert_eq!(t.operation.state, OperationState::Unknown);
            }
            if expected == "elsewhere" {
                assert_eq!(t.paid_hash, Some(hash()));
            }
        }
    }
    for grpc in [false, true] {
        let mut step = if grpc {
            Step::grpc(Rpc::TrackPayment, vec![])
        } else {
            Step::raw(
                "GET",
                &format!(
                    "/v2/router/track/{}",
                    base64::engine::general_purpose::URL_SAFE.encode(hex::decode(hash()).unwrap())
                ),
                b"{\"code\":5}".to_vec(),
            )
        };
        if grpc {
            step.grpc_code = Some(5);
        } else {
            step.status = 404;
        }
        let (intent, e) = observe_script(
            grpc,
            OperationKind::PayInvoice,
            RecoveryReference {
                payment_hash: Some(hash()),
                attempt: Some("lnd-payment:7".into()),
                ..Default::default()
            },
            step,
        )
        .await;
        assert!(matches!(e.class, Class::Lost));
        assert!(!apply_observation(&intent, e).release);
    }
}

#[tokio::test]
async fn instant_or_success_close_frames_never_fabricate_cooperative_or_confirmed() {
    for grpc in [false, true] {
        for instant in [false, true] {
            let step = if grpc {
                Step::grpc(
                    Rpc::Close,
                    vec![grpc_frame(ln::CloseStatusUpdate {
                        update: Some(if instant {
                            ln::close_status_update::Update::CloseInstant(
                                ln::InstantUpdate::default(),
                            )
                        } else {
                            ln::close_status_update::Update::ChanClose(ln::ChannelCloseUpdate {
                                closing_txid: (0u8..32).collect(),
                                success: true,
                                ..Default::default()
                            })
                        }),
                    })],
                )
            } else {
                Step::raw("DELETE",&format!("/v1/channels/{}/1",txid()),serde_json::to_vec(&json!({"result":if instant{json!({"close_instant":{}})}else{json!({"chan_close":{"closing_txid":base64::engine::general_purpose::STANDARD.encode((0u8..32).collect::<Vec<_>>()),"success":true}})}})).unwrap())
            };
            let backend = if grpc {
                Backend::LndGrpc
            } else {
                Backend::LndRest
            };
            let c = config(backend);
            let server = Server::start(grpc, vec![step]).await;
            let dir = tempfile::tempdir().unwrap();
            let s = settings(dir.path(), server.endpoint.clone(), backend);
            let e = if grpc {
                grpc_adapter(
                    grpc::Grpc::connect(&s, &Limits::default()).await.unwrap(),
                    c.clone(),
                )
                .execute_once(permit(reviewed(OperationKind::CloseChannel, &c)))
                .await
            } else {
                rest_adapter(Rest::connect(&s, &Limits::default()).unwrap(), c.clone())
                    .execute_once(permit(reviewed(OperationKind::CloseChannel, &c)))
                    .await
            };
            if instant {
                assert!(matches!(e.class, Class::Lost));
                assert!(e.facts.is_none());
            } else {
                match e.facts.unwrap() {
                    Facts::Close {
                        close_type,
                        closed,
                        confirmations,
                        ..
                    } => {
                        assert_eq!(close_type, CloseType::Unknown);
                        assert!(!closed);
                        assert!(confirmations.is_none());
                    }
                    _ => panic!("wrong fact"),
                }
            }
            server.stop(1).await;
        }
    }
}

#[tokio::test]
async fn stale_generation_wrong_hash_and_invalid_address_never_mutate_twice_or_accept() {
    for grpc in [false, true] {
        let backend = if grpc {
            Backend::LndGrpc
        } else {
            Backend::LndRest
        };
        let c = config(backend);
        let server = Server::start(grpc, vec![]).await;
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path(), server.endpoint.clone(), backend);
        let mut intent = reviewed(OperationKind::SendOnchain, &c);
        intent.connection_generation = Uuid::new_v4();
        let e = if grpc {
            grpc_adapter(
                grpc::Grpc::connect(&s, &Limits::default()).await.unwrap(),
                c.clone(),
            )
            .execute_once(permit(intent))
            .await
        } else {
            rest_adapter(Rest::connect(&s, &Limits::default()).unwrap(), c.clone())
                .execute_once(permit(intent))
                .await
        };
        assert!(matches!(e.class, Class::Conflict));
        server.stop(0).await;
        for kind in [
            OperationKind::CreateInvoice,
            OperationKind::PayInvoice,
            OperationKind::NewAddress,
        ] {
            let step = if grpc {
                match kind {
                    OperationKind::CreateInvoice => Step::grpc(
                        Rpc::AddInvoice,
                        vec![grpc_frame(ln::AddInvoiceResponse {
                            r_hash: vec![9; 32],
                            payment_request: invoice(),
                            ..Default::default()
                        })],
                    ),
                    OperationKind::PayInvoice => {
                        let mut p = rpc_payment(2);
                        p.payment_hash = "09".repeat(32);
                        Step::grpc(Rpc::Pay, vec![grpc_frame(p)])
                    }
                    _ => Step::grpc(
                        Rpc::Address,
                        vec![grpc_frame(ln::NewAddressResponse {
                            address: "not-an-address".into(),
                        })],
                    ),
                }
            } else {
                let mut value = response(kind);
                match kind {
                    OperationKind::CreateInvoice => {
                        value["r_hash"] =
                            json!(base64::engine::general_purpose::STANDARD.encode([9; 32]))
                    }
                    OperationKind::PayInvoice => value["payment_hash"] = json!("09".repeat(32)),
                    _ => value["address"] = json!("not-an-address"),
                };
                let mut step = rest_step(kind);
                step.chunks = serde_json::to_vec(&if kind == OperationKind::PayInvoice {
                    json!({"result":value})
                } else {
                    value
                })
                .unwrap()
                .chunks(3)
                .map(|c| c.to_vec())
                .collect();
                step
            };
            let server = Server::start(grpc, vec![step]).await;
            let s = settings(dir.path(), server.endpoint.clone(), backend);
            let e = if grpc {
                grpc_adapter(
                    grpc::Grpc::connect(&s, &Limits::default()).await.unwrap(),
                    c.clone(),
                )
                .execute_once(permit(reviewed(kind, &c)))
                .await
            } else {
                rest_adapter(Rest::connect(&s, &Limits::default()).unwrap(), c.clone())
                    .execute_once(permit(reviewed(kind, &c)))
                    .await
            };
            assert!(matches!(e.class, Class::Partial));
            assert!(e.facts.is_none());
            no_secrets(e);
            server.stop(1).await;
        }
    }
}

#[tokio::test]
async fn closed_history_requires_exact_outpoint_and_known_cooperative_txid_but_reports_unilateral()
{
    for grpc in [false, true] {
        for scenario in ["cooperative", "wrong-txid", "wrong-point", "unilateral"] {
            let backend = if grpc {
                Backend::LndGrpc
            } else {
                Backend::LndRest
            };
            let c = config(backend);
            let intent = reviewed(OperationKind::CloseChannel, &c);
            let closing = if scenario == "cooperative" {
                txid()
            } else {
                "11".repeat(32)
            };
            let channel = if scenario == "wrong-point" {
                format!("{}:2", txid())
            } else {
                point()
            };
            let raw_type = if scenario == "unilateral" {
                "REMOTE_FORCE_CLOSE"
            } else {
                "COOPERATIVE_CLOSE"
            };
            let steps = if grpc {
                vec![
                    Step::grpc(Rpc::Info, vec![grpc_frame(rpc_info())]),
                    Step::grpc(
                        Rpc::Channels,
                        vec![grpc_frame(ln::ListChannelsResponse::default())],
                    ),
                    Step::grpc(
                        Rpc::PendingChannels,
                        vec![grpc_frame(ln::PendingChannelsResponse::default())],
                    ),
                    Step::grpc(
                        Rpc::ClosedChannels,
                        vec![grpc_frame(ln::ClosedChannelsResponse {
                            channels: vec![ln::ChannelCloseSummary {
                                channel_point: channel,
                                remote_pubkey: peer(),
                                chan_id: 7,
                                capacity: 3,
                                closing_tx_hash: closing,
                                close_type: if scenario == "unilateral" {
                                    ln::channel_close_summary::ClosureType::RemoteForceClose as i32
                                } else {
                                    ln::channel_close_summary::ClosureType::CooperativeClose as i32
                                },
                                ..Default::default()
                            }],
                        })],
                    ),
                ]
            } else {
                vec![
                    Step::rest("GET", "/v1/getinfo", fixture()["info"].clone()),
                    Step::rest("GET", "/v1/channels", json!({"channels":[]})),
                    Step::rest("GET", "/v1/channels/pending", fixture()["pending"].clone()),
                    Step::rest(
                        "GET",
                        "/v1/channels/closed",
                        json!({"channels":[{"channel_point":channel,"remote_pubkey":peer(),"chan_id":"7","capacity":"3","closing_tx_hash":closing,"close_type":raw_type}]}),
                    ),
                ]
            };
            let server = Server::start(grpc, steps).await;
            let dir = tempfile::tempdir().unwrap();
            let s = settings(dir.path(), server.endpoint.clone(), backend);
            let mut q = query(&intent, RecoveryReference::planned(&intent));
            q.close_txids = vec![txid()];
            q.close_type = Some(CloseType::Unknown);
            let e = if grpc {
                grpc_adapter(
                    grpc::Grpc::connect(&s, &Limits::default()).await.unwrap(),
                    c,
                )
                .observe_exact(q)
                .await
            } else {
                rest_adapter(Rest::connect(&s, &Limits::default()).unwrap(), c)
                    .observe_exact(q)
                    .await
            };
            server.stop(4).await;
            let transition = apply_observation(&intent, e);
            match scenario {
                "cooperative" => {
                    assert_eq!(transition.operation.state, OperationState::Succeeded);
                    assert!(transition.release);
                }
                "unilateral" => {
                    assert_eq!(transition.operation.state, OperationState::Failed);
                    assert_eq!(
                        transition.operation.error.as_ref().unwrap().code,
                        ErrorCode::UnexpectedUnilateralClose
                    );
                }
                _ => {
                    assert_eq!(transition.operation.state, OperationState::Unknown);
                    assert!(!transition.release);
                }
            }
            emit(
                &format!("close-{scenario}-{grpc}"),
                "Operation",
                transition.operation,
            );
        }
    }
}

#[tokio::test]
async fn walletkit_estimate_uses_tagged_route_and_units_without_inventing_public_targets() {
    for grpc in [false, true] {
        let backend = if grpc {
            Backend::LndGrpc
        } else {
            Backend::LndRest
        };
        let step = if grpc {
            Step::grpc(
                Rpc::EstimateFee,
                vec![grpc_frame(lnd_grpc_rust::walletrpc::EstimateFeeResponse {
                    sat_per_kw: 253,
                    min_relay_fee_sat_per_kw: 250,
                })],
            )
        } else {
            Step::rest(
                "GET",
                "/v2/wallet/estimatefee/2",
                json!({"sat_per_kw":"253","min_relay_fee_sat_per_kw":"250"}),
            )
        };
        let server = Server::start(grpc, vec![step]).await;
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path(), server.endpoint.clone(), backend);
        let result = if grpc {
            grpc::Grpc::connect(&s, &Limits::default())
                .await
                .unwrap()
                .call(Rpc::EstimateFee, json!({"conf_target":2}), 4096)
                .await
        } else {
            Rest::connect(&s, &Limits::default())
                .unwrap()
                .call(Rpc::EstimateFee, json!({"conf_target":2}), 4096)
                .await
        };
        let (v, _) = result.unary().unwrap();
        assert_eq!(reads::fee_rate(&v).unwrap(), Some(d(2)));
        let captures = server.stop(1).await;
        if grpc {
            let p: lnd_grpc_rust::walletrpc::EstimateFeeRequest = decode(&captures[0]);
            assert_eq!(p.conf_target, 2);
        } else {
            assert!(captures[0].body.is_empty());
        }
    }
}

#[test]
fn absent_messages_are_not_zero_and_unknown_numeric_enums_remain_unknown() {
    for channel in [json!({}), json!({"local_balance":null})] {
        assert!(reads::balances(
            &fixture()["wallet"],
            &channel,
            "synthetic",
            Network::Regtest,
            now()
        )
        .unwrap()
        .channel_local_msat
        .is_none());
    }
    assert_eq!(
        reads::balances(
            &fixture()["wallet"],
            &json!({"local_balance":{"msat":"0"}}),
            "synthetic",
            Network::Regtest,
            now()
        )
        .unwrap()
        .channel_local_msat,
        Some(Msat(d(0)))
    );
    let mut f = fixture();
    f["invoices"]["invoices"][0]["state"] = json!(999);
    assert_eq!(
        reads::invoices(&f["invoices"], 100).unwrap().items[0].state,
        InvoiceState::Unknown
    );
    f["payments"]["payments"][0]["status"] = json!(999);
    assert_eq!(
        reads::payments(&f["payments"], 100).unwrap().items[0].state,
        PaymentState::Unknown
    );
}

#[tokio::test]
async fn close_late_permission_error_is_uncertain_not_a_pre_execution_refusal() {
    for grpc in [false, true] {
        let backend = if grpc {
            Backend::LndGrpc
        } else {
            Backend::LndRest
        };
        let c = config(backend);
        let intent = reviewed(OperationKind::CloseChannel, &c);
        let mut step = if grpc {
            grpc_step(OperationKind::CloseChannel)
        } else {
            Step::raw(
                "DELETE",
                &format!("/v1/channels/{}/1", txid()),
                format!(
                    "{}\n{{\"error\":{{\"code\":7}}}}",
                    json!({"result":fixture()["close"]})
                )
                .into_bytes(),
            )
        };
        if grpc {
            step.grpc_code = Some(7);
        }
        let server = Server::start(grpc, vec![step]).await;
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path(), server.endpoint.clone(), backend);
        let e = if grpc {
            grpc_adapter(
                grpc::Grpc::connect(&s, &Limits::default()).await.unwrap(),
                c,
            )
            .execute_once(permit(intent.clone()))
            .await
        } else {
            rest_adapter(Rest::connect(&s, &Limits::default()).unwrap(), c)
                .execute_once(permit(intent.clone()))
                .await
        };
        server.stop(1).await;
        assert!(matches!(e.class, Class::Lost));
        assert_eq!(e.reference.channel, Some(point()));
        assert!(e.facts.is_none());
        let claim_id = e.claim_id;
        let mut op = intent.operation.clone();
        op.state = OperationState::Dispatching;
        op.stage = OperationStage::Submitted;
        let t = evidence::transition(
            &intent,
            op,
            Knowledge::new(&intent),
            e,
            evidence::ObservationContext {
                claim_id,
                allocated_sequence: 0,
                read: false,
                now: now(),
            },
        )
        .unwrap();
        assert!(!t.release);
        assert_eq!(t.operation.state, OperationState::Unknown);
    }
}

#[tokio::test]
async fn permission_denial_and_wrong_identity_stop_preparation_before_any_mutation() {
    for grpc in [false, true] {
        for wrong_identity in [false, true] {
            let backend = if grpc {
                Backend::LndGrpc
            } else {
                Backend::LndRest
            };
            let mut info = rpc_info();
            let mut rest_info = fixture()["info"].clone();
            if wrong_identity {
                info.identity_pubkey =
                    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5".into();
                rest_info["identity_pubkey"] = json!(info.identity_pubkey);
            }
            let mut steps = vec![if grpc {
                Step::grpc(Rpc::Info, vec![grpc_frame(info)])
            } else {
                Step::rest("GET", "/v1/getinfo", rest_info)
            }];
            if !wrong_identity {
                let mut denial = if grpc {
                    Step::grpc(Rpc::CheckPermissions, vec![])
                } else {
                    Step::raw(
                        "POST",
                        "/v1/macaroon/checkpermissions",
                        b"{\"code\":7,\"message\":\"UPSTREAM_SENTENCE_CANARY\"}".to_vec(),
                    )
                };
                if grpc {
                    denial.grpc_code = Some(7);
                } else {
                    denial.status = 403;
                }
                steps.push(denial);
            }
            let count = steps.len();
            let server = Server::start(grpc, steps).await;
            let dir = tempfile::tempdir().unwrap();
            let s = settings(dir.path(), server.endpoint.clone(), backend);
            let result = if grpc {
                grpc_adapter(
                    grpc::Grpc::connect(&s, &Limits::default()).await.unwrap(),
                    config(backend),
                )
                .prepare(&request(OperationKind::OpenChannel))
                .await
            } else {
                rest_adapter(
                    Rest::connect(&s, &Limits::default()).unwrap(),
                    config(backend),
                )
                .prepare(&request(OperationKind::OpenChannel))
                .await
            };
            assert_eq!(
                result.err().unwrap().code,
                if wrong_identity {
                    ErrorCode::IdentityChanged
                } else {
                    ErrorCode::NodeAuthError
                }
            );
            server.stop(count).await;
        }
    }
}
