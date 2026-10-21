use super::*;
use lightning_client::{
    money::Sat,
    settings::{Limits, NodeSettings},
};
use std::{os::unix::fs::PermissionsExt, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};

const FIXTURE: &str = include_str!("../../../tests/fixtures/cln-v25.02/synthetic.json");
fn fixture() -> Value {
    serde_json::from_str(FIXTURE).unwrap()
}
fn decimal(n: u64) -> Decimal {
    Decimal::new(n).unwrap()
}
fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_750_000_000, 0).unwrap()
}
fn peer() -> String {
    fixture()["getinfo"]["id"].as_str().unwrap().into()
}
fn config() -> NodeConfig {
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
        backend: Backend::ClnRest,
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
fn facts(config: &NodeConfig) -> ReadFacts {
    ReadFacts {
        binding: config.binding.clone(),
        generation: config.generation,
        observed_at: now(),
        connection: NodeConnection::Online,
        sync_usable: true,
        permission: true,
        peer_connected: true,
        close_target: Some(format!(
            "{}:1",
            fixture()["fundchannel"]["txid"].as_str().unwrap()
        )),
        close_peer: Some(peer()),
    }
}
fn request(kind: OperationKind) -> OperationRequest {
    match kind {
        OperationKind::CreateInvoice => OperationRequest::CreateInvoice(CreateInvoice {
            amount_msat: Msat(decimal(1001)),
            description: "Synthetic invoice".into(),
            expiry_seconds: 3600,
        }),
        OperationKind::PayInvoice => OperationRequest::PayInvoice(PayInvoice {
            bolt11: invoice(),
            amount_msat: None,
            max_fee_msat: Msat(decimal(1000)),
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
            amount_sat: Sat(decimal(100000)),
            private: true,
            fee_rate_sat_vbyte: decimal(1),
        }),
        OperationKind::CloseChannel => OperationRequest::CloseChannel(CloseChannel {
            channel_id: fixture()["fundchannel"]["channel_id"]
                .as_str()
                .unwrap()
                .into(),
            fee_rate_sat_vbyte: decimal(1),
        }),
        OperationKind::NewAddress => OperationRequest::NewAddress(NewAddress {
            address_type: AddressType::P2wpkh,
        }),
        OperationKind::SendOnchain => OperationRequest::SendOnchain(SendOnchain {
            address: address(),
            amount_sat: Sat(decimal(10000)),
            fee_rate_sat_vbyte: decimal(1),
        }),
    }
}
fn reviewed(kind: OperationKind, config: &NodeConfig) -> ReviewedIntent {
    ReviewedIntent::build(request(kind), config, &facts(config), now())
        .unwrap()
        .0
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
        .build_signed(|hash| {
            Secp256k1::new()
                .sign_ecdsa_recoverable(hash, &SecretKey::from_slice(&[42; 32]).unwrap())
        })
        .unwrap()
        .to_string()
}
fn address() -> String {
    let key = bitcoin::CompressedPublicKey(peer().parse().unwrap());
    bitcoin::Address::p2wpkh(&key, bitcoin::Network::Regtest).to_string()
}

async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    status: u16,
    body: Vec<u8>,
    location: Option<String>,
    truncate: bool,
) -> Value {
    let mut bytes = Vec::new();
    let mut block = [0u8; 1024];
    let (header_end, length) = loop {
        let n = stream.read(&mut block).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&block[..n]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..end]);
            let length = headers
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            break (end + 4, length);
        }
        assert!(bytes.len() < 65536);
    };
    while bytes.len() < header_end + length {
        let n = stream.read(&mut block).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&block[..n]);
    }
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let captured = json!({"headers":headers,"params":serde_json::from_slice::<Value>(&bytes[header_end..header_end+length]).unwrap()});
    let location = location
        .map(|l| format!("Location: {l}\r\n"))
        .unwrap_or_default();
    let wire=format!("HTTP/1.1 {status} Synthetic\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{location}\r\n",body.len()+usize::from(truncate));
    stream.write_all(wire.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    stream.shutdown().await.unwrap();
    captured
}
async fn server(status: u16, body: Value) -> (Transport, tokio::task::JoinHandle<Value>) {
    raw_server(
        status,
        serde_json::to_vec(&body).unwrap(),
        None,
        false,
        Limits::default(),
    )
    .await
}
async fn raw_server(
    status: u16,
    body: Vec<u8>,
    location: Option<String>,
    truncate: bool,
    limits: Limits,
) -> (Transport, tokio::task::JoinHandle<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve_stream(stream, status, body, location, truncate).await
    });
    (Transport::synthetic(endpoint, &limits), task)
}
fn adapter(transport: Transport, config: NodeConfig) -> ClnAdapter {
    ClnAdapter {
        transport,
        config,
        max_items: 100,
    }
}

#[test]
fn checked_amounts_never_round_or_coerce_absence() {
    for (value, expected) in [
        (json!(1), Some(1)),
        (json!(1000), Some(1000)),
        (json!("1msat"), Some(1)),
        (json!("1sat"), Some(1000)),
        (json!("1001"), Some(1001)),
        (json!(i64::MAX), Some(i64::MAX as u64)),
        (json!(9223372036854775808u64), None),
        (Value::Null, None),
    ] {
        assert_eq!(
            reads::amount(&json!({"a":value}), "a")
                .unwrap()
                .map(Decimal::get),
            expected
        );
    }
    assert_eq!(reads::amount(&json!({}), "a").unwrap(), None);
    for value in [
        json!(1.0),
        json!(-1),
        json!("1e3"),
        json!("1.2sat"),
        json!("1btc"),
        json!(true),
        json!({}),
    ] {
        assert_eq!(
            reads::amount(&json!({"a":value}), "a").unwrap_err().code,
            ErrorCode::UpstreamInvalidResponse
        );
    }
}
#[test]
fn info_sync_warning_and_network_mapping() {
    let mut value = fixture()["getinfo"].clone();
    assert_eq!(reads::info(&value).unwrap().synced, Some(true));
    for warning in ["warning_bitcoind_sync", "warning_lightningd_sync"] {
        value[warning] = json!("UPSTREAM_SENTENCE_CANARY");
        assert_eq!(reads::info(&value).unwrap().synced, None);
        value.as_object_mut().unwrap().remove(warning);
    }
    for (input, expected) in [
        ("bitcoin", Network::Mainnet),
        ("mainnet", Network::Mainnet),
        ("testnet", Network::Testnet),
        ("signet", Network::Signet),
        ("regtest", Network::Regtest),
        ("unrecognized", Network::Unknown),
    ] {
        value["network"] = json!(input);
        assert_eq!(reads::info(&value).unwrap().network, expected);
    }
    value["id"] = json!("wrong");
    assert!(reads::info(&value).is_err());
}
#[test]
fn balances_exact_units_reserved_missing_and_nonintegral_sat() {
    let mut value = fixture()["listfunds"].clone();
    let balances = reads::balances(&value, "synthetic", Network::Regtest, now(), 100).unwrap();
    assert_eq!(balances.onchain_confirmed_sat, Some(Sat(decimal(5))));
    assert_eq!(balances.onchain_unconfirmed_sat, Some(Sat(decimal(2))));
    assert_eq!(
        balances.onchain_spendable_sat,
        balances.onchain_confirmed_sat
    );
    assert_eq!(balances.channel_local_msat, Some(Msat(decimal(1001))));
    assert_eq!(balances.channel_remote_msat, Some(Msat(decimal(1999))));
    assert_eq!(balances.channel_spendable_msat, None);
    value["channels"][0]
        .as_object_mut()
        .unwrap()
        .remove("our_amount_msat");
    assert_eq!(
        reads::balances(&value, "synthetic", Network::Regtest, now(), 100)
            .unwrap()
            .channel_local_msat,
        None
    );
    value["outputs"][0]["amount_msat"] = json!(1001);
    assert_eq!(
        reads::balances(&value, "synthetic", Network::Regtest, now(), 100)
            .unwrap()
            .onchain_confirmed_sat,
        None
    );
    assert_eq!(
        reads::balances(&value, "synthetic", Network::Regtest, now(), 1)
            .unwrap_err()
            .code,
        ErrorCode::NodeOffline
    );
}
#[test]
fn payment_projection_preserves_group_semantics_and_order() {
    let value = fixture()["listpays"].clone();
    let mut reordered = value.clone();
    reordered["pays"].as_array_mut().unwrap().reverse();
    let projected = reads::payments(&value, 100).unwrap();
    let other = reads::payments(&reordered, 100).unwrap();
    assert_eq!(
        serde_json::to_value(&projected.items).unwrap(),
        serde_json::to_value(&other.items).unwrap()
    );
    assert_eq!(projected.items.len(), 1);
    let payment = &projected.items[0];
    assert_eq!(payment.state, PaymentState::Succeeded);
    assert_eq!(payment.amount_msat, Some(Msat(decimal(1001))));
    assert_eq!(payment.fee_msat, Some(Msat(decimal(2))));
    assert_eq!(payment.created_at.timestamp(), 1_750_000_000);
    assert_eq!(payment.completed_at.unwrap().timestamp(), 1_750_000_030);
    let mut pending = value.clone();
    pending["pays"][1]["status"] = json!("pending");
    assert_eq!(
        reads::payments(&pending, 100).unwrap().items[0].state,
        PaymentState::Pending
    );
    for mutation in [
        "duplicate",
        "success_pending",
        "unknown",
        "missing_index",
        "multiple_success",
    ] {
        let mut hostile = value.clone();
        let mut row = hostile["pays"][1].clone();
        match mutation {
            "duplicate" => hostile["pays"].as_array_mut().unwrap().push(row),
            "success_pending" => {
                row["status"] = json!("pending");
                row["created_index"] = json!(9);
                hostile["pays"].as_array_mut().unwrap().push(row);
            }
            "unknown" => hostile["pays"][0]["status"] = json!("UPSTREAM_SENTENCE_CANARY"),
            "missing_index" => {
                hostile["pays"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("created_index");
            }
            _ => {
                row["created_index"] = json!(9);
                hostile["pays"].as_array_mut().unwrap().push(row);
            }
        }
        let projected = reads::payments(&hostile, 100).unwrap();
        assert_eq!(
            projected.items[0].state,
            PaymentState::Unknown,
            "{mutation}"
        );
        assert_eq!(projected.items[0].amount_msat, None);
        assert_eq!(projected.items[0].fee_msat, None);
    }
    for amount in [Value::Null, json!(0)] {
        let mut hostile = value.clone();
        hostile["pays"][1]["amount_msat"] = amount;
        let projected = reads::payments(&hostile, 100).unwrap();
        assert_eq!(projected.items[0].amount_msat, None);
        assert_eq!(projected.items[0].fee_msat, None);
    }
    assert!(reads::payments(&value, 1).is_err());
    assert!(reads::payments(&json!({"pays":[]}), 1)
        .unwrap()
        .items
        .is_empty());
}
#[test]
fn invoices_use_signed_timestamp_and_strip_preimages() {
    let mut value = fixture()["listinvoices"].clone();
    value["invoices"][0]["bolt11"] = json!(invoice());
    let projected = reads::invoices(&value, 100).unwrap();
    assert_eq!(projected.items.len(), 1);
    assert!(projected.truncated);
    let invoice = &projected.items[0];
    assert_eq!(invoice.created_at, now());
    assert_eq!(invoice.amount_msat, Some(Msat(decimal(1001))));
    assert_eq!(invoice.received_msat, Some(Msat(decimal(1002))));
    assert_eq!(invoice.state, InvoiceState::Paid);
    let encoded = serde_json::to_string(invoice).unwrap();
    assert!(!encoded.contains("PREIMAGE_CANARY"));
    assert!(!encoded.contains("created_index"));
    let row = value["invoices"][0].clone();
    value["invoices"].as_array_mut().unwrap().push(row);
    for invoice in reads::invoices(&value, 100).unwrap().items {
        assert_eq!(invoice.state, InvoiceState::Unknown);
        assert_eq!(invoice.amount_msat, None);
    }
}
#[test]
fn peers_channels_transactions_and_fees_preserve_unknowns() {
    let fixture = fixture();
    let peers = reads::peers(&fixture["listpeers"], 100).unwrap();
    assert_eq!(peers.items[0].address.as_deref(), Some("192.0.2.1:9735"));
    assert_eq!(peers.items[0].inbound, None);
    let channels = reads::channels(
        &fixture["listpeerchannels"],
        &fixture["listclosedchannels"],
        100,
    )
    .unwrap();
    assert_eq!(channels.items.len(), 2);
    let open = channels
        .items
        .iter()
        .find(|c| c.state == ChannelState::Active)
        .unwrap();
    assert_eq!(open.capacity_sat, Some(Sat(decimal(3))));
    assert_eq!(open.remote_msat, Some(Msat(decimal(1999))));
    let closed = channels
        .items
        .iter()
        .find(|c| c.state == ChannelState::Closed)
        .unwrap();
    assert_eq!(closed.close_type, Some(CloseType::Unknown));
    let txs = reads::transactions(&fixture["listtransactions"], 100).unwrap();
    let tx = &txs.items[0];
    assert_eq!(tx.amount_sat, None);
    assert_eq!(tx.fee_sat, None);
    assert_eq!(tx.occurred_at, None);
    assert_eq!(tx.confirmations, None);
    assert_eq!(tx.block_height, None);
    assert_eq!(tx.direction, Direction::Unknown);
    assert_eq!(tx.outputs[0].amount_sat, Sat(decimal(2)));
    assert!(!serde_json::to_string(tx).unwrap().contains("RAW_TX_CANARY"));
    let fees = reads::fees(&fixture["feerates"], "synthetic", now()).unwrap();
    assert!(fees.economy.is_none() && fees.normal.is_none() && fees.priority.is_none());
}

#[test]
fn all_eight_commands_have_exact_reviewed_parameters() {
    let config = config();
    let fixture = fixture();
    for (kind, name) in [
        (OperationKind::CreateInvoice, "invoice"),
        (OperationKind::PayInvoice, "xpay"),
        (OperationKind::ConnectPeer, "connect"),
        (OperationKind::DisconnectPeer, "disconnect"),
        (OperationKind::OpenChannel, "fundchannel"),
        (OperationKind::CloseChannel, "close"),
        (OperationKind::NewAddress, "newaddr"),
        (OperationKind::SendOnchain, "withdraw"),
    ] {
        let intent = reviewed(kind, &config);
        let (_, params) = command(
            &intent.operation.request,
            intent.invoice_label.as_deref(),
            intent.close_target.as_deref(),
        )
        .unwrap();
        let mut expected = fixture["requests"][name].clone();
        match kind {
            OperationKind::CreateInvoice => {
                expected["label"] = json!(format!("ld-{}", intent.operation.id))
            }
            OperationKind::PayInvoice => expected["invstring"] = json!(invoice()),
            OperationKind::SendOnchain => expected["destination"] = json!(address()),
            _ => {}
        }
        assert_eq!(params, expected, "{name}");
    }
    assert_eq!(feerate(decimal(1)).unwrap(), "1000perkb");
    assert_eq!((1000u32.div_ceil(4)).max(253), 253);
    assert!(feerate(decimal(u32::MAX as u64)).is_err());
}

#[tokio::test]
async fn success_envelope_and_rune_header_are_exact() {
    let (transport, server) = server(201, fixture()["getinfo"].clone()).await;
    let value = transport.call(Rpc::GetInfo, json!({})).await.unwrap();
    assert_eq!(value, fixture()["getinfo"]);
    let request = server.await.unwrap();
    let headers = request["headers"].as_str().unwrap().to_ascii_lowercase();
    assert!(headers.starts_with("post /v1/getinfo http/1.1"));
    assert!(headers.contains("rune: synthetic_rune_canary"));
    assert!(!headers.contains("nodeid:"));
    assert_eq!(request["params"], json!({}));
}

#[tokio::test]
async fn error_envelopes_are_sanitized_and_not_status_heuristics() {
    for case in fixture()["errors"].as_array().unwrap() {
        let status = case["status"].as_u64().unwrap() as u16;
        let (transport, server) = server(status, case["body"].clone()).await;
        let error = transport
            .call(Rpc::Connect, json!({"id":peer()}))
            .await
            .unwrap_err();
        server.await.unwrap();
        assert_eq!(
            format!("{:?}", error.read_code()),
            case["read_code"].as_str().unwrap()
        );
        let rejected = matches!(error.mutation_class(Rpc::Connect), Class::Rejected(_));
        assert_eq!(rejected, case["rejected"].as_bool().unwrap());
        let text = format!("{error:?}");
        for canary in [
            "PREIMAGE_CANARY",
            "SYNTHETIC_RUNE_CANARY",
            "/secret/cert",
            "https://secret.invalid",
            "RAW_TX_CANARY",
            "PSBT_CANARY",
            "UPSTREAM_SENTENCE_CANARY",
        ] {
            assert!(!text.contains(canary));
        }
    }
}

#[tokio::test]
async fn bounded_truncated_wrong_type_wrapped_and_redirect_are_not_success() {
    for (body, truncate, limits) in [
        (b"{\"id\":".to_vec(), false, Limits::default()),
        (b"{}".to_vec(), true, Limits::default()),
        (b"{\"result\":{}}".to_vec(), false, Limits::default()),
        (b"[]".to_vec(), false, Limits::default()),
        (
            vec![b' '; 100],
            false,
            Limits {
                max_response_bytes: 32,
                ..Limits::default()
            },
        ),
    ] {
        let (transport, task) = raw_server(201, body, None, truncate, limits).await;
        let error = transport
            .call(Rpc::FundChannel, json!({}))
            .await
            .unwrap_err();
        task.await.unwrap();
        assert!(!matches!(
            error.mutation_class(Rpc::FundChannel),
            Class::Positive | Class::Rejected(_)
        ));
    }
    let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let location = format!("http://{}/stolen", destination.local_addr().unwrap());
    let (transport, task) = raw_server(
        302,
        b"{}".to_vec(),
        Some(location),
        false,
        Limits::default(),
    )
    .await;
    let error = transport.call(Rpc::Withdraw, json!({})).await.unwrap_err();
    task.await.unwrap();
    assert!(matches!(error.mutation_class(Rpc::Withdraw), Class::Lost));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), destination.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dispatch_is_one_shot_and_returns_publication_not_completion() {
    for (kind, response_key) in [
        (OperationKind::OpenChannel, "fundchannel"),
        (OperationKind::CloseChannel, "close_unilateral"),
        (OperationKind::SendOnchain, "withdraw"),
        (OperationKind::DisconnectPeer, "disconnect"),
        (OperationKind::ConnectPeer, "connect"),
        (OperationKind::NewAddress, "newaddr"),
        (OperationKind::CreateInvoice, "invoice"),
        (OperationKind::PayInvoice, "xpay"),
    ] {
        let config = config();
        let intent = reviewed(kind, &config);
        let mut response = fixture()[response_key].clone();
        if kind == OperationKind::NewAddress {
            response["bech32"] = json!(address());
        }
        if kind == OperationKind::CreateInvoice {
            response["bolt11"] = json!(invoice());
        }
        let (transport, server) = server(201, response).await;
        let evidence = adapter(transport, config)
            .execute_once(ClaimPermit {
                claim_id: Uuid::new_v4(),
                intent,
                secret: None,
            })
            .await;
        let captured = server.await.unwrap();
        assert!(matches!(evidence.class, Class::Positive), "{kind:?}");
        match evidence.facts.unwrap() {
            Facts::Open {
                active, published, ..
            } => {
                assert!(!active);
                assert!(published);
                assert_eq!(captured["params"]["feerate"], "1000perkb");
                assert_eq!(captured["params"]["announce"], false);
            }
            Facts::Close {
                close_type,
                closed,
                published,
                ..
            } => {
                assert_eq!(close_type, CloseType::Unilateral);
                assert!(!closed);
                assert!(published);
                assert_eq!(captured["params"]["unilateraltimeout"], 0);
            }
            Facts::Send {
                fee_sat,
                confirmations,
                published,
                ..
            } => {
                assert!(published);
                assert_eq!(fee_sat, None);
                assert_eq!(confirmations, None);
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn invalid_dispatch_fields_and_preimage_mismatch_stay_uncertain() {
    for (kind, value) in [
        (
            OperationKind::OpenChannel,
            json!({"txid":fixture()["fundchannel"]["txid"],"outnum":0}),
        ),
        (
            OperationKind::PayInvoice,
            json!({"payment_preimage":"00".repeat(32),"amount_msat":1001,"amount_sent_msat":1001,"successful_parts":1,"failed_parts":0}),
        ),
        (OperationKind::NewAddress, json!({"bech32":"invalid"})),
        (OperationKind::ConnectPeer, json!({"id":"wrong"})),
    ] {
        let config = config();
        let intent = reviewed(kind, &config);
        let (transport, server) = server(201, value).await;
        let evidence = adapter(transport, config)
            .execute_once(ClaimPermit {
                claim_id: Uuid::new_v4(),
                intent,
                secret: None,
            })
            .await;
        server.await.unwrap();
        assert!(matches!(evidence.class, Class::Partial));
        assert!(evidence.facts.is_none());
    }
}

fn settings(directory: &std::path::Path, endpoint: url::Url) -> NodeSettings {
    let cert = directory.join("synthetic-ca.pem");
    let rune = directory.join("synthetic-rune");
    std::fs::write(
        &cert,
        include_bytes!("../../../tests/fixtures/cln-v25.02/synthetic-ca.pem"),
    )
    .unwrap();
    std::fs::write(&rune, b"SYNTHETIC_RUNE_CANARY\n").unwrap();
    std::fs::set_permissions(&rune, std::fs::Permissions::from_mode(0o600)).unwrap();
    NodeSettings {
        id: "synthetic".into(),
        label: "Synthetic".into(),
        backend: Backend::ClnRest,
        endpoint,
        certificate_file: cert,
        credential_file: rune,
        expected_pubkey: peer(),
        network: Network::Regtest,
        read_only: false,
        policy: config().policy.limits,
        peer_policy: PeerPolicy::default(),
    }
}
async fn tls_server(host: &str) -> (url::Url, tokio::task::JoinHandle<Option<Value>>) {
    use tokio_rustls::{
        rustls::{Certificate, PrivateKey, ServerConfig},
        TlsAcceptor,
    };
    let cert = Certificate(
        include_bytes!("../../../tests/fixtures/cln-v25.02/synthetic-cert.der").to_vec(),
    );
    let key =
        PrivateKey(include_bytes!("../../../tests/fixtures/cln-v25.02/synthetic-key.der").to_vec());
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{host}:{}/", listener.local_addr().unwrap().port())
        .parse()
        .unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        match acceptor.accept(stream).await {
            Ok(stream) => Some(
                serve_stream(
                    stream,
                    201,
                    serde_json::to_vec(&fixture()["getinfo"]).unwrap(),
                    None,
                    false,
                )
                .await,
            ),
            Err(_) => None,
        }
    });
    (endpoint, task)
}

#[tokio::test]
async fn configured_tls_root_hostname_and_file_credentials_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let (endpoint, task) = tls_server("localhost").await;
    let settings = settings(directory.path(), endpoint);
    let adapter = ClnAdapter::connect(&settings, &Limits::default(), config())
        .await
        .unwrap();
    let captured = task.await.unwrap().unwrap();
    assert!(captured["headers"]
        .as_str()
        .unwrap()
        .contains("SYNTHETIC_RUNE_CANARY"));
    drop(adapter);
    let (endpoint, task) = tls_server("127.0.0.1").await;
    let mut wrong_host = settings.clone();
    wrong_host.endpoint = endpoint;
    let error = ClnAdapter::connect(&wrong_host, &Limits::default(), config())
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::NodeOffline);
    assert!(task.await.unwrap().is_none());
    let mut invalid = settings.clone();
    invalid.endpoint = "http://localhost/".parse().unwrap();
    assert!(Transport::connect(&invalid, &Limits::default()).is_err());
    for endpoint in [
        "https://user:secret@localhost/",
        "https://localhost/?credential=bad",
        "https://localhost/#fragment",
        "https://localhost/v1/",
    ] {
        invalid = settings.clone();
        invalid.endpoint = endpoint.parse().unwrap();
        assert!(Transport::connect(&invalid, &Limits::default()).is_err());
    }
    invalid = settings.clone();
    invalid.certificate_file = directory.path().join("missing");
    assert!(Transport::connect(&invalid, &Limits::default()).is_err());
    std::fs::write(&settings.certificate_file, b"").unwrap();
    assert!(Transport::connect(&settings, &Limits::default()).is_err());
    std::fs::write(
        &settings.certificate_file,
        include_bytes!("../../../tests/fixtures/cln-v25.02/synthetic-ca.pem"),
    )
    .unwrap();
    std::fs::set_permissions(
        &settings.credential_file,
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(Transport::connect(&settings, &Limits::default()).is_err());
    std::fs::set_permissions(
        &settings.credential_file,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(&settings.credential_file, b"SYNTHETIC\nINJECTED_HEADER").unwrap();
    assert!(Transport::connect(&settings, &Limits::default()).is_err());
}

#[tokio::test]
async fn configured_deadline_never_retries_a_mutation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let task = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    });
    let transport = Transport::synthetic(
        endpoint,
        &Limits {
            rpc_seconds: 1,
            ..Limits::default()
        },
    );
    let started = std::time::Instant::now();
    let error = transport.call(Rpc::Withdraw, json!({})).await.unwrap_err();
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(matches!(error.mutation_class(Rpc::Withdraw), Class::Lost));
    task.await.unwrap();
}

#[test]
fn close_labels_and_required_fields_never_invent_cooperation() {
    let config = config();
    let intent = reviewed(OperationKind::CloseChannel, &config);
    for (name, expected, published) in [
        ("close_mutual", CloseType::Cooperative, true),
        ("close_unilateral", CloseType::Unilateral, true),
        ("close_unopened", CloseType::Unknown, false),
    ] {
        let mut reference = RecoveryReference::planned(&intent);
        let facts = dispatch_facts(&intent, &fixture()[name], &mut reference).unwrap();
        match facts {
            Facts::Close {
                close_type,
                closed,
                published: actual,
                ..
            } => {
                assert_eq!(close_type, expected);
                assert!(!closed);
                assert_eq!(actual, published);
            }
            _ => panic!("wrong fact"),
        }
    }
    let mut reference = RecoveryReference::planned(&intent);
    assert!(dispatch_facts(&intent, &json!({"type":"mutual"}), &mut reference).is_err());
}

#[test]
fn payment_multipart_time_and_later_failure_do_not_fabricate_settlement() {
    let mut value = fixture()["listpays"].clone();
    value["pays"][1]["number_of_parts"] = json!(2);
    let projected = reads::payments(&value, 100).unwrap();
    assert_eq!(projected.items[0].completed_at, None);
    assert_eq!(projected.items[0].fee_msat, Some(Msat(decimal(2))));
    value["pays"][0]["created_index"] = json!(99);
    let projected = reads::payments(&value, 100).unwrap();
    assert_eq!(projected.items[0].state, PaymentState::Succeeded);
    assert_eq!(projected.items[0].fee_msat, Some(Msat(decimal(2))));
}

async fn scripted(
    values: Vec<Value>,
    limits: &Limits,
) -> (Transport, tokio::task::JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let task = tokio::spawn(async move {
        let mut captured = Vec::new();
        for value in values {
            let (stream, _) = listener.accept().await.unwrap();
            captured.push(
                serve_stream(
                    stream,
                    201,
                    serde_json::to_vec(&value).unwrap(),
                    None,
                    false,
                )
                .await,
            );
        }
        captured
    });
    (Transport::synthetic(endpoint, limits), task)
}
fn query(
    kind: OperationKind,
    config: &NodeConfig,
    reference: RecoveryReference,
) -> ObservationQuery {
    ObservationQuery {
        operation_id: Uuid::new_v4(),
        binding: config.binding.clone(),
        generation: config.generation,
        kind,
        claim_id: Uuid::new_v4(),
        sequence: 1,
        reference,
        close_type: None,
        close_txids: vec![],
    }
}

#[tokio::test]
async fn preparation_checks_exact_operation_label_and_expiry_without_mutation() {
    let config = config();
    let intent = reviewed(OperationKind::CreateInvoice, &config);
    let (transport, task) = scripted(
        vec![fixture()["getinfo"].clone(), json!({"valid":true})],
        &Limits::default(),
    )
    .await;
    let facts = adapter(transport, config)
        .prepare_review(&intent.operation)
        .await
        .unwrap();
    assert!(facts.permission);
    assert!(facts.sync_usable);
    let requests = task.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1]["headers"]
        .as_str()
        .unwrap()
        .starts_with("POST /v1/checkrune "));
    assert_eq!(requests[1]["params"]["method"], "invoice");
    assert_eq!(
        requests[1]["params"]["params"],
        json!({"amount_msat":1001,"label":intent.invoice_label,"description":"Synthetic invoice","expiry":3600})
    );
}

#[tokio::test]
async fn payment_reads_enrich_by_exact_hash_and_exhaustion_is_unavailable() {
    let mut discovery = fixture()["listpays"].clone();
    discovery["pays"][1]["amount_sent_msat"] = json!(1);
    let exact = fixture()["listpays"].clone();
    let (transport, task) = scripted(
        vec![
            fixture()["getinfo"].clone(),
            discovery.clone(),
            exact.clone(),
        ],
        &Limits::default(),
    )
    .await;
    let read = adapter(transport, config())
        .read(ReadQuery::Payments)
        .await
        .unwrap();
    match read {
        ReadResult::Payments(rows) => {
            assert_eq!(rows.items.len(), 1);
            assert_eq!(rows.items[0].fee_msat, Some(Msat(decimal(2))));
        }
        _ => panic!("wrong read"),
    }
    let requests = task.await.unwrap();
    assert_eq!(
        requests[2]["params"],
        json!({"payment_hash":"f8261a56bbc8efc5675429c512d3b14de7f6a0866c1247fe4865d3968314a1cd"})
    );
    assert!(!requests[2]["params"]
        .as_object()
        .unwrap()
        .contains_key("limit"));
    assert!(!requests[2]["params"]
        .as_object()
        .unwrap()
        .contains_key("start"));
    let budget = serde_json::to_vec(&discovery).unwrap().len()
        + serde_json::to_vec(&exact).unwrap().len()
        - 1;
    let limits = Limits {
        max_response_bytes: budget,
        ..Limits::default()
    };
    let (transport, task) = scripted(
        vec![fixture()["getinfo"].clone(), discovery, exact],
        &limits,
    )
    .await;
    let error = adapter(transport, config())
        .read(ReadQuery::Payments)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::NodeOffline);
    task.await.unwrap();
}

#[tokio::test]
async fn exact_observation_does_not_attribute_old_groups_or_absence_to_failure() {
    let config = config();
    for pays in [
        fixture()["listpays"].clone(),
        json!({"pays":[]}),
        json!({"pays":[fixture()["listpays"]["pays"][0].clone()]}),
    ] {
        let (transport, task) =
            scripted(vec![fixture()["getinfo"].clone(), pays], &Limits::default()).await;
        let reference = RecoveryReference {
            payment_hash: Some(
                "f8261a56bbc8efc5675429c512d3b14de7f6a0866c1247fe4865d3968314a1cd".into(),
            ),
            ..Default::default()
        };
        let evidence = adapter(transport, config.clone())
            .observe_exact(query(OperationKind::PayInvoice, &config, reference.clone()))
            .await;
        assert!(matches!(evidence.class, Class::NotFound));
        assert!(evidence.facts.is_none());
        assert_eq!(evidence.reference, reference);
        let requests = task.await.unwrap();
        assert_eq!(
            requests[1]["params"],
            json!({"payment_hash":reference.payment_hash})
        );
    }
    let (transport, task) = scripted(
        vec![
            fixture()["getinfo"].clone(),
            json!({"channels":[]}),
            json!({"closedchannels":[]}),
        ],
        &Limits::default(),
    )
    .await;
    let reference = RecoveryReference {
        channel: Some(format!(
            "{}:1",
            fixture()["fundchannel"]["txid"].as_str().unwrap()
        )),
        ..Default::default()
    };
    let evidence = adapter(transport, config.clone())
        .observe_exact(query(OperationKind::OpenChannel, &config, reference))
        .await;
    assert!(matches!(evidence.class, Class::NotFound));
    task.await.unwrap();
}

#[tokio::test]
async fn exact_channel_and_invoice_observation_require_original_references() {
    let config = config();
    let intent = reviewed(OperationKind::CreateInvoice, &config);
    let mut row = fixture()["listinvoices"]["invoices"][0].clone();
    row["label"] = json!(intent.invoice_label);
    row["bolt11"] = json!(invoice());
    let (transport, task) = scripted(
        vec![fixture()["getinfo"].clone(), json!({"invoices":[row]})],
        &Limits::default(),
    )
    .await;
    let evidence = adapter(transport, config.clone())
        .observe_exact(query(
            OperationKind::CreateInvoice,
            &config,
            RecoveryReference::planned(&intent),
        ))
        .await;
    assert!(matches!(evidence.class, Class::Positive));
    let requests = task.await.unwrap();
    assert_eq!(requests[1]["params"], json!({"label":intent.invoice_label}));
    let channel = fixture()["fundchannel"]["channel_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (transport, task) = scripted(
        vec![
            fixture()["getinfo"].clone(),
            fixture()["listpeerchannels"].clone(),
            fixture()["listclosedchannels"].clone(),
        ],
        &Limits::default(),
    )
    .await;
    let evidence = adapter(transport, config.clone())
        .observe_exact(query(
            OperationKind::OpenChannel,
            &config,
            RecoveryReference {
                channel: Some(channel),
                ..Default::default()
            },
        ))
        .await;
    match evidence.facts.unwrap() {
        Facts::Open { active, .. } => assert!(active),
        _ => panic!("wrong fact"),
    };
    task.await.unwrap();
}

#[tokio::test]
async fn closed_history_carries_close_type_only_for_same_observed_transaction() {
    let config = config();
    let mut closed = fixture()["listclosedchannels"].clone();
    closed["closedchannels"][0]["channel_id"] = fixture()["fundchannel"]["channel_id"].clone();
    closed["closedchannels"][0]["funding_txid"] = fixture()["fundchannel"]["txid"].clone();
    closed["closedchannels"][0]["funding_outnum"] = json!(1);
    for (known_txids, expected) in [
        (
            vec!["4444444444444444444444444444444444444444444444444444444444444444".into()],
            CloseType::Unilateral,
        ),
        (vec![], CloseType::Unknown),
    ] {
        let (transport, task) = scripted(
            vec![
                fixture()["getinfo"].clone(),
                json!({"channels":[]}),
                closed.clone(),
            ],
            &Limits::default(),
        )
        .await;
        let mut query = query(
            OperationKind::CloseChannel,
            &config,
            RecoveryReference {
                channel: facts(&config).close_target,
                ..Default::default()
            },
        );
        query.close_type = Some(CloseType::Unilateral);
        query.close_txids = known_txids;
        let evidence = adapter(transport, config.clone())
            .observe_exact(query)
            .await;
        match evidence.facts.unwrap() {
            Facts::Close {
                closed, close_type, ..
            } => {
                assert!(closed);
                assert_eq!(close_type, expected);
            }
            _ => panic!("wrong fact"),
        };
        task.await.unwrap();
    }
}

fn emit(name: &str, schema: &str, value: impl Serialize) {
    if let Ok(directory) = std::env::var("CLN_EVIDENCE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&json!({"schema":schema,"value":value})).unwrap(),
        )
        .unwrap();
    }
}
#[tokio::test]
async fn real_dispatch_evidence_transitions_emit_frozen_operation_projections() {
    let config = config();
    for (kind, key) in [
        (OperationKind::OpenChannel, "fundchannel"),
        (OperationKind::CloseChannel, "close_unilateral"),
        (OperationKind::SendOnchain, "withdraw"),
        (OperationKind::PayInvoice, "xpay"),
        (OperationKind::CreateInvoice, "invoice"),
        (OperationKind::ConnectPeer, "connect"),
        (OperationKind::DisconnectPeer, "disconnect"),
        (OperationKind::NewAddress, "newaddr"),
    ] {
        let intent = reviewed(kind, &config);
        let mut response = fixture()[key].clone();
        if kind == OperationKind::CreateInvoice {
            response["bolt11"] = json!(invoice());
        }
        if kind == OperationKind::NewAddress {
            response["bech32"] = json!(address());
        }
        let claim_id = Uuid::new_v4();
        let mut operation = intent.operation.clone();
        operation.state = OperationState::Dispatching;
        operation.stage = OperationStage::Submitted;
        operation.authorization.status = if operation.review.sensitive {
            AuthorizationState::Consumed
        } else {
            AuthorizationState::NotRequired
        };
        let knowledge = Knowledge::new(&intent);
        let (transport, task) = server(201, response).await;
        let evidence = adapter(transport, config.clone())
            .execute_once(ClaimPermit {
                claim_id,
                intent: intent.clone(),
                secret: None,
            })
            .await;
        task.await.unwrap();
        let transition = evidence::transition(
            &intent,
            operation,
            knowledge,
            evidence,
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
        emit(&format!("cln-{kind:?}"), "Operation", &transition.operation);
    }
    let fixture = fixture();
    emit(
        "balances",
        "Balances",
        reads::balances(
            &fixture["listfunds"],
            "synthetic",
            Network::Regtest,
            now(),
            100,
        )
        .unwrap(),
    );
    for row in reads::payments(&fixture["listpays"], 100).unwrap().items {
        emit("payment", "Payment", row);
    }
    for (i, row) in reads::channels(
        &fixture["listpeerchannels"],
        &fixture["listclosedchannels"],
        100,
    )
    .unwrap()
    .items
    .iter()
    .enumerate()
    {
        emit(&format!("channel-{i}"), "Channel", row);
    }
    for row in reads::transactions(&fixture["listtransactions"], 100)
        .unwrap()
        .items
    {
        emit("transaction", "Transaction", row);
    }
}

#[tokio::test]
async fn documented_refusals_are_method_specific_not_message_scraping() {
    for (rpc, code, expected) in [
        (Rpc::XPay, 207, Some(ErrorCode::InvoiceExpired)),
        (Rpc::XPay, 200, None),
        (Rpc::XPay, 205, None),
        (Rpc::XPay, 206, None),
        (Rpc::XPay, 215, None),
        (Rpc::Invoice, 900, Some(ErrorCode::IdempotencyConflict)),
        (Rpc::Invoice, 901, Some(ErrorCode::IdempotencyConflict)),
        (Rpc::Invoice, -1, Some(ErrorCode::UpstreamRejected)),
        (Rpc::Withdraw, 301, Some(ErrorCode::InsufficientFunds)),
        (Rpc::Withdraw, 302, Some(ErrorCode::UpstreamRejected)),
        (Rpc::Withdraw, 313, Some(ErrorCode::UpstreamRejected)),
        (Rpc::Withdraw, -1, Some(ErrorCode::UpstreamRejected)),
        (Rpc::Connect, 400, Some(ErrorCode::PeerUnavailable)),
        (Rpc::Connect, 401, Some(ErrorCode::PeerUnavailable)),
        (Rpc::Connect, 402, Some(ErrorCode::PeerUnavailable)),
        (Rpc::FundChannel, 303, None),
    ] {
        let (transport, task) = server(
            500,
            json!({"code":code,"message":"UPSTREAM_SENTENCE_CANARY no route insufficient funds"}),
        )
        .await;
        let error = transport.call(rpc, json!({})).await.unwrap_err();
        task.await.unwrap();
        let actual = match error.mutation_class(rpc) {
            Class::Rejected(rejection) => Some(rejection.code()),
            _ => None,
        };
        assert_eq!(actual, expected);
    }
}

#[tokio::test]
async fn chunked_oversize_response_hits_streaming_bound_without_content_length() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 1024];
        while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buffer[..n]);
        }
        let mut wire =
            b"HTTP/1.1 201 Synthetic\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                .to_vec();
        for chunk in b"{\"ignored\":\"SYNTHETIC_RESPONSE_TOO_LARGE\"}".chunks(8) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        stream.write_all(&wire).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let transport = Transport::synthetic(
        endpoint,
        &Limits {
            max_response_bytes: 16,
            ..Limits::default()
        },
    );
    let error = transport.call(Rpc::Withdraw, json!({})).await.unwrap_err();
    assert!(matches!(error, transport::CallError::Limit));
    assert_eq!(error.read_code(), ErrorCode::NodeOffline);
    assert!(matches!(error.mutation_class(Rpc::Withdraw), Class::Lost));
    task.await.unwrap();
}

#[tokio::test]
async fn unrelated_peer_in_filtered_response_cannot_prove_disconnect() {
    let config = config();
    let reference = RecoveryReference {
        peer: Some("02c6047f9441ed7d6d3045406e95c07cd85a778e4b8cef3ca7abac09b95c709ee5".into()),
        ..Default::default()
    };
    let (transport, task) = scripted(
        vec![fixture()["getinfo"].clone(), fixture()["listpeers"].clone()],
        &Limits::default(),
    )
    .await;
    let evidence = adapter(transport, config.clone())
        .observe_exact(query(OperationKind::DisconnectPeer, &config, reference))
        .await;
    assert!(!matches!(
        evidence.class,
        Class::Positive | Class::Rejected(_)
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn disappearing_exact_hash_marks_snapshot_truncated_not_authoritative_empty() {
    let (transport, task) = scripted(
        vec![
            fixture()["getinfo"].clone(),
            fixture()["listpays"].clone(),
            json!({"pays":[]}),
        ],
        &Limits::default(),
    )
    .await;
    match adapter(transport, config())
        .read(ReadQuery::Payments)
        .await
        .unwrap()
    {
        ReadResult::Payments(rows) => {
            assert!(rows.items.is_empty());
            assert!(rows.truncated);
        }
        _ => panic!("wrong read"),
    };
    task.await.unwrap();
}

#[tokio::test]
async fn observed_unilateral_transaction_reaches_truthful_terminal_engine_failure() {
    let config = config();
    let intent = reviewed(OperationKind::CloseChannel, &config);
    let claim_id = Uuid::new_v4();
    let mut operation = intent.operation.clone();
    operation.state = OperationState::Dispatching;
    operation.stage = OperationStage::Submitted;
    operation.authorization.status = AuthorizationState::Consumed;
    let mut closed = fixture()["listclosedchannels"].clone();
    closed["closedchannels"][0]["channel_id"] = fixture()["fundchannel"]["channel_id"].clone();
    closed["closedchannels"][0]["funding_txid"] = fixture()["fundchannel"]["txid"].clone();
    closed["closedchannels"][0]["funding_outnum"] = json!(1);
    let (transport, task) = scripted(
        vec![
            fixture()["close_unilateral"].clone(),
            fixture()["getinfo"].clone(),
            json!({"channels":[]}),
            closed,
        ],
        &Limits::default(),
    )
    .await;
    let adapter = adapter(transport, config.clone());
    let evidence = adapter
        .execute_once(ClaimPermit {
            claim_id,
            intent: intent.clone(),
            secret: None,
        })
        .await;
    let pending = evidence::transition(
        &intent,
        operation,
        Knowledge::new(&intent),
        evidence,
        evidence::ObservationContext {
            claim_id,
            allocated_sequence: 0,
            read: false,
            now: now(),
        },
    )
    .unwrap();
    assert!(!pending.release);
    assert_eq!(pending.operation.state, OperationState::Pending);
    let mut query = query(
        OperationKind::CloseChannel,
        &config,
        pending.knowledge.reference.clone(),
    );
    query.operation_id = intent.operation.id;
    query.claim_id = claim_id;
    query.close_type = Some(CloseType::Unilateral);
    query.close_txids =
        vec!["4444444444444444444444444444444444444444444444444444444444444444".into()];
    let evidence = adapter.observe_exact(query).await;
    task.await.unwrap();
    let completed = evidence::transition(
        &intent,
        pending.operation,
        pending.knowledge,
        evidence,
        evidence::ObservationContext {
            claim_id,
            allocated_sequence: 1,
            read: true,
            now: now() + chrono::Duration::seconds(1),
        },
    )
    .unwrap();
    assert!(completed.release);
    assert_eq!(completed.operation.state, OperationState::Failed);
    assert_eq!(completed.operation.stage, OperationStage::ChannelClosed);
    assert_eq!(
        completed.operation.error.as_ref().unwrap().code,
        ErrorCode::UnexpectedUnilateralClose
    );
    emit("cln-unilateral-closed", "Operation", completed.operation);
}
