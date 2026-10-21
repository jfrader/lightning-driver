use super::*;

async fn read(f: &Journey, browser: &Browser, suffix: &str, schema: &str) -> (StatusCode, Value) {
    let (status, value, _) = call(
        &f.state,
        authenticated(get(&format!("/api/v1/nodes/synthetic/{suffix}")), browser),
        schema,
    )
    .await;
    (status, value)
}

async fn expire(f: &Journey) {
    f.state
        .registry
        .get("synthetic")
        .unwrap()
        .reads
        .lock()
        .await
        .checked = None;
}

#[actix_web::test]
async fn live_info_requires_graph_sync_only_for_routing_payments() {
    for backend in [Backend::LndGrpc, Backend::LndRest, Backend::ClnRest] {
        for read_only in [false, true] {
            let f = Journey::new(backend, read_only).await;
            f.harness.scenario.lock().unwrap().expect_mutations(&[]);
            let browser = login(&f.state, None).await;
            let (status, info) = read(&f, &browser, "info", "NodeInfo").await;
            assert_eq!(status, StatusCode::OK, "{backend:?}: {info}");
            let node = &info["node"];
            assert_eq!(node["status"]["synced_to_chain"], true);
            assert_eq!(
                node["status"]["synced_to_graph"],
                if backend == Backend::ClnRest {
                    Value::Null
                } else {
                    json!(false)
                }
            );
            let capabilities = node["capabilities"].as_object().unwrap();
            assert_eq!(capabilities.len(), 8);
            for (kind, capability) in capabilities {
                let reason = if read_only {
                    json!("read_only")
                } else if kind == "pay_invoice" && backend != Backend::ClnRest {
                    json!("syncing")
                } else {
                    Value::Null
                };
                assert_eq!(
                    *capability,
                    json!({"enabled": reason.is_null(), "reason": reason}),
                    "{backend:?}/{kind}"
                );
            }
            f.harness
                .scenario
                .lock()
                .unwrap()
                .assert_no_unexpected_calls();
            f.harness.stop().await;
        }
    }
}

#[actix_web::test]
async fn seeded_collections_use_production_factory_on_all_transports() {
    for backend in [Backend::LndGrpc, Backend::LndRest, Backend::ClnRest] {
        let f = Journey::new(backend, false).await;
        f.harness.scenario.lock().unwrap().seed_collections();
        f.harness.scenario.lock().unwrap().expect_mutations(&[]);
        let browser = login(&f.state, None).await;
        for (route, schema) in [
            ("info", "NodeInfo"),
            ("balances", "Balances"),
            ("payments", "PaymentsPage"),
            ("invoices", "InvoicesPage"),
            ("peers", "PeersPage"),
            ("channels", "ChannelsPage"),
            ("transactions", "TransactionsPage"),
            ("fee-estimates", "FeeEstimates"),
            ("status", "NodeStatus"),
        ] {
            let (status, value) = read(&f, &browser, route, schema).await;
            assert_eq!(status, StatusCode::OK, "{backend:?}/{route}: {value}");
            match route {
                "info" => {
                    assert_eq!(value["node"]["network"], "regtest");
                    assert_eq!(value["node"]["identity_pubkey"], PEER);
                    assert_eq!(
                        value["node"]["capabilities"]["pay_invoice"]["enabled"],
                        true
                    );
                    assert_eq!(value["alias"], "Synthetic");
                }
                "balances" => {
                    assert_eq!(value["channel_local_msat"], "1001");
                    assert_eq!(
                        value["onchain_confirmed_sat"],
                        if backend == Backend::ClnRest {
                            "5"
                        } else {
                            "9007199254740993"
                        }
                    );
                }
                "invoices" | "payments" => {
                    assert_eq!(value["items"][0]["amount_msat"], "1001");
                }
                "peers" => assert_eq!(value["items"][0]["pubkey"], PEER),
                "channels" => assert_eq!(value["items"][0]["capacity_sat"], "3"),
                "transactions" => {
                    assert_eq!(value["items"][0]["txid"], synthetic_node_harness::TXID)
                }
                "fee-estimates" => assert!(value["normal"].is_null()),
                "status" => assert_eq!(value["status"], "online"),
                _ => unreachable!(),
            }
        }
        for route in [
            "invoices?status=unpaid",
            "payments?status=failed",
            "channels?state=opening",
        ] {
            let schema = if route.starts_with("invoices") {
                "InvoicesPage"
            } else if route.starts_with("payments") {
                "PaymentsPage"
            } else {
                "ChannelsPage"
            };
            let (status, value) = read(&f, &browser, route, schema).await;
            assert_eq!(status, StatusCode::OK, "{value}");
            assert_eq!(value["items"], json!([]));
        }
        for route in [
            "payments?limit=0",
            "payments?limit=201",
            "payments?limit=01",
            "payments?status=bogus",
            "peers?status=paid",
            "info?limit=1",
            "balances?limit=1",
            "channels?state=paid",
        ] {
            assert_eq!(
                read(&f, &browser, route, "Error").await.0,
                StatusCode::BAD_REQUEST,
                "{route}"
            );
        }
        f.harness
            .scenario
            .lock()
            .unwrap()
            .assert_no_unexpected_calls();
        f.harness.stop().await;
    }
}

#[actix_web::test]
async fn failed_observation_keeps_last_good_data_and_disables_capabilities() {
    let f = Journey::new(Backend::LndRest, false).await;
    f.harness.scenario.lock().unwrap().seed_collections();
    let browser = login(&f.state, None).await;
    let (_, first) = read(&f, &browser, "balances", "Balances").await;
    let (_, info) = read(&f, &browser, "info", "NodeInfo").await;
    f.harness
        .scenario
        .lock()
        .unwrap()
        .fault("GetInfo", Fault::PermissionDenied);
    expire(&f).await;
    let (status, stale) = read(&f, &browser, "balances", "Balances").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stale["observed_at"], first["observed_at"]);
    assert_eq!(stale["stale"], true);
    let (_, stale_info) = read(&f, &browser, "info", "NodeInfo").await;
    assert_eq!(stale_info["observed_at"], info["observed_at"]);
    assert_eq!(
        stale_info["node"]["capabilities"]["pay_invoice"]["enabled"],
        false
    );
    assert_eq!(
        read(&f, &browser, "payments", "Error").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    expire(&f).await;
    let (_, recovered) = read(&f, &browser, "info", "NodeInfo").await;
    assert_eq!(recovered["stale"], false);
    f.harness.stop().await;
}

#[actix_web::test]
async fn no_initial_observation_and_identity_mismatch_are_not_empty_success() {
    for backend in [Backend::LndGrpc, Backend::LndRest, Backend::ClnRest] {
        let f = Journey::new(backend, true).await;
        let browser = login(&f.state, None).await;
        f.harness.scenario.lock().unwrap().set_identity(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "regtest",
        );
        for (route, schema) in [
            ("info", "Error"),
            ("balances", "Error"),
            ("payments", "Error"),
        ] {
            assert_eq!(
                read(&f, &browser, route, schema).await.0,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        let (_, status) = read(&f, &browser, "status", "NodeStatus").await;
        assert_eq!(status["status"], "identity_mismatch");
        assert!(status["observed_at"].is_null());
        let summary = f
            .state
            .registry
            .get("synthetic")
            .unwrap()
            .summary(Utc::now(), lightning_client::money::Decimal::ZERO);
        assert_eq!(
            summary.capabilities.pay_invoice.reason,
            Some(CapabilityReason::ReadOnly)
        );
        f.harness
            .scenario
            .lock()
            .unwrap()
            .set_identity(PEER, "regtest");
        expire(&f).await;
        let (_, info) = read(&f, &browser, "info", "NodeInfo").await;
        assert_eq!(
            info["node"]["capabilities"]["pay_invoice"]["reason"],
            "read_only"
        );
        f.harness.stop().await;
    }
}

#[actix_web::test]
async fn cursor_snapshot_is_immutable_and_bound_to_session_limit_and_node() {
    let mut f = Journey::new(Backend::ClnRest, false).await;
    f.harness.scenario.lock().unwrap().seed_collections();
    let mut browser = login(&f.state, None).await;
    let (status, first) = read(&f, &browser, "channels?limit=1", "ChannelsPage").await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let cursor = first["next_cursor"].as_str().unwrap();
    let route = format!("channels?limit=1&cursor={cursor}");
    f.harness
        .scenario
        .lock()
        .unwrap()
        .fault("getinfo", Fault::PermissionDenied);
    expire(&f).await;
    assert_eq!(
        read(&f, &browser, "status", "NodeStatus").await.1["stale"],
        true
    );
    let (status, second) = read(&f, &browser, &route, "ChannelsPage").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["observed_at"], first["observed_at"]);
    assert_eq!(second["stale"], false);
    assert!(second["next_cursor"].is_null());
    assert_ne!(second["items"][0]["id"], first["items"][0]["id"]);
    assert_eq!(read(&f, &browser, &route, "ChannelsPage").await.1, second);
    let authenticator = std::mem::replace(
        &mut browser.authenticator,
        WebauthnAuthenticator::new(SoftPasskey::new(true)),
    );
    let other = login(&f.state, Some(authenticator)).await;
    assert_eq!(
        read(&f, &other, &route, "ErrorResponse").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        read(
            &f,
            &browser,
            &format!("channels?limit=2&cursor={cursor}"),
            "ErrorResponse"
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        read(
            &f,
            &browser,
            &format!("channels?limit=1&state=active&cursor={cursor}"),
            "ErrorResponse"
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        read(
            &f,
            &browser,
            &format!("peers?limit=1&cursor={cursor}"),
            "ErrorResponse"
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    f.settings.nodes[0].expected_pubkey =
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5".into();
    f.restart().await;
    let browser = login(&f.state, Some(other.authenticator)).await;
    assert_eq!(
        read(&f, &browser, &route, "ErrorResponse").await.0,
        StatusCode::GONE
    );
    assert_eq!(
        read(&f, &browser, "channels", "ErrorResponse").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    f.settings.nodes.clear();
    f.restart().await;
    let browser = login(&f.state, Some(browser.authenticator)).await;
    assert_eq!(
        read(&f, &browser, "channels", "ErrorResponse").await.0,
        StatusCode::NOT_FOUND
    );
    f.harness.stop().await;
}

#[actix_web::test]
async fn syncing_network_mismatch_and_offline_observations_fail_closed() {
    for backend in [Backend::LndGrpc, Backend::LndRest, Backend::ClnRest] {
        let f = Journey::new(backend, false).await;
        let browser = login(&f.state, None).await;
        f.harness.scenario.lock().unwrap().set_syncing(true);
        let (_, info) = read(&f, &browser, "info", "NodeInfo").await;
        assert_eq!(
            info["node"]["capabilities"]["pay_invoice"]["reason"],
            "syncing"
        );
        let future = f.state.registry.get("synthetic").unwrap().summary(
            Utc::now() + chrono::Duration::seconds(2),
            lightning_client::money::Decimal::ZERO,
        );
        assert!(future.status.stale);
        assert_eq!(
            future.capabilities.pay_invoice.reason,
            Some(CapabilityReason::NodeOffline)
        );
        f.harness
            .scenario
            .lock()
            .unwrap()
            .set_identity(PEER, "mainnet");
        expire(&f).await;
        let (_, info) = read(&f, &browser, "info", "NodeInfo").await;
        assert_eq!(info["stale"], true);
        assert_eq!(info["node"]["network"], "regtest");
        assert_eq!(info["node"]["status"]["error_code"], "network_mismatch");
        assert_eq!(
            info["node"]["capabilities"]["pay_invoice"]["reason"],
            "unverified"
        );
        f.harness
            .scenario
            .lock()
            .unwrap()
            .set_identity(PEER, "regtest");
        f.harness.scenario.lock().unwrap().set_syncing(false);
        f.harness.scenario.lock().unwrap().fault(
            if backend == Backend::ClnRest {
                "getinfo"
            } else {
                "GetInfo"
            },
            Fault::TimeoutBeforeEffect,
        );
        expire(&f).await;
        let (_, status) = read(&f, &browser, "status", "NodeStatus").await;
        assert_eq!(status["status"], "offline");
        assert_eq!(status["stale"], true);
        assert_eq!(
            read(&f, &browser, "peers", "ErrorResponse").await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        f.harness.stop().await;
    }
}

#[actix_web::test]
async fn initial_offline_is_503_and_collection_snapshots_keep_their_own_expiry_and_bounds() {
    let mut f = Journey::new(Backend::ClnRest, false).await;
    f.settings.api.limits.pagination.snapshot_max_items = 1;
    f.restart().await;
    let browser = login(&f.state, None).await;
    f.harness
        .scenario
        .lock()
        .unwrap()
        .fault("getinfo", Fault::TimeoutBeforeEffect);
    assert_eq!(
        read(&f, &browser, "channels", "ErrorResponse").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    expire(&f).await;
    let (status, bounded) = read(&f, &browser, "channels?limit=1", "ChannelsPage").await;
    assert_eq!(status, StatusCode::OK, "{bounded}");
    assert_eq!(bounded["items"].as_array().unwrap().len(), 1);
    assert_eq!(bounded["truncated"], true);
    assert!(bounded["next_cursor"].is_null());
    let calls = f.harness.scenario.lock().unwrap().calls("listpeerchannels");
    assert_eq!(
        read(&f, &browser, "channels?limit=1", "ChannelsPage")
            .await
            .1,
        bounded
    );
    assert_eq!(
        f.harness.scenario.lock().unwrap().calls("listpeerchannels"),
        calls
    );
    f.harness.stop().await;
}

#[actix_web::test]
async fn observation_cache_bytes_are_bounded_without_disabling_a_healthy_node() {
    let mut f = Journey::new(Backend::LndRest, false).await;
    f.settings.api.limits.snapshot_cache_bytes = 1;
    f.restart().await;
    f.harness.scenario.lock().unwrap().seed_collections();
    let browser = login(&f.state, None).await;
    assert_eq!(
        read(&f, &browser, "peers", "ErrorResponse").await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let (_, info) = read(&f, &browser, "info", "NodeInfo").await;
    assert_eq!(info["node"]["capabilities"]["pay_invoice"]["enabled"], true);
    assert_eq!(*f.state.observation_bytes.lock().unwrap(), 0);
    f.harness.stop().await;
}

#[actix_web::test]
async fn expired_collection_cursor_is_410_without_a_daemon_read() {
    let mut f = Journey::new(Backend::ClnRest, false).await;
    f.settings.api.limits.pagination.snapshot_ttl_seconds = 1;
    f.restart().await;
    let browser = login(&f.state, None).await;
    let (_, first) = read(&f, &browser, "channels?limit=1", "ChannelsPage").await;
    let cursor = first["next_cursor"].as_str().unwrap();
    let calls = f.harness.scenario.lock().unwrap().calls("getinfo");
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        read(
            &f,
            &browser,
            &format!("channels?limit=1&cursor={cursor}"),
            "ErrorResponse"
        )
        .await
        .0,
        StatusCode::GONE
    );
    assert_eq!(f.harness.scenario.lock().unwrap().calls("getinfo"), calls);
    f.harness.stop().await;
}

#[actix_web::test]
async fn ui_overview_parallel_reads_share_warmup_instead_of_rejecting_each_other() {
    for backend in [Backend::LndGrpc, Backend::LndRest, Backend::ClnRest] {
        let f = Journey::new(backend, false).await;
        f.harness.scenario.lock().unwrap().seed_collections();
        f.harness.scenario.lock().unwrap().expect_mutations(&[]);
        let browser = login(&f.state, None).await;
        let (info, balances, payments) = tokio::join!(
            read(&f, &browser, "info", "NodeInfo"),
            read(&f, &browser, "balances", "Balances"),
            read(&f, &browser, "payments", "PaymentsPage")
        );
        for (status, value) in [info, balances, payments] {
            assert_eq!(status, StatusCode::OK, "{backend:?}: {value}");
        }
        f.harness
            .scenario
            .lock()
            .unwrap()
            .assert_no_unexpected_calls();
        f.harness.stop().await;
    }
}
