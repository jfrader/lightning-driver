use super::*;
use chrono::{DateTime, Utc};
use lightning_client::model::Backend;
use serde_json::json;

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000, 0).unwrap()
}

#[test]
fn cln_payment_returns_the_preimage_for_the_invoice_it_issued() {
    use bitcoin::hashes::{sha256, Hash};
    for seed in [45, u8::MAX] {
        let mut scenario = Scenario::new(seed, now());
        let issued = scenario.reply("invoice", &json!({"amount_msat":1001,"description":"Synthetic invoice","expiry":3600,"label":"ld-issued"})).unwrap();
        let paid = scenario
            .reply("xpay", &json!({"invstring":issued["bolt11"],"maxfee":0}))
            .unwrap();
        let preimage = hex::decode(paid["payment_preimage"].as_str().unwrap()).unwrap();
        assert_eq!(
            issued["payment_hash"],
            sha256::Hash::hash(&preimage).to_string()
        );
        let pays = scenario.reply("listpays", &json!({})).unwrap();
        assert_eq!(pays["pays"][1]["preimage"], paid["payment_preimage"]);
        assert_eq!(pays["pays"][1]["payment_hash"], issued["payment_hash"]);
        assert_ne!(paid["payment_preimage"], hex::encode([seed; 32]));
    }
}

#[test]
fn seeded_scenarios_preserve_exact_amounts_and_absence_not_zero() {
    let mut scenario = Scenario::new(45, now());
    assert_eq!(
        scenario.payment_invoice(),
        Scenario::new(45, now()).payment_invoice()
    );
    assert_ne!(
        scenario.payment_invoice(),
        Scenario::new(46, now()).payment_invoice()
    );
    assert_eq!(
        scenario.reply("WalletBalance", &json!({})).unwrap()["confirmed_balance"],
        "9007199254740993"
    );
    assert_eq!(
        scenario.reply("WalletBalance", &json!({})).unwrap()["unconfirmed_balance"],
        "0"
    );
    scenario
        .reply(
            "SendCoins",
            &json!({"amount":"10000","addr":scenario.address()}),
        )
        .unwrap();
    assert_eq!(
        scenario.reply("GetTransactions", &json!({})).unwrap()["transactions"][0]["total_fees"],
        "0"
    );
    let cln = scenario.reply("listtransactions", &json!({})).unwrap();
    assert!(cln["transactions"][0].get("total_fees").is_none());
    assert!(cln["transactions"][0].get("amount").is_none());
    let invoice = scenario.payment_invoice();
    scenario
        .reply("xpay", &json!({"invstring":invoice,"maxfee":0}))
        .unwrap();
    let groups = scenario.reply("listpays", &json!({})).unwrap();
    assert_eq!(groups["pays"][0]["status"], "failed");
    assert!(groups["pays"][0].get("amount_msat").is_none());
    assert_eq!(groups["pays"][1]["status"], "complete");
    assert_eq!(groups["pays"][1]["amount_msat"], 1001);
    assert_eq!(groups["pays"][1]["amount_sent_msat"], 1001);
}

#[test]
fn exhausted_mutation_scripts_do_not_apply_a_second_effect() {
    let mut scenario = Scenario::new(45, now());
    scenario.expect_mutations(&["NewAddress"]);
    assert!(scenario.reply("NewAddress", &json!({})).is_some());
    assert!(scenario.reply("NewAddress", &json!({})).is_none());
    assert_eq!(scenario.effects("NewAddress"), 1);
    assert_eq!(scenario.unexpected.len(), 1);
}

#[tokio::test]
async fn only_loopback_can_be_bound() {
    for bind in ["0.0.0.0:0", "[::]:0", "192.0.2.1:0"] {
        let result = Harness::start(Backend::ClnRest, bind.parse().unwrap(), 45, now()).await;
        assert!(matches!(result,Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied));
    }
}

#[tokio::test]
async fn disposable_tls_and_wire_authentication_are_required() {
    for backend in [Backend::ClnRest, Backend::LndRest] {
        let harness = Harness::start(backend, "127.0.0.1:0".parse().unwrap(), 45, Utc::now())
            .await
            .unwrap();
        let directory = harness.directory().to_owned();
        let node = harness.node("synthetic");
        let cert =
            reqwest::Certificate::from_pem(&std::fs::read(node.certificate_file.unwrap()).unwrap())
                .unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert)
            .build()
            .unwrap();
        let url = node.endpoint.join("v1/getinfo").unwrap();
        let request = if backend == Backend::ClnRest {
            client.post(url.clone())
        } else {
            client.get(url.clone())
        };
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 403);
        assert_eq!(
            harness
                .scenario
                .lock()
                .unwrap()
                .calls(if backend == Backend::ClnRest {
                    "getinfo"
                } else {
                    "GetInfo"
                }),
            0
        );
        let request = if backend == Backend::ClnRest {
            client.post(url).header("Rune", crate::scenario::RUNE)
        } else {
            client.get(url).header(
                "Grpc-Metadata-macaroon",
                hex::encode(crate::scenario::MACAROON),
            )
        };
        assert!(request
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
        harness.stop().await;
        assert!(!directory.exists());
    }
}
