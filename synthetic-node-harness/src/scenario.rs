use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{Secp256k1, SecretKey},
};
use chrono::{DateTime, Utc};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};

pub const PEER: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
pub const TXID: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
pub const POINT: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:1";
pub(crate) const RUNE: &str = "SYNTHETIC_DEV_RUNE";
pub(crate) const MACAROON: &[u8] = b"SYNTHETIC_DEV_MACAROON";

#[derive(Clone, Debug)]
pub enum Fault {
    Reject,
    PermissionDenied,
    TimeoutBeforeEffect,
    TimeoutAfterEffect,
    Malformed,
    Oversized,
    StreamError,
}

/// All state belongs to one isolated node. No callbacks or adapter injection.
pub struct Scenario {
    pub(crate) lnd: Value,
    pub(crate) cln: Value,
    pub(crate) now: DateTime<Utc>,
    seed: u8,
    faults: BTreeMap<String, VecDeque<Fault>>,
    calls: BTreeMap<String, usize>,
    effects: BTreeMap<String, usize>,
    arguments: BTreeMap<String, Vec<Value>>,
    expected_mutations: Option<VecDeque<String>>,
    pub(crate) unexpected: Vec<String>,
    invoice: Option<Value>,
    invoice_preimage: Option<[u8; 32]>,
    payment: Option<Value>,
    open_pending: bool,
    closed: bool,
}

impl Scenario {
    /// Populate read-only journeys without invoking a mutation as a probe.
    pub fn seed_collections(&mut self) {
        let lnd: Value = serde_json::from_str(include_str!(
            "../../api-server/tests/fixtures/lnd-v0.18.5-beta/synthetic.json"
        ))
        .expect("tagged LND fixture");
        let cln: Value = serde_json::from_str(include_str!(
            "../../api-server/tests/fixtures/cln-v25.02/synthetic.json"
        ))
        .expect("tagged CLN fixture");
        self.invoice = Some(lnd["invoices"]["invoices"][0].clone());
        let bolt11 = self.payment_invoice();
        let hash = sha256::Hash::hash(&[self.seed; 32]);
        if let Some(invoice) = &mut self.invoice {
            invoice["r_hash"] = serde_json::json!(STANDARD.encode(hash.to_byte_array()));
            invoice["payment_request"] = serde_json::json!(bolt11);
        }
        self.payment = Some(lnd["payments"]["payments"][0].clone());
        self.lnd["transactions"] = lnd["transactions"].clone();
        self.cln["listpays"] = cln["listpays"].clone();
        self.lnd["info"]["synced_to_graph"] = serde_json::json!(true);
        let mut invoice = cln["listinvoices"]["invoices"][0].clone();
        invoice["bolt11"] = serde_json::json!(bolt11);
        invoice["payment_hash"] = serde_json::json!(hash.to_string());
        // The scenario serves one daemon family; its invoice storage follows that family.
        self.cln["listinvoices"] = serde_json::json!({"invoices":[invoice]});
    }
    pub fn set_identity(&mut self, pubkey: &str, network: &str) {
        self.lnd["info"]["identity_pubkey"] = serde_json::json!(pubkey);
        self.lnd["info"]["chains"][0]["network"] = serde_json::json!(network);
        self.cln["getinfo"]["id"] = serde_json::json!(pubkey);
        self.cln["getinfo"]["network"] = serde_json::json!(network);
    }
    pub fn set_syncing(&mut self, syncing: bool) {
        self.lnd["info"]["synced_to_chain"] = serde_json::json!(!syncing);
        self.lnd["info"]["synced_to_graph"] = serde_json::json!(!syncing);
        if syncing {
            self.cln["getinfo"]["warning_bitcoind_sync"] = serde_json::json!("Synthetic syncing");
        } else if let Some(info) = self.cln["getinfo"].as_object_mut() {
            info.remove("warning_bitcoind_sync");
        }
    }
    pub fn new(seed: u8, now: DateTime<Utc>) -> Self {
        let mut lnd: Value = serde_json::from_str(include_str!(
            "../../api-server/tests/fixtures/lnd-v0.18.5-beta/synthetic.json"
        ))
        .expect("tagged LND fixture");
        let mut cln: Value = serde_json::from_str(include_str!(
            "../../api-server/tests/fixtures/cln-v25.02/synthetic.json"
        ))
        .expect("tagged CLN fixture");
        lnd["invoices"]["invoices"] = json!([]);
        lnd["payments"]["payments"] = json!([]);
        lnd["transactions"]["transactions"] = json!([]);
        cln["listinvoices"]["invoices"] = json!([]);
        cln["listpays"]["pays"] = json!([]);
        Self {
            lnd,
            cln,
            now,
            seed,
            faults: BTreeMap::new(),
            calls: BTreeMap::new(),
            effects: BTreeMap::new(),
            arguments: BTreeMap::new(),
            expected_mutations: None,
            unexpected: vec![],
            invoice: None,
            invoice_preimage: None,
            payment: None,
            open_pending: false,
            closed: false,
        }
    }
    /// Method names are the documented CLN names or LND protobuf method names.
    pub fn fault(&mut self, method: &str, fault: Fault) {
        self.faults
            .entry(method.into())
            .or_default()
            .push_back(fault);
    }
    pub fn calls(&self, method: &str) -> usize {
        self.calls.get(method).copied().unwrap_or(0)
    }
    pub fn effects(&self, method: &str) -> usize {
        self.effects.get(method).copied().unwrap_or(0)
    }
    pub fn mutation_arguments(&self, method: &str) -> &[Value] {
        self.arguments.get(method).map(Vec::as_slice).unwrap_or(&[])
    }
    /// Tests opt into a finite mutation script; the browser sandbox stays free-form.
    pub fn expect_mutations(&mut self, methods: &[&str]) {
        self.expected_mutations = Some(methods.iter().map(|m| (*m).to_owned()).collect());
    }
    pub fn assert_no_unexpected_calls(&self) {
        assert!(
            self.unexpected.is_empty(),
            "unexpected wire calls: {:?}",
            self.unexpected
        );
    }
    pub(crate) fn begin(&mut self, method: &str) -> Option<Fault> {
        *self.calls.entry(method.into()).or_default() += 1;
        self.faults.get_mut(method).and_then(VecDeque::pop_front)
    }
    pub fn address(&self) -> String {
        bitcoin::Address::p2wpkh(
            &bitcoin::CompressedPublicKey(PEER.parse().expect("fixture pubkey")),
            bitcoin::Network::Regtest,
        )
        .to_string()
    }
    pub fn payment_invoice(&self) -> String {
        self.bolt11(1001, "Synthetic payment", 3600, [self.seed; 32])
    }
    fn bolt11(&self, amount: u64, description: &str, expiry: u64, preimage: [u8; 32]) -> String {
        InvoiceBuilder::new(Currency::Regtest)
            .description(description.into())
            .payment_hash(sha256::Hash::hash(&preimage))
            .payment_secret(PaymentSecret([44; 32]))
            .duration_since_epoch(std::time::Duration::from_secs(
                self.now.timestamp().max(0) as u64
            ))
            .expiry_time(std::time::Duration::from_secs(expiry))
            .min_final_cltv_expiry_delta(18)
            .amount_milli_satoshis(amount)
            .build_signed(|h| {
                Secp256k1::new().sign_ecdsa_recoverable(
                    h,
                    &SecretKey::from_slice(&[42; 32]).expect("fixture signing key"),
                )
            })
            .expect("synthetic invoice")
            .to_string()
    }
    pub(crate) fn reply(&mut self, method: &str, p: &Value) -> Option<Value> {
        let mutation = matches!(
            method,
            "AddInvoice"
                | "SendPaymentV2"
                | "ConnectPeer"
                | "DisconnectPeer"
                | "OpenChannelSync"
                | "CloseChannel"
                | "NewAddress"
                | "SendCoins"
                | "invoice"
                | "xpay"
                | "connect"
                | "disconnect"
                | "fundchannel"
                | "close"
                | "newaddr"
                | "withdraw"
        );
        if mutation {
            if let Some(expected) = &mut self.expected_mutations {
                if expected.pop_front().as_deref() != Some(method) {
                    self.unexpected
                        .push(format!("unexpected or exhausted mutation: {method}"));
                    return None;
                }
            }
            let arguments = self.arguments.entry(method.into()).or_default();
            if arguments.len() >= 128 {
                self.unexpected
                    .push("scenario mutation capacity exhausted".into());
                return None;
            }
            arguments.push(p.clone());
            *self.effects.entry(method.into()).or_default() += 1;
        }
        let value = match method {
            "GetInfo" => self.lnd["info"].clone(),
            "getinfo" => self.cln["getinfo"].clone(),
            "WalletBalance" => self.lnd["wallet"].clone(),
            "ChannelBalance" => self.lnd["channel_balance"].clone(),
            "listfunds" => self.cln["listfunds"].clone(),
            "CheckMacaroonPermissions" | "checkrune" => json!({"valid":true}),
            "EstimateFee" => json!({"sat_per_kw":"500","min_relay_fee_sat_per_kw":"250"}),
            "feerates" => self.cln["feerates"].clone(),
            "ListInvoices" => json!({"invoices":self.invoice.iter().cloned().collect::<Vec<_>>()}),
            "LookupInvoice" => {
                let row = self.invoice.as_ref()?;
                if p["r_hash_str"] != hex::encode(STANDARD.decode(row["r_hash"].as_str()?).ok()?) {
                    return None;
                }
                row.clone()
            }
            "listinvoices" => {
                if self.cln["listinvoices"]["invoices"]
                    .as_array()
                    .is_some_and(|rows| !rows.is_empty())
                    && p.get("label").is_none()
                {
                    self.cln["listinvoices"].clone()
                } else {
                    json!({"invoices":self.invoice.iter().filter(|r| p.get("label").is_none_or(|v|v == &r["label"])).cloned().collect::<Vec<_>>()})
                }
            }
            "ListPayments" => json!({"payments":self.payment.iter().cloned().collect::<Vec<_>>()}),
            "listpays" => self.cln["listpays"].clone(),
            "TrackPaymentV2" => {
                let pay = self.payment.as_mut()?;
                if p["payment_hash_hex"] != pay["payment_hash"] {
                    return None;
                }
                pay["status"] = json!("SUCCEEDED");
                pay.clone()
            }
            "ListPeers" => self.lnd["peers"].clone(),
            "listpeers" => self.cln["listpeers"].clone(),
            "ListChannels" => {
                if self.open_pending || self.closed {
                    json!({"channels":[]})
                } else {
                    self.lnd["channels"].clone()
                }
            }
            "PendingChannels" => {
                let pending = self.lnd["pending"].clone();
                self.open_pending = false;
                self.lnd["pending"]["pending_open_channels"] = json!([]);
                pending
            }
            "ClosedChannels" => self.lnd["closed"].clone(),
            "listpeerchannels" => {
                let mut v = self.cln["listpeerchannels"].clone();
                if self.open_pending {
                    self.open_pending = false;
                    v["channels"][0]["state"] = json!("CHANNELD_AWAITING_LOCKIN");
                }
                if self.closed {
                    v["channels"] = json!([]);
                }
                v
            }
            "listclosedchannels" => self.cln["listclosedchannels"].clone(),
            "GetTransactions" => self.lnd["transactions"].clone(),
            "listtransactions" => self.cln["listtransactions"].clone(),
            "AddInvoice" | "invoice" => {
                let lnd = method == "AddInvoice";
                let preimage: [u8; 32] = if lnd {
                    STANDARD
                        .decode(p["r_preimage"].as_str()?)
                        .ok()?
                        .try_into()
                        .ok()?
                } else {
                    [self.seed.wrapping_add(1); 32]
                };
                let hash = sha256::Hash::hash(&preimage).to_string();
                let amount = number(p, if lnd { "value_msat" } else { "amount_msat" })?;
                let expiry = number(p, "expiry")?;
                let description = p[if lnd { "memo" } else { "description" }].as_str()?;
                let bolt11 = self.bolt11(amount, description, expiry, preimage);
                let row = if lnd {
                    json!({"r_hash":STANDARD.encode(hex::decode(&hash).ok()?),"value_msat":amount.to_string(),"amt_paid_msat":"0","state":"OPEN","creation_date":self.now.timestamp().to_string(),"settle_date":"0","expiry":expiry.to_string(),"payment_request":bolt11,"memo":description})
                } else {
                    json!({"payment_hash":hash,"bolt11":bolt11,"label":p["label"],"amount_msat":amount,"description":description,"status":"unpaid","expires_at":self.now.timestamp()+expiry as i64,"created_index":1})
                };
                self.invoice = Some(row.clone());
                self.invoice_preimage = Some(preimage);
                if lnd {
                    json!({"r_hash":row["r_hash"],"payment_request":bolt11})
                } else {
                    row
                }
            }
            "SendPaymentV2" | "xpay" => {
                let invoice: lightning_invoice::Bolt11Invoice = p[if method == "xpay" {
                    "invstring"
                } else {
                    "payment_request"
                }]
                .as_str()?
                .parse()
                .ok()?;
                let hash = invoice.payment_hash().to_string();
                let amount = invoice.amount_milli_satoshis()?;
                self.payment = Some(
                    json!({"payment_hash":hash,"value_msat":amount.to_string(),"fee_msat":"0","creation_time_ns":self.now.timestamp_nanos_opt()?.to_string(),"payment_index":"7","status":"IN_FLIGHT","failure_reason":"FAILURE_REASON_NONE"}),
                );
                if method == "xpay" {
                    let preimage = self
                        .invoice_preimage
                        .into_iter()
                        .chain(std::iter::once([self.seed; 32]))
                        .find(|preimage| sha256::Hash::hash(preimage) == *invoice.payment_hash())?;
                    let preimage = hex::encode(preimage);
                    self.cln["listpays"] = json!({"pays":[{"payment_hash":hash,"status":"failed","created_at":self.now.timestamp()-1,"created_index":1,"amount_sent_msat":99000},{"payment_hash":hash,"status":"complete","created_at":self.now.timestamp(),"created_index":7,"completed_at":self.now.timestamp(),"amount_msat":amount,"amount_sent_msat":amount,"preimage":preimage}]});
                    json!({"payment_preimage":preimage,"failed_parts":0,"successful_parts":1,"amount_msat":amount,"amount_sent_msat":amount})
                } else {
                    self.payment.clone()?
                }
            }
            "ConnectPeer" | "connect" => {
                self.lnd["peers"] =
                    json!({"peers":[{"pub_key":PEER,"address":"192.0.2.1:9735","inbound":false}]});
                self.cln["listpeers"]["peers"][0]["connected"] = json!(true);
                if method == "connect" {
                    self.cln["connect"].clone()
                } else {
                    json!({})
                }
            }
            "DisconnectPeer" | "disconnect" => {
                self.lnd["peers"] = json!({"peers":[]});
                self.cln["listpeers"]["peers"][0]["connected"] = json!(false);
                json!({})
            }
            "OpenChannelSync" | "fundchannel" => {
                self.open_pending = true;
                let amount = number(
                    p,
                    if method == "fundchannel" {
                        "amount"
                    } else {
                        "local_funding_amount"
                    },
                )?;
                self.lnd["channels"]["channels"][0]["capacity"] = json!(amount.to_string());
                self.lnd["channels"]["channels"][0]["local_balance"] = json!(amount.to_string());
                self.lnd["channels"]["channels"][0]["remote_balance"] = json!("0");
                self.cln["listpeerchannels"]["channels"][0]["total_msat"] =
                    json!(amount.checked_mul(1000)?);
                self.cln["listpeerchannels"]["channels"][0]["to_us_msat"] =
                    json!(amount.checked_mul(1000)?);
                self.lnd["pending"]["pending_open_channels"] = json!([{"channel":{"remote_node_pub":PEER,"channel_point":POINT,"capacity":amount.to_string(),"local_balance":amount.to_string(),"remote_balance":"0","private":true}}]);
                if method == "fundchannel" {
                    self.cln["fundchannel"].clone()
                } else {
                    json!({"funding_txid_str":TXID,"output_index":1})
                }
            }
            "CloseChannel" | "close" => {
                self.closed = true;
                self.lnd["closed"] = json!({"channels":[{"remote_pubkey":PEER,"channel_point":POINT,"chan_id":"9007199254740993","capacity":"3","close_type":"COOPERATIVE_CLOSE","closing_tx_hash":TXID}]});
                let mut row = self.cln["listclosedchannels"]["closedchannels"][0].clone();
                row["channel_id"] =
                    self.cln["listpeerchannels"]["channels"][0]["channel_id"].clone();
                row["funding_txid"] = json!(TXID);
                row["funding_outnum"] = json!(1);
                row["last_commitment_txid"] = json!(TXID);
                self.cln["listclosedchannels"] = json!({"closedchannels":[row]});
                if method == "close" {
                    json!({"type":"mutual","txids":[TXID],"txs":["SYNTHETIC_RAW_TX"]})
                } else {
                    json!({"chan_close":{"closing_txid":STANDARD.encode(hex::decode(TXID).ok()?.into_iter().rev().collect::<Vec<_>>()),"success":true}})
                }
            }
            "NewAddress" => json!({"address":self.address()}),
            "newaddr" => json!({"bech32":self.address()}),
            "SendCoins" | "withdraw" => {
                let amount = number(
                    p,
                    if method == "withdraw" {
                        "satoshi"
                    } else {
                        "amount"
                    },
                )?;
                self.lnd["transactions"] = json!({"transactions":[{"tx_hash":TXID,"amount":format!("-{amount}"),"total_fees":"0","num_confirmations":0,"block_height":0,"time_stamp":self.now.timestamp().to_string(),"output_details":[{"output_index":0,"address":p["addr"],"amount":amount.to_string(),"is_our_address":false}]}]});
                json!({"txid":TXID})
            }
            _ => {
                self.unexpected.push(method.into());
                return None;
            }
        };
        Some(value)
    }
}
pub(crate) fn number(p: &Value, key: &str) -> Option<u64> {
    p[key].as_u64().or_else(|| p[key].as_str()?.parse().ok())
}
