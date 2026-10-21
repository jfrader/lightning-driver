use base64::{engine::general_purpose::STANDARD, Engine};
use lnd_grpc_rust::{lnrpc as ln, prost::Message, routerrpc as router, walletrpc as wallet};
use serde_json::{json, Value};

pub(crate) fn decode(method: &str, bytes: &[u8]) -> Option<Value> {
    if bytes.len() < 5
        || bytes[0] != 0
        || u32::from_be_bytes(bytes[1..5].try_into().ok()?) as usize != bytes.len() - 5
    {
        return None;
    }
    let bytes = &bytes[5..];
    Some(match method {
        "AddInvoice" => {
            let p = ln::Invoice::decode(bytes).ok()?;
            json!({"r_preimage":STANDARD.encode(p.r_preimage),"value_msat":p.value_msat.to_string(),"memo":p.memo,"expiry":p.expiry.to_string()})
        }
        "SendPaymentV2" => {
            let p = router::SendPaymentRequest::decode(bytes).ok()?;
            json!({"payment_request":p.payment_request,"fee_limit_msat":p.fee_limit_msat.to_string()})
        }
        "TrackPaymentV2" => {
            let p = router::TrackPaymentRequest::decode(bytes).ok()?;
            json!({"payment_hash_hex":hex::encode(p.payment_hash)})
        }
        "LookupInvoice" => {
            let p = ln::PaymentHash::decode(bytes).ok()?;
            json!({"r_hash_str":hex::encode(p.r_hash)})
        }
        "ConnectPeer" => {
            let p = ln::ConnectPeerRequest::decode(bytes).ok()?.addr?;
            json!({"addr":{"pubkey":p.pubkey,"host":p.host}})
        }
        "DisconnectPeer" => {
            let p = ln::DisconnectPeerRequest::decode(bytes).ok()?;
            json!({"pub_key":p.pub_key})
        }
        "OpenChannelSync" => {
            let p = ln::OpenChannelRequest::decode(bytes).ok()?;
            json!({"node_pubkey":STANDARD.encode(p.node_pubkey),"local_funding_amount":p.local_funding_amount.to_string(),"sat_per_vbyte":p.sat_per_vbyte.to_string(),"private":p.private})
        }
        "CloseChannel" => {
            let p = ln::CloseChannelRequest::decode(bytes).ok()?;
            if p.force {
                return None;
            }
            json!({"force":false,"sat_per_vbyte":p.sat_per_vbyte.to_string()})
        }
        "SendCoins" => {
            let p = ln::SendCoinsRequest::decode(bytes).ok()?;
            if p.send_all {
                return None;
            }
            json!({"addr":p.addr,"amount":p.amount.to_string(),"sat_per_vbyte":p.sat_per_vbyte.to_string()})
        }
        _ => json!({}),
    })
}
fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v[k].as_str()
}
fn i(v: &Value, k: &str) -> Option<i64> {
    s(v, k)?.parse().ok()
}
fn u(v: &Value, k: &str) -> Option<u64> {
    s(v, k)?.parse().ok()
}
fn b(v: &Value, k: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s(v, k)?).ok()
}
fn frame(m: impl Message) -> Vec<u8> {
    let bytes = m.encode_to_vec();
    let mut out = vec![0];
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend(bytes);
    out
}
fn rows<'a>(v: &'a Value, key: &str) -> Option<&'a Vec<Value>> {
    v[key].as_array()
}
fn invoice(v: &Value) -> Option<ln::Invoice> {
    Some(ln::Invoice {
        r_hash: b(v, "r_hash")?,
        value_msat: i(v, "value_msat")?,
        amt_paid_msat: i(v, "amt_paid_msat")?,
        state: match s(v, "state")? {
            "OPEN" => 0,
            "SETTLED" => 1,
            "CANCELED" => 2,
            "ACCEPTED" => 3,
            _ => return None,
        },
        settle_date: v
            .get("settle_date")
            .and_then(Value::as_str)
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        creation_date: i(v, "creation_date")?,
        expiry: i(v, "expiry")?,
        payment_request: s(v, "payment_request")?.into(),
        memo: s(v, "memo")?.into(),
        ..Default::default()
    })
}
fn payment(v: &Value) -> Option<ln::Payment> {
    Some(ln::Payment {
        payment_hash: s(v, "payment_hash")?.into(),
        value_msat: i(v, "value_msat")?,
        fee_msat: i(v, "fee_msat")?,
        creation_time_ns: i(v, "creation_time_ns")?,
        payment_index: u(v, "payment_index")?,
        status: match s(v, "status")? {
            "UNKNOWN" => 0,
            "IN_FLIGHT" => 1,
            "SUCCEEDED" => 2,
            "FAILED" => 3,
            "INITIATED" => 4,
            _ => return None,
        },
        ..Default::default()
    })
}

pub(crate) fn encode(method: &str, v: &Value) -> Option<Vec<u8>> {
    Some(match method {
        "GetInfo" => frame(ln::GetInfoResponse {
            identity_pubkey: s(v, "identity_pubkey")?.into(),
            alias: s(v, "alias")?.into(),
            version: s(v, "version")?.into(),
            chains: vec![ln::Chain {
                network: s(&v["chains"][0], "network")?.into(),
                ..Default::default()
            }],
            synced_to_chain: v["synced_to_chain"].as_bool()?,
            synced_to_graph: v["synced_to_graph"].as_bool()?,
            block_height: v["block_height"].as_u64()?.try_into().ok()?,
            ..Default::default()
        }),
        "WalletBalance" => frame(ln::WalletBalanceResponse {
            confirmed_balance: i(v, "confirmed_balance")?,
            unconfirmed_balance: i(v, "unconfirmed_balance")?,
            locked_balance: i(v, "locked_balance")?,
            reserved_balance_anchor_chan: i(v, "reserved_balance_anchor_chan")?,
            ..Default::default()
        }),
        "ChannelBalance" => frame(ln::ChannelBalanceResponse {
            local_balance: Some(ln::Amount { sat: 1, msat: 1001 }),
            remote_balance: Some(ln::Amount { sat: 2, msat: 2000 }),
            ..Default::default()
        }),
        "CheckMacaroonPermissions" => frame(ln::CheckMacPermResponse { valid: true }),
        "EstimateFee" => frame(wallet::EstimateFeeResponse {
            sat_per_kw: 500,
            min_relay_fee_sat_per_kw: 250,
        }),
        "ListInvoices" => frame(ln::ListInvoiceResponse {
            invoices: rows(v, "invoices")?
                .iter()
                .map(invoice)
                .collect::<Option<Vec<_>>>()?,
            ..Default::default()
        }),
        "LookupInvoice" => frame(invoice(v)?),
        "ListPayments" => frame(ln::ListPaymentsResponse {
            payments: rows(v, "payments")?
                .iter()
                .map(payment)
                .collect::<Option<Vec<_>>>()?,
            ..Default::default()
        }),
        "SendPaymentV2" | "TrackPaymentV2" => frame(payment(v)?),
        "ListPeers" => frame(ln::ListPeersResponse {
            peers: rows(v, "peers")?
                .iter()
                .map(|r| {
                    Some(ln::Peer {
                        pub_key: s(r, "pub_key")?.into(),
                        address: s(r, "address")?.into(),
                        inbound: r["inbound"].as_bool()?,
                        ..Default::default()
                    })
                })
                .collect::<Option<Vec<_>>>()?,
        }),
        "ListChannels" => frame(ln::ListChannelsResponse {
            channels: rows(v, "channels")?
                .iter()
                .map(|r| {
                    Some(ln::Channel {
                        remote_pubkey: s(r, "remote_pubkey")?.into(),
                        channel_point: s(r, "channel_point")?.into(),
                        chan_id: u(r, "chan_id")?,
                        capacity: i(r, "capacity")?,
                        local_balance: i(r, "local_balance")?,
                        remote_balance: i(r, "remote_balance")?,
                        active: r["active"].as_bool()?,
                        private: r["private"].as_bool()?,
                        ..Default::default()
                    })
                })
                .collect::<Option<Vec<_>>>()?,
        }),
        "PendingChannels" => frame(ln::PendingChannelsResponse {
            pending_open_channels: rows(v, "pending_open_channels")?
                .iter()
                .map(|r| {
                    let c = &r["channel"];
                    Some(ln::pending_channels_response::PendingOpenChannel {
                        channel: Some(ln::pending_channels_response::PendingChannel {
                            remote_node_pub: s(c, "remote_node_pub")?.into(),
                            channel_point: s(c, "channel_point")?.into(),
                            capacity: i(c, "capacity")?,
                            local_balance: i(c, "local_balance")?,
                            remote_balance: i(c, "remote_balance")?,
                            private: true,
                            ..Default::default()
                        }),
                        ..Default::default()
                    })
                })
                .collect::<Option<Vec<_>>>()?,
            ..Default::default()
        }),
        "ClosedChannels" => frame(ln::ClosedChannelsResponse {
            channels: rows(v, "channels")?
                .iter()
                .map(|r| {
                    Some(ln::ChannelCloseSummary {
                        remote_pubkey: s(r, "remote_pubkey")?.into(),
                        channel_point: s(r, "channel_point")?.into(),
                        chan_id: u(r, "chan_id")?,
                        capacity: i(r, "capacity")?,
                        closing_tx_hash: s(r, "closing_tx_hash")?.into(),
                        close_type: 0,
                        ..Default::default()
                    })
                })
                .collect::<Option<Vec<_>>>()?,
        }),
        "GetTransactions" => frame(ln::TransactionDetails {
            transactions: rows(v, "transactions")?
                .iter()
                .map(|r| {
                    Some(ln::Transaction {
                        tx_hash: s(r, "tx_hash")?.into(),
                        amount: i(r, "amount")?,
                        total_fees: i(r, "total_fees")?,
                        num_confirmations: r["num_confirmations"].as_i64()? as i32,
                        block_height: 0,
                        time_stamp: i(r, "time_stamp")?,
                        output_details: rows(r, "output_details")?
                            .iter()
                            .map(|o| {
                                Some(ln::OutputDetail {
                                    output_index: o["output_index"].as_i64()?,
                                    address: s(o, "address")?.into(),
                                    amount: i(o, "amount")?,
                                    is_our_address: o["is_our_address"].as_bool()?,
                                    ..Default::default()
                                })
                            })
                            .collect::<Option<Vec<_>>>()?,
                        ..Default::default()
                    })
                })
                .collect::<Option<Vec<_>>>()?,
            ..Default::default()
        }),
        "AddInvoice" => frame(ln::AddInvoiceResponse {
            r_hash: b(v, "r_hash")?,
            payment_request: s(v, "payment_request")?.into(),
            ..Default::default()
        }),
        "ConnectPeer" => frame(ln::ConnectPeerResponse::default()),
        "DisconnectPeer" => frame(ln::DisconnectPeerResponse::default()),
        "OpenChannelSync" => frame(ln::ChannelPoint {
            funding_txid: Some(ln::channel_point::FundingTxid::FundingTxidStr(
                s(v, "funding_txid_str")?.into(),
            )),
            output_index: v["output_index"].as_u64()? as u32,
        }),
        "CloseChannel" => frame(ln::CloseStatusUpdate {
            update: Some(ln::close_status_update::Update::ChanClose(
                ln::ChannelCloseUpdate {
                    closing_txid: b(&v["chan_close"], "closing_txid")?,
                    success: true,
                    ..Default::default()
                },
            )),
        }),
        "NewAddress" => frame(ln::NewAddressResponse {
            address: s(v, "address")?.into(),
        }),
        "SendCoins" => frame(ln::SendCoinsResponse {
            txid: s(v, "txid")?.into(),
        }),
        _ => return None,
    })
}
