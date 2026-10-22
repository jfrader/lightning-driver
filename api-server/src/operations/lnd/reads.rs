use super::*;
use bitcoin::hashes::Hash;
use lightning_client::money::Sat;
use std::collections::BTreeMap;

pub(super) fn invalid() -> EngineError {
    failure(ErrorCode::UpstreamInvalidResponse)
}
pub(super) fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn enum_name(v: &Value, key: &str) -> Result<String> {
    match v.get(key) {
        Some(Value::String(s)) => Ok(s.chars().take(64).collect()),
        Some(Value::Number(n)) => n.as_i64().map(|n| n.to_string()).ok_or_else(invalid),
        _ => Err(invalid()),
    }
}
fn optional_text(v: &Value, key: &str) -> Result<Option<String>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok((!s.is_empty()).then(|| s.clone())),
        _ => Err(invalid()),
    }
}
pub(super) fn array<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    v.get(key).and_then(Value::as_array).ok_or_else(invalid)
}
pub(super) fn boolean(v: &Value, key: &str) -> Result<Option<bool>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        _ => Err(invalid()),
    }
}
// These are ProtoJSON int64/uint64, not generated-message serde numbers.
pub(super) fn amount(v: &Value, key: &str) -> Result<Option<Decimal>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            if s.is_empty()
                || !s.bytes().all(|b| b.is_ascii_digit())
                || (s.len() > 1 && s.starts_with('0'))
            {
                return Err(invalid());
            }
            Ok(s.parse::<u64>().ok().and_then(|n| Decimal::new(n).ok()))
        }
        _ => Err(invalid()),
    }
}
pub(super) fn small(v: &Value, key: &str) -> Result<Option<Decimal>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| Decimal::new(n).ok())
            .map(Some)
            .ok_or_else(invalid),
        // LND's REST gateway renders 64-bit integers as decimal strings.
        Some(Value::String(s))
            if !s.is_empty()
                && s.bytes().all(|b| b.is_ascii_digit())
                && (s.len() == 1 || !s.starts_with('0')) =>
        {
            Ok(Some(
                Decimal::new(s.parse::<u64>().map_err(|_| invalid())?).map_err(|_| invalid())?,
            ))
        }
        _ => Err(invalid()),
    }
}
pub(super) fn hash(v: &Value, key: &str) -> Result<String> {
    let s = text(v, key)?;
    let h = s
        .parse::<bitcoin::hashes::sha256::Hash>()
        .map_err(|_| invalid())?;
    if h.to_string() != s {
        return Err(invalid());
    }
    Ok(s.into())
}
pub(super) fn pubkey(v: &Value, key: &str) -> Result<String> {
    let s = text(v, key)?;
    if s.parse::<bitcoin::secp256k1::PublicKey>()
        .map_err(|_| invalid())?
        .to_string()
        != s
    {
        return Err(invalid());
    }
    Ok(s.into())
}
pub(super) fn bytes(v: &Value, key: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text(v, key)?)
        .map_err(|_| invalid())
}
pub(super) fn bytes_hash(v: &Value, key: &str) -> Result<String> {
    let b = bytes(v, key)?;
    if b.len() != 32 {
        return Err(invalid());
    }
    Ok(hex::encode(b))
}
pub(super) fn txid_bytes(v: &Value, key: &str) -> Result<String> {
    bitcoin::Txid::from_slice(&bytes(v, key)?)
        .map(|t| t.to_string())
        .map_err(|_| invalid())
}
pub(super) fn channel_point(v: &Value) -> Result<String> {
    let txid = match optional_text(v, "funding_txid_str")? {
        Some(s) => {
            hash(&json!({"hash":s}), "hash")?;
            s
        }
        None => txid_bytes(v, "funding_txid_bytes")?,
    };
    let index = small(v, "output_index")?
        .and_then(|n| u32::try_from(n.get()).ok())
        .ok_or_else(invalid)?;
    Ok(format!("{txid}:{index}"))
}
fn point(v: &Value, key: &str) -> Result<String> {
    let s = text(v, key)?;
    let p = s.parse::<bitcoin::OutPoint>().map_err(|_| invalid())?;
    if p.to_string() != s {
        return Err(invalid());
    }
    Ok(s.into())
}
pub(super) fn time(v: &Value, key: &str, nanos: bool) -> Result<Option<DateTime<Utc>>> {
    Ok(amount(v, key)?
        .filter(|n| *n != Decimal::ZERO)
        .and_then(|n| {
            if nanos {
                DateTime::from_timestamp(
                    (n.get() / 1_000_000_000) as i64,
                    (n.get() % 1_000_000_000) as u32,
                )
            } else {
                DateTime::from_timestamp(n.get() as i64, 0)
            }
        }))
}
pub(super) struct Info {
    pub identity: String,
    pub network: Network,
    pub alias: Option<String>,
    pub version: Option<String>,
    pub synced: Option<bool>,
    pub graph_synced: Option<bool>,
    pub height: Option<Decimal>,
}
pub(super) fn info(v: &Value) -> Result<Info> {
    let chains = array(v, "chains")?;
    let network = if chains.len() == 1 {
        match text(&chains[0], "network")? {
            "bitcoin" | "mainnet" => Network::Mainnet,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            _ => Network::Unknown,
        }
    } else {
        Network::Unknown
    };
    Ok(Info {
        identity: pubkey(v, "identity_pubkey")?,
        network,
        alias: optional_text(v, "alias")?,
        version: optional_text(v, "version")?,
        synced: boolean(v, "synced_to_chain")?,
        graph_synced: boolean(v, "synced_to_graph")?,
        height: small(v, "block_height")?,
    })
}
pub(super) fn balances(
    w: &Value,
    c: &Value,
    node: &str,
    network: Network,
    now: DateTime<Utc>,
) -> Result<Balances> {
    let confirmed = amount(w, "confirmed_balance")?;
    let spendable = confirmed
        .zip(amount(w, "locked_balance")?)
        .zip(amount(w, "reserved_balance_anchor_chan")?)
        .and_then(|((a, b), c)| a.checked_sub(b).ok()?.checked_sub(c).ok());
    Ok(Balances {
        node_id: node.into(),
        network,
        onchain_confirmed_sat: confirmed.map(Sat),
        onchain_unconfirmed_sat: amount(w, "unconfirmed_balance")?.map(Sat),
        onchain_spendable_sat: spendable.map(Sat),
        channel_local_msat: amount(&c["local_balance"], "msat")?.map(Msat),
        channel_remote_msat: amount(&c["remote_balance"], "msat")?.map(Msat),
        channel_spendable_msat: None,
        observed_at: now,
        stale: false,
    })
}
pub(super) fn invoices(v: &Value, max: usize) -> Result<Collection<Invoice>> {
    let rows = array(v, "invoices")?;
    require_budget(rows, max)?;
    let mut items = Vec::new();
    let mut truncated = rows.len() > max;
    let mut seen = std::collections::BTreeSet::new();
    for r in rows {
        let Some(created) = time(r, "creation_date", false)? else {
            truncated = true;
            continue;
        };
        let h = bytes_hash(r, "r_hash")?;
        if !seen.insert(h.clone()) {
            return Err(invalid());
        }
        let backend = enum_name(r, "state")?;
        let state = match backend.as_str() {
            "OPEN" => InvoiceState::Unpaid,
            "SETTLED" => InvoiceState::Paid,
            "CANCELED" => InvoiceState::Canceled,
            "ACCEPTED" => InvoiceState::Accepted,
            _ => InvoiceState::Unknown,
        };
        let expiry = amount(r, "expiry")?.and_then(|n| {
            created.checked_add_signed(chrono::Duration::try_seconds(n.get() as i64)?)
        });
        items.push(Invoice {
            payment_hash: h,
            amount_msat: amount(r, "value_msat")?
                .filter(|n| *n != Decimal::ZERO)
                .map(Msat),
            received_msat: if matches!(state, InvoiceState::Paid | InvoiceState::Accepted) {
                amount(r, "amt_paid_msat")?.map(Msat)
            } else {
                None
            },
            state,
            backend_state: backend.chars().take(64).collect(),
            bolt11: optional_text(r, "payment_request")?,
            description: optional_text(r, "memo")?,
            created_at: created,
            expires_at: expiry,
            paid_at: if state == InvoiceState::Paid {
                time(r, "settle_date", false)?
            } else {
                None
            },
        });
    }
    items.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.payment_hash.cmp(&b.payment_hash))
    });
    items.truncate(max);
    Ok(Collection { items, truncated })
}
pub(super) fn payments(v: &Value, max: usize) -> Result<Collection<Payment>> {
    let rows = array(v, "payments")?;
    require_budget(rows, max)?;
    let mut by_hash: BTreeMap<String, Payment> = BTreeMap::new();
    let mut truncated = rows.len() > max;
    for r in rows {
        let Some(created) = time(r, "creation_time_ns", true)? else {
            truncated = true;
            continue;
        };
        let h = hash(r, "payment_hash")?;
        let backend = enum_name(r, "status")?;
        let state = match backend.as_str() {
            "INITIATED" | "IN_FLIGHT" => PaymentState::Pending,
            "SUCCEEDED" => PaymentState::Succeeded,
            "FAILED" => PaymentState::Failed,
            _ => PaymentState::Unknown,
        };
        let p = Payment {
            payment_hash: h.clone(),
            amount_msat: amount(r, "value_msat")?.map(Msat),
            fee_msat: amount(r, "fee_msat")?.map(Msat),
            destination: None,
            state,
            backend_state: backend.chars().take(64).collect(),
            created_at: created,
            completed_at: None,
        };
        if let Some(old) = by_hash.get_mut(&h) {
            old.created_at = old.created_at.min(created);
            old.amount_msat = None;
            old.fee_msat = None;
            old.state = PaymentState::Unknown;
            old.backend_state = "UNKNOWN".into();
        } else {
            by_hash.insert(h, p);
        }
    }
    let mut items: Vec<_> = by_hash.into_values().collect();
    items.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.payment_hash.cmp(&b.payment_hash))
    });
    items.truncate(max);
    Ok(Collection { items, truncated })
}
pub(super) fn peers(v: &Value, max: usize) -> Result<Collection<Peer>> {
    let rows = array(v, "peers")?;
    let mut items = Vec::new();
    require_budget(rows, max)?;
    for r in rows {
        items.push(Peer {
            pubkey: pubkey(r, "pub_key")?,
            connected: true,
            address: optional_text(r, "address")?,
            inbound: boolean(r, "inbound")?,
        });
    }
    items.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
    if items.windows(2).any(|p| p[0].pubkey == p[1].pubkey) {
        return Err(invalid());
    }
    items.truncate(max);
    Ok(Collection {
        items,
        truncated: rows.len() > max,
    })
}
fn channel(
    r: &Value,
    state: ChannelState,
    backend: &str,
    closed: bool,
    close_type: Option<CloseType>,
) -> Result<Channel> {
    let p = point(r, "channel_point")?;
    Ok(Channel {
        id: p.clone(),
        peer_pubkey: pubkey(
            r,
            if closed {
                "remote_pubkey"
            } else {
                "remote_node_pub"
            },
        )?,
        funding_outpoint: Some(p),
        short_channel_id: optional_text(r, "chan_id")?.filter(|s| s != "0"),
        state,
        backend_state: backend.into(),
        private: boolean(r, "private")?,
        capacity_sat: amount(r, "capacity")?.map(Sat),
        local_msat: amount(r, "local_balance")?
            .and_then(|n| n.checked_mul(1000).ok())
            .map(Msat),
        remote_msat: amount(r, "remote_balance")?
            .and_then(|n| n.checked_mul(1000).ok())
            .map(Msat),
        spendable_msat: None,
        close_type,
    })
}
pub(super) fn closure(v: &Value) -> Result<CloseType> {
    Ok(match enum_name(v, "close_type")?.as_str() {
        "COOPERATIVE_CLOSE" => CloseType::Cooperative,
        "LOCAL_FORCE_CLOSE" | "REMOTE_FORCE_CLOSE" | "BREACH_CLOSE" => CloseType::Unilateral,
        _ => CloseType::Unknown,
    })
}
pub(super) fn channels(
    open: &Value,
    pending: &Value,
    closed: &Value,
    max: usize,
) -> Result<Collection<Channel>> {
    let count = array(open, "channels")?
        .len()
        .saturating_add(array(closed, "channels")?.len());
    let count = [
        "pending_open_channels",
        "pending_closing_channels",
        "waiting_close_channels",
        "pending_force_closing_channels",
    ]
    .into_iter()
    .try_fold(count, |n, key| -> Result<usize> {
        Ok(n.saturating_add(array(pending, key)?.len()))
    })?;
    if count > max.saturating_add(1) {
        return Err(failure(ErrorCode::NodeOffline));
    }
    let mut items = Vec::new();
    for r in array(open, "channels")? {
        let active = boolean(r, "active")?.ok_or_else(invalid)?;
        let mut r = r.clone();
        r["remote_node_pub"] = r["remote_pubkey"].clone();
        items.push(channel(
            &r,
            if active {
                ChannelState::Active
            } else {
                ChannelState::Inactive
            },
            if active { "ACTIVE" } else { "INACTIVE" },
            false,
            None,
        )?);
    }
    for (key, state, ct) in [
        ("pending_open_channels", ChannelState::Opening, None),
        ("pending_closing_channels", ChannelState::Closing, None),
        ("waiting_close_channels", ChannelState::Closing, None),
        (
            "pending_force_closing_channels",
            ChannelState::Closing,
            Some(CloseType::Unilateral),
        ),
    ] {
        for r in array(pending, key)? {
            items.push(channel(&r["channel"], state, key, false, ct)?);
        }
    }
    for r in array(closed, "channels")? {
        items.push(channel(
            r,
            ChannelState::Closed,
            &enum_name(r, "close_type")?,
            true,
            Some(closure(r)?),
        )?);
    }
    items.sort_by(|a, b| a.id.cmp(&b.id));
    // A changing inventory must not silently pick one lifecycle state.
    if items.windows(2).any(|p| p[0].id == p[1].id) {
        return Err(invalid());
    }
    let truncated = items.len() > max;
    items.truncate(max);
    Ok(Collection { items, truncated })
}
pub(super) fn transactions(v: &Value, max: usize) -> Result<Collection<Transaction>> {
    let rows = array(v, "transactions")?;
    let mut items = Vec::new();
    require_budget(rows, max)?;
    for r in rows {
        let signed = match r.get("amount") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => {
                let n = s.parse::<i64>().map_err(|_| invalid())?;
                if n.to_string() != *s {
                    return Err(invalid());
                }
                Some(n)
            }
            _ => return Err(invalid()),
        };
        let mut outputs = Vec::new();
        for o in array(r, "output_details")? {
            outputs.push(TransactionOutput {
                index: small(o, "output_index")?
                    .and_then(|n| u32::try_from(n.get()).ok())
                    .ok_or_else(invalid)?,
                address: optional_text(o, "address")?,
                amount_sat: Sat(amount(o, "amount")?.ok_or_else(invalid)?),
                is_ours: boolean(o, "is_our_address")?,
            });
        }
        outputs.sort_by_key(|o| o.index);
        if outputs.windows(2).any(|p| p[0].index == p[1].index) {
            return Err(invalid());
        }
        items.push(Transaction {
            txid: hash(r, "tx_hash")?,
            direction: match signed {
                Some(n) if n > 0 => Direction::Incoming,
                Some(n) if n < 0 => Direction::Outgoing,
                Some(_) => Direction::SelfTransfer,
                None => Direction::Unknown,
            },
            amount_sat: signed
                .and_then(|n| Decimal::new(n.unsigned_abs()).ok())
                .map(Sat),
            fee_sat: amount(r, "total_fees")?.map(Sat),
            confirmations: small(r, "num_confirmations")?,
            block_height: small(r, "block_height")?.filter(|n| *n != Decimal::ZERO),
            occurred_at: time(r, "time_stamp", false)?,
            outputs,
        });
    }
    items.sort_by(|a, b| a.txid.cmp(&b.txid));
    if items.windows(2).any(|p| p[0].txid == p[1].txid) {
        return Err(invalid());
    }
    items.sort_by(|a, b| b.occurred_at.cmp(&a.occurred_at).then(a.txid.cmp(&b.txid)));
    items.truncate(max);
    Ok(Collection {
        items,
        truncated: rows.len() > max,
    })
}
pub(super) fn fees(node: &str, now: DateTime<Utc>) -> FeeEstimates {
    FeeEstimates {
        node_id: node.into(),
        observed_at: Some(now),
        stale: false,
        economy: None,
        normal: None,
        priority: None,
    }
}
pub(super) fn fee_rate(v: &Value) -> Result<Option<Decimal>> {
    Ok(amount(v, "sat_per_kw")?.and_then(|n| Decimal::new(n.get().div_ceil(250)).ok()))
}
fn require_budget(rows: &[Value], max: usize) -> Result<()> {
    if rows.len() > max.saturating_add(1) {
        return Err(failure(ErrorCode::NodeOffline));
    }
    Ok(())
}
