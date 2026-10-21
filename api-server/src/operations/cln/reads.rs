use super::*;
use lightning_client::money::Sat;
use std::collections::{BTreeMap, BTreeSet};

fn invalid() -> EngineError {
    failure(ErrorCode::UpstreamInvalidResponse)
}
pub(super) fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value.get(key).and_then(Value::as_array).ok_or_else(invalid)
}
pub(super) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn optional_text(value: &Value, key: &str) -> Result<Option<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok((!s.is_empty()).then(|| s.clone())),
        _ => Err(invalid()),
    }
}
pub(super) fn uint(value: &Value, key: &str) -> Result<Option<u64>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or_else(invalid),
    }
}
fn boolean(value: &Value, key: &str) -> Result<Option<bool>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_bool().map(Some).ok_or_else(invalid),
    }
}
pub(super) fn hash(value: &Value, key: &str) -> Result<String> {
    let text = text(value, key)?;
    use bitcoin::hashes::sha256;
    let parsed = sha256::Hash::from_str(text).map_err(|_| invalid())?;
    if parsed.to_string() != text {
        return Err(invalid());
    }
    Ok(text.into())
}
pub(super) fn txid(value: &Value, key: &str) -> Result<String> {
    let text = text(value, key)?;
    let parsed = text.parse::<bitcoin::Txid>().map_err(|_| invalid())?;
    if parsed.to_string() != text {
        return Err(invalid());
    }
    Ok(text.into())
}
pub(super) fn pubkey(value: &Value, key: &str) -> Result<String> {
    let text = text(value, key)?;
    if text
        .parse::<bitcoin::secp256k1::PublicKey>()
        .map_err(|_| invalid())?
        .to_string()
        != text
    {
        return Err(invalid());
    }
    Ok(text.into())
}
use std::str::FromStr;

// Overflow is unknown money, not rounded/truncated money. Wrong encodings are schema errors.
pub(super) fn amount(value: &Value, key: &str) -> Result<Option<Decimal>> {
    let number = match value.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => n.as_u64().ok_or_else(invalid)?,
        Some(Value::String(s)) => {
            let (digits, multiplier) = if let Some(d) = s.strip_suffix("msat") {
                (d, 1)
            } else if let Some(d) = s.strip_suffix("sat") {
                (d, 1000)
            } else {
                (s.as_str(), 1)
            };
            if digits.is_empty()
                || !digits.bytes().all(|b| b.is_ascii_digit())
                || (digits.len() > 1 && digits.starts_with('0'))
            {
                return Err(invalid());
            }
            let Ok(number) = digits.parse::<u64>() else {
                return Ok(None);
            };
            let Some(number) = number.checked_mul(multiplier) else {
                return Ok(None);
            };
            number
        }
        _ => return Err(invalid()),
    };
    Ok(Decimal::new(number).ok())
}
fn sat(amount: Option<Decimal>) -> Option<Sat> {
    amount
        .filter(|n| n.get() % 1000 == 0)
        .and_then(|n| Decimal::new(n.get() / 1000).ok())
        .map(Sat)
}
fn time(value: &Value, key: &str) -> Result<Option<DateTime<Utc>>> {
    Ok(uint(value, key)?
        .filter(|n| *n != 0)
        .and_then(|n| i64::try_from(n).ok())
        .and_then(|n| DateTime::from_timestamp(n, 0)))
}
pub(super) fn required_time(value: &Value, key: &str) -> Result<DateTime<Utc>> {
    time(value, key)?.ok_or_else(invalid)
}
fn add(total: Option<Decimal>, amount: Option<Decimal>) -> Option<Decimal> {
    total.zip(amount).and_then(|(a, b)| a.checked_add(b).ok())
}
fn sub(total: Option<Decimal>, amount: Option<Decimal>) -> Option<Decimal> {
    total.zip(amount).and_then(|(a, b)| a.checked_sub(b).ok())
}
fn bounded<T>(mut items: Vec<T>, max: usize, mut truncated: bool) -> Collection<T> {
    truncated |= items.len() > max;
    items.truncate(max);
    Collection { items, truncated }
}
fn require_budget(rows: &[Value], max: usize) -> Result<()> {
    if rows.len() > max {
        return Err(failure(ErrorCode::NodeOffline));
    }
    Ok(())
}

pub(super) struct Info {
    pub identity: String,
    pub alias: Option<String>,
    pub version: Option<String>,
    pub network: Network,
    pub synced: Option<bool>,
    pub height: Option<Decimal>,
}
pub(super) fn info(value: &Value) -> Result<Info> {
    // Presence of a warning (including an unexpected null) never becomes synced=true.
    let synced = if value.get("warning_bitcoind_sync").is_none()
        && value.get("warning_lightningd_sync").is_none()
    {
        Some(true)
    } else {
        None
    };
    let network = match text(value, "network")? {
        "bitcoin" | "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => Network::Unknown,
    };
    Ok(Info {
        identity: pubkey(value, "id")?,
        alias: optional_text(value, "alias")?,
        version: optional_text(value, "version")?,
        network,
        synced,
        height: uint(value, "blockheight")?.and_then(|n| Decimal::new(n).ok()),
    })
}

pub(super) fn balances(
    value: &Value,
    node: &str,
    network: Network,
    now: DateTime<Utc>,
    max: usize,
) -> Result<Balances> {
    let outputs = array(value, "outputs")?;
    let channels = array(value, "channels")?;
    require_budget(outputs, max)?;
    require_budget(channels, max)?;
    let mut confirmed = Some(Decimal::ZERO);
    let mut unconfirmed = Some(Decimal::ZERO);
    for output in outputs {
        let amount = amount(output, "amount_msat")?;
        match text(output, "status")? {
            "confirmed" => match boolean(output, "reserved")? {
                Some(false) => confirmed = add(confirmed, amount),
                Some(true) => {}
                None => confirmed = None,
            },
            "unconfirmed" => unconfirmed = add(unconfirmed, amount),
            "spent" | "immature" => {}
            _ => {
                confirmed = None;
                unconfirmed = None;
            }
        }
    }
    let mut local = Some(Decimal::ZERO);
    let mut remote = Some(Decimal::ZERO);
    for channel in channels {
        let ours = amount(channel, "our_amount_msat")?;
        let total = amount(channel, "amount_msat")?;
        local = add(local, ours);
        remote = add(remote, sub(total, ours));
    }
    Ok(Balances {
        node_id: node.into(),
        network,
        onchain_confirmed_sat: sat(confirmed),
        onchain_unconfirmed_sat: sat(unconfirmed),
        onchain_spendable_sat: sat(confirmed),
        channel_local_msat: local.map(Msat),
        channel_remote_msat: remote.map(Msat),
        channel_spendable_msat: None,
        observed_at: now,
        stale: false,
    })
}

pub(super) fn invoices(value: &Value, max: usize) -> Result<Collection<Invoice>> {
    let rows = array(value, "invoices")?;
    require_budget(rows, max)?;
    let mut items = Vec::new();
    let mut truncated = false;
    for row in rows {
        let payment_hash = hash(row, "payment_hash")?;
        let Some(bolt11) = optional_text(row, "bolt11")? else {
            truncated = true;
            continue;
        };
        let Ok(invoice) = bolt11.parse::<lightning_invoice::Bolt11Invoice>() else {
            truncated = true;
            continue;
        };
        if invoice.payment_hash().to_string() != payment_hash {
            truncated = true;
            continue;
        }
        let Some(created_at) = i64::try_from(invoice.duration_since_epoch().as_secs())
            .ok()
            .filter(|n| *n != 0)
            .and_then(|n| DateTime::from_timestamp(n, 0))
        else {
            truncated = true;
            continue;
        };
        let (state, backend_state) = match text(row, "status")? {
            "unpaid" => (InvoiceState::Unpaid, "unpaid"),
            "paid" => (InvoiceState::Paid, "paid"),
            "expired" => (InvoiceState::Expired, "expired"),
            _ => (InvoiceState::Unknown, "unknown"),
        };
        items.push(Invoice {
            payment_hash,
            amount_msat: amount(row, "amount_msat")?.map(Msat),
            received_msat: if state == InvoiceState::Paid {
                amount(row, "amount_received_msat")?.map(Msat)
            } else {
                None
            },
            state,
            backend_state: backend_state.into(),
            bolt11: Some(bolt11),
            description: optional_text(row, "description")?,
            created_at,
            expires_at: time(row, "expires_at")?,
            paid_at: if state == InvoiceState::Paid {
                time(row, "paid_at")?
            } else {
                None
            },
        });
    }
    let mut counts = BTreeMap::new();
    for invoice in &items {
        *counts.entry(invoice.payment_hash.clone()).or_insert(0usize) += 1;
    }
    for invoice in &mut items {
        if counts[&invoice.payment_hash] > 1 {
            invoice.state = InvoiceState::Unknown;
            invoice.amount_msat = None;
            invoice.received_msat = None;
            invoice.paid_at = None;
        }
    }
    items.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then(a.payment_hash.cmp(&b.payment_hash))
    });
    Ok(bounded(items, max, truncated))
}

// created_index is the minimum retained part index of a CLN payment group. It is
// private provenance, never a timestamp or a public row/operation identifier.
struct Group {
    index: Option<u64>,
    created: Option<DateTime<Utc>>,
    state: PaymentState,
    amount: Option<Decimal>,
    sent: Option<Decimal>,
    completed: Option<DateTime<Utc>>,
    destination: Option<String>,
}
pub(super) fn sort_payments(items: &mut [Payment]) {
    items.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then(a.payment_hash.cmp(&b.payment_hash))
    });
}
pub(super) fn payments(value: &Value, max: usize) -> Result<Collection<Payment>> {
    let rows = array(value, "pays")?;
    require_budget(rows, max)?;
    let mut groups: BTreeMap<String, Vec<Group>> = BTreeMap::new();
    for row in rows {
        let state = match text(row, "status")? {
            "complete" => PaymentState::Succeeded,
            "pending" => PaymentState::Pending,
            "failed" => PaymentState::Failed,
            _ => PaymentState::Unknown,
        };
        let destination = optional_text(row, "destination")?;
        if destination.is_some() {
            pubkey(row, "destination")?;
        }
        groups
            .entry(hash(row, "payment_hash")?)
            .or_default()
            .push(Group {
                index: uint(row, "created_index")?,
                created: time(row, "created_at")?,
                state,
                amount: amount(row, "amount_msat")?.filter(|n| *n != Decimal::ZERO),
                sent: amount(row, "amount_sent_msat")?,
                // Summary output only gives the earliest successful part's time; it
                // cannot establish that every part in a multipart group has a time.
                completed: if uint(row, "number_of_parts")?.is_none_or(|n| n == 1) {
                    time(row, "completed_at")?
                } else {
                    None
                },
                destination,
            });
    }
    let mut items = Vec::new();
    let mut truncated = false;
    for (payment_hash, mut groups) in groups {
        groups.sort_by_key(|g| (g.index.unwrap_or(u64::MAX), g.created));
        if groups.first().is_some_and(|g| g.index.is_none()) {
            truncated = true;
            continue;
        }
        let Some(created_at) = groups.first().and_then(|g| g.created) else {
            truncated = true;
            continue;
        };
        let mut indices = BTreeSet::new();
        let ambiguous = groups.iter().any(|g| {
            g.index.is_none_or(|n| !indices.insert(n))
                || g.state == PaymentState::Unknown
                || g.created.is_none()
        });
        let active: Vec<_> = groups
            .iter()
            .filter(|g| g.state != PaymentState::Failed)
            .collect();
        let chosen = if ambiguous || active.len() > 1 {
            None
        } else if let Some(group) = active.first() {
            // Only a later successful/pending group supersedes older failures.
            if group.state != PaymentState::Succeeded
                && groups
                    .iter()
                    .any(|old| old.state == PaymentState::Failed && old.index > group.index)
            {
                None
            } else {
                Some(*group)
            }
        } else {
            groups.last()
        };
        let (state, amount_msat, fee_msat, destination, completed_at) = match chosen {
            None => (PaymentState::Unknown, None, None, None, None),
            Some(group) => {
                let fee = if group.amount.is_some() {
                    sub(group.sent, group.amount).map(Msat)
                } else {
                    None
                };
                (
                    group.state,
                    group.amount.map(Msat),
                    fee,
                    group.destination.clone(),
                    if group.state == PaymentState::Succeeded {
                        group.completed
                    } else {
                        None
                    },
                )
            }
        };
        items.push(Payment {
            payment_hash,
            amount_msat,
            fee_msat,
            destination,
            state,
            backend_state: match state {
                PaymentState::Succeeded => "complete",
                PaymentState::Pending => "pending",
                PaymentState::Failed => "failed",
                PaymentState::Unknown => "unknown",
            }
            .into(),
            created_at,
            completed_at,
        });
    }
    sort_payments(&mut items);
    Ok(bounded(items, max, truncated))
}

pub(super) fn peers(value: &Value, max: usize) -> Result<Collection<Peer>> {
    let rows = array(value, "peers")?;
    require_budget(rows, max)?;
    let mut items = Vec::new();
    let mut ids = BTreeSet::new();
    for row in rows {
        let pubkey = pubkey(row, "id")?;
        if !ids.insert(pubkey.clone()) {
            return Err(invalid());
        }
        let connected = boolean(row, "connected")?.ok_or_else(invalid)?;
        let address = if connected {
            match row.get("netaddr") {
                None | Some(Value::Null) => None,
                Some(Value::Array(addresses)) if addresses.len() == 1 => {
                    Some(addresses[0].as_str().ok_or_else(invalid)?.to_owned())
                }
                _ => return Err(invalid()),
            }
        } else {
            None
        };
        items.push(Peer {
            pubkey,
            connected,
            address,
            inbound: None,
        });
    }
    items.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
    Ok(bounded(items, max, false))
}
fn outpoint(row: &Value) -> Result<Option<String>> {
    match (row.get("funding_txid"), uint(row, "funding_outnum")?) {
        (None | Some(Value::Null), None) => Ok(None),
        (Some(_), Some(n)) => Ok(Some(format!(
            "{}:{}",
            txid(row, "funding_txid")?,
            u32::try_from(n).map_err(|_| invalid())?
        ))),
        _ => Ok(None),
    }
}
pub(super) fn channels(open: &Value, closed: &Value, max: usize) -> Result<Collection<Channel>> {
    let open = array(open, "channels")?;
    let closed = array(closed, "closedchannels")?;
    require_budget(open, max)?;
    require_budget(closed, max)?;
    let mut items = Vec::new();
    let mut truncated = false;
    let mut ids = BTreeSet::new();
    for (rows, is_closed) in [(open, false), (closed, true)] {
        for row in rows {
            let funding_outpoint = outpoint(row)?;
            let id = match row.get("channel_id") {
                None | Some(Value::Null) => funding_outpoint.clone(),
                Some(_) => Some(hash(row, "channel_id")?),
            };
            let Some(id) = id else {
                truncated = true;
                continue;
            };
            if !ids.insert(id.clone()) {
                return Err(invalid());
            }
            if row.get("peer_id").is_none_or(Value::is_null) {
                truncated = true;
                continue;
            }
            let (state, backend_state) = if is_closed {
                (ChannelState::Closed, "closed")
            } else {
                match text(row, "state")? {
                    "CHANNELD_NORMAL" => (
                        if boolean(row, "peer_connected")? == Some(true) {
                            ChannelState::Active
                        } else {
                            ChannelState::Inactive
                        },
                        "CHANNELD_NORMAL",
                    ),
                    "OPENINGD" => (ChannelState::Opening, "OPENINGD"),
                    "CHANNELD_AWAITING_LOCKIN" => {
                        (ChannelState::Opening, "CHANNELD_AWAITING_LOCKIN")
                    }
                    "CHANNELD_SHUTTING_DOWN" => (ChannelState::Closing, "CHANNELD_SHUTTING_DOWN"),
                    "CLOSINGD_SIGEXCHANGE" => (ChannelState::Closing, "CLOSINGD_SIGEXCHANGE"),
                    "CLOSINGD_COMPLETE" => (ChannelState::Closing, "CLOSINGD_COMPLETE"),
                    "AWAITING_UNILATERAL" => (ChannelState::Closing, "AWAITING_UNILATERAL"),
                    "FUNDING_SPEND_SEEN" => (ChannelState::Closing, "FUNDING_SPEND_SEEN"),
                    "ONCHAIN" => (ChannelState::Closing, "ONCHAIN"),
                    _ => (ChannelState::Unknown, "unknown"),
                }
            };
            let total = amount(row, "total_msat")?;
            let ours = amount(
                row,
                if is_closed {
                    "final_to_us_msat"
                } else {
                    "to_us_msat"
                },
            )?;
            items.push(Channel {
                id,
                peer_pubkey: pubkey(row, "peer_id")?,
                funding_outpoint,
                short_channel_id: optional_text(row, "short_channel_id")?,
                state,
                backend_state: backend_state.into(),
                private: boolean(row, "private")?,
                capacity_sat: sat(total),
                local_msat: ours.map(Msat),
                remote_msat: sub(total, ours).map(Msat),
                spendable_msat: if is_closed {
                    None
                } else {
                    amount(row, "spendable_msat")?.map(Msat)
                },
                close_type: if is_closed {
                    Some(CloseType::Unknown)
                } else {
                    None
                },
            });
        }
    }
    items.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(bounded(items, max, truncated))
}

pub(super) fn transactions(value: &Value, max: usize) -> Result<Collection<Transaction>> {
    let rows = array(value, "transactions")?;
    require_budget(rows, max)?;
    let mut items = Vec::new();
    let mut ids = BTreeSet::new();
    for row in rows {
        let txid = txid(row, "hash")?;
        if !ids.insert(txid.clone()) {
            return Err(invalid());
        }
        let mut outputs = Vec::new();
        for output in array(row, "outputs")? {
            let index = uint(output, "index")?
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(invalid)?;
            let amount_sat = sat(amount(output, "amount_msat")?).ok_or_else(invalid)?;
            outputs.push(TransactionOutput {
                index,
                address: None,
                amount_sat,
                is_ours: None,
            });
        }
        outputs.sort_by_key(|o| o.index);
        if outputs.windows(2).any(|w| w[0].index == w[1].index) {
            return Err(invalid());
        }
        // This schema has no address/ownership field or wallet-net value. Its raw
        // script and transaction are not part of the public transaction projection.
        items.push(Transaction {
            txid,
            direction: Direction::Unknown,
            amount_sat: None,
            fee_sat: None,
            confirmations: None,
            block_height: uint(row, "blockheight")?
                .filter(|n| *n > 0)
                .and_then(|n| Decimal::new(n).ok()),
            occurred_at: None,
            outputs,
        });
    }
    items.sort_by(|a, b| a.txid.cmp(&b.txid));
    Ok(bounded(items, max, false))
}
pub(super) fn fees(value: &Value, node: &str, now: DateTime<Utc>) -> Result<FeeEstimates> {
    // No approved target blockcounts exist. Do not invent 1/3/6 or interpolate.
    let perkb = value
        .get("perkb")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    if let Some(estimates) = perkb.get("estimates") {
        for estimate in estimates.as_array().ok_or_else(invalid)? {
            uint(estimate, "blockcount")?.ok_or_else(invalid)?;
            uint(estimate, "feerate")?.ok_or_else(invalid)?;
        }
    }
    Ok(FeeEstimates {
        node_id: node.into(),
        observed_at: Some(now),
        stale: false,
        economy: None,
        normal: None,
        priority: None,
    })
}
