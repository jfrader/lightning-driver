use super::transport::{Rpc, Transport};
use crate::operations::{
    failure, Collection, InfoObservation, ReadQuery, ReadResult, Reads, ResponseFuture, Result,
};
use chrono::{DateTime, Utc};
use lightning_client::{
    model::*,
    money::Decimal,
    settings::{Limits, NodeSettings},
};
use serde_json::Value;
use std::time::{Duration, Instant};

pub(crate) struct BitcoinReads {
    transport: Transport,
    id: String,
    genesis: String,
    network: Network,
    max_items: usize,
    uptime: tokio::sync::Mutex<Option<(Instant, Decimal)>>,
    freshness: Duration,
}
pub(super) fn invalid() -> crate::operations::EngineError {
    failure(ErrorCode::UpstreamInvalidResponse)
}
fn number(value: &Value) -> Result<Decimal> {
    Decimal::new(value.as_u64().ok_or_else(invalid)?).map_err(|_| invalid())
}
fn n(value: &Value, key: &str) -> Result<Decimal> {
    number(&value[key])
}
fn text(value: &Value, key: &str) -> Result<String> {
    value[key].as_str().map(str::to_owned).ok_or_else(invalid)
}
fn boolean(value: &Value, key: &str) -> Result<bool> {
    value[key].as_bool().ok_or_else(invalid)
}
fn optional(value: &Value, key: &str) -> Result<Option<Decimal>> {
    value
        .get(key)
        .filter(|value| !value.is_null())
        .map(number)
        .transpose()
}
fn scaled(value: &Value, factor: f64, max: u64) -> Result<Decimal> {
    let value = value.as_f64().ok_or_else(invalid)? * factor;
    if !value.is_finite() || value < 0.0 || value.round() > max as f64 {
        return Err(invalid());
    }
    Decimal::new(value.round() as u64).map_err(|_| invalid())
}
fn warnings(value: &Value) -> Result<Vec<String>> {
    match value {
        Value::String(value) => Ok(if value.is_empty() {
            vec![]
        } else {
            vec![value.clone()]
        }),
        Value::Array(values) => values
            .iter()
            .map(|value| value.as_str().map(str::to_owned).ok_or_else(invalid))
            .collect(),
        _ => Err(invalid()),
    }
}
impl BitcoinReads {
    pub async fn connect(node: &NodeSettings, limits: &Limits) -> Result<Self> {
        Ok(Self {
            transport: Transport::connect(node, limits).await?,
            id: node.id.clone(),
            genesis: node
                .expected_genesis
                .clone()
                .ok_or_else(|| failure(ErrorCode::NotConfigured))?,
            network: node.network,
            max_items: limits.pagination.snapshot_max_items,
            uptime: tokio::sync::Mutex::new(None),
            freshness: Duration::from_secs(u64::from(limits.rpc_seconds)),
        })
    }
    async fn verify(&self) -> Result<()> {
        let hash = self.transport.call(Rpc::Genesis).await?;
        let hash = hash.as_str().ok_or_else(invalid)?;
        if !hash.eq_ignore_ascii_case(&self.genesis) {
            return Err(failure(ErrorCode::IdentityChanged));
        }
        Ok(())
    }
    fn chain_network(&self, blockchain: &Value) -> Result<Network> {
        let network = match blockchain["chain"].as_str() {
            Some("main") => Network::Mainnet,
            Some("test") => Network::Testnet,
            Some("testnet4") => Network::Testnet4,
            Some("signet") => Network::Signet,
            Some("regtest") => Network::Regtest,
            _ => return Err(invalid()),
        };
        if network != self.network {
            return Err(failure(ErrorCode::NetworkMismatch));
        }
        Ok(network)
    }
    async fn uptime(&self) -> Result<Decimal> {
        let mut cache = self.uptime.lock().await;
        if let Some((at, value)) = *cache {
            if at.elapsed() < self.freshness {
                return Ok(value);
            }
        }
        let value = number(&self.transport.call(Rpc::Uptime).await?)?;
        *cache = Some((Instant::now(), value));
        Ok(value)
    }
    async fn info(&self) -> Result<BitcoinNodeInfo> {
        let blockchain = self.transport.call(Rpc::Blockchain).await?;
        let network = self.chain_network(&blockchain)?;
        let net = self.transport.call(Rpc::Network).await?;
        let mempool = self.transport.call(Rpc::Mempool).await?;
        let mut notices = warnings(&blockchain["warnings"])?;
        for notice in warnings(&net["warnings"])? {
            if !notices.contains(&notice) {
                notices.push(notice);
            }
        }
        let best_block_hash = text(&blockchain, "bestblockhash")?;
        if best_block_hash.len() != 64
            || !best_block_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid());
        }
        Ok(BitcoinNodeInfo {
            node_id: self.id.clone(),
            chain: text(&blockchain, "chain")?,
            network,
            blocks: n(&blockchain, "blocks")?,
            headers: n(&blockchain, "headers")?,
            best_block_hash,
            verification_progress_bp: scaled(&blockchain["verificationprogress"], 10000.0, 10000)?,
            initial_block_download: boolean(&blockchain, "initialblockdownload")?,
            pruned: boolean(&blockchain, "pruned")?,
            prune_height: optional(&blockchain, "pruneheight")?,
            connections: n(&net, "connections")?,
            connections_in: optional(&net, "connections_in")?,
            connections_out: optional(&net, "connections_out")?,
            mempool: BitcoinMempool {
                transactions: n(&mempool, "size")?,
                vsize: n(&mempool, "bytes")?,
                usage: n(&mempool, "usage")?,
            },
            size_on_disk: n(&blockchain, "size_on_disk")?,
            version: n(&net, "version")?,
            subversion: text(&net, "subversion")?,
            uptime_seconds: self.uptime().await?,
            warnings: notices,
            observed_at: Utc::now(),
            stale: false,
        })
    }
    async fn peers(&self) -> Result<Collection<BitcoinPeer>> {
        let value = self.transport.call(Rpc::Peers).await?;
        let rows = value.as_array().ok_or_else(invalid)?;
        let items = rows
            .iter()
            .take(self.max_items)
            .map(peer)
            .collect::<Result<_>>()?;
        Ok(Collection {
            items,
            truncated: rows.len() > self.max_items,
        })
    }
}
fn peer(row: &Value) -> Result<BitcoinPeer> {
    let network = match row["network"].as_str() {
        Some("ipv4") => PeerTransport::Ipv4,
        Some("ipv6") => PeerTransport::Ipv6,
        Some("onion") => PeerTransport::Onion,
        Some("i2p") => PeerTransport::I2p,
        Some("cjdns") => PeerTransport::Cjdns,
        Some("not_publicly_routable" | "notreachable") => PeerTransport::Notreachable,
        _ => return Err(invalid()),
    };
    let synced = |key| -> Result<Option<Decimal>> {
        if row.get(key).and_then(Value::as_i64) == Some(-1) {
            Ok(None)
        } else {
            optional(row, key)
        }
    };
    Ok(BitcoinPeer {
        id: n(row, "id")?,
        addr: text(row, "addr")?,
        network,
        inbound: boolean(row, "inbound")?,
        connection_type: text(row, "connection_type")?,
        version: n(row, "version")?,
        subversion: text(row, "subver")?,
        ping_ms: row
            .get("pingtime")
            .map(|value| scaled(value, 1000.0, i64::MAX as u64))
            .transpose()?,
        connected_at: DateTime::from_timestamp(row["conntime"].as_i64().ok_or_else(invalid)?, 0)
            .ok_or_else(invalid)?,
        bytes_sent: n(row, "bytessent")?,
        bytes_received: n(row, "bytesrecv")?,
        synced_headers: synced("synced_headers")?,
        synced_blocks: synced("synced_blocks")?,
    })
}
impl Reads for BitcoinReads {
    fn availability(&self) -> ResponseFuture<'_, ReadAvailability> {
        Box::pin(async { ReadAvailability::bitcoin() })
    }
    fn read(&self, query: ReadQuery) -> ResponseFuture<'_, Result<ReadResult>> {
        Box::pin(async move {
            tokio::time::timeout(self.freshness, self.read_inner(query))
                .await
                .map_err(|_| failure(ErrorCode::NodeOffline))?
        })
    }
}
impl BitcoinReads {
    async fn read_inner(&self, query: ReadQuery) -> Result<ReadResult> {
        if !matches!(
            query,
            ReadQuery::Info | ReadQuery::Bitcoin | ReadQuery::BitcoinPeers
        ) {
            return Err(failure(ErrorCode::Unsupported));
        }
        self.verify().await?;
        match query {
            ReadQuery::Bitcoin => Ok(ReadResult::Bitcoin(self.info().await?)),
            ReadQuery::BitcoinPeers => Ok(ReadResult::BitcoinPeers(self.peers().await?)),
            ReadQuery::Info => {
                let chain = self.transport.call(Rpc::Blockchain).await?;
                let network = self.chain_network(&chain)?;
                let now = Utc::now();
                Ok(ReadResult::Info(InfoObservation {
                    identity_pubkey: String::new(),
                    network,
                    alias: None,
                    version: None,
                    status: NodeStatus {
                        node_id: self.id.clone(),
                        status: NodeConnection::Online,
                        synced_to_chain: Some(!boolean(&chain, "initialblockdownload")?),
                        synced_to_graph: None,
                        block_height: Some(n(&chain, "blocks")?),
                        observed_at: Some(now),
                        checked_at: now,
                        stale: false,
                        error_code: None,
                    },
                }))
            }
            _ => Err(failure(ErrorCode::Unsupported)),
        }
    }
}
