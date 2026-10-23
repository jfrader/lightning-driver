mod grpc;
mod reads;
#[cfg(test)]
mod tests;
pub(crate) mod tls;
mod transport;
mod watchtower;

use super::*;
use base64::Engine as _;
use evidence::{Class, Facts, Rejection};
use lightning_client::money::{Decimal, Msat};
use serde_json::{json, Value};
use transport::{Rpc, Wire};

type LndGrpcAdapter = LndAdapter<grpc::Grpc>;
type LndRestAdapter = LndAdapter<transport::Rest>;
// Both transports enter the same claim/evidence and normalization path.
struct LndAdapter<T: Wire> {
    transport: T,
    config: NodeConfig,
    max_items: usize,
    watchtower: tokio::sync::OnceCell<watchtower::Probe>,
}
pub(super) async fn connect_grpc(
    settings: &lightning_client::settings::NodeSettings,
    limits: &lightning_client::settings::Limits,
    config: NodeConfig,
) -> Result<Arc<dyn Adapter>> {
    Ok(Arc::new(
        LndGrpcAdapter::connect(settings, limits, config).await?,
    ))
}
pub(super) async fn connect_rest(
    settings: &lightning_client::settings::NodeSettings,
    limits: &lightning_client::settings::Limits,
    config: NodeConfig,
) -> Result<Arc<dyn Adapter>> {
    Ok(Arc::new(
        LndRestAdapter::connect(settings, limits, config).await?,
    ))
}
impl LndGrpcAdapter {
    pub async fn connect(
        settings: &lightning_client::settings::NodeSettings,
        limits: &lightning_client::settings::Limits,
        config: NodeConfig,
    ) -> Result<Self> {
        check_config(settings, &config, Backend::LndGrpc)?;
        Self::pin(
            grpc::Grpc::connect(settings, limits).await?,
            config,
            limits.pagination.snapshot_max_items,
        )
        .await
    }
}
impl LndRestAdapter {
    pub async fn connect(
        settings: &lightning_client::settings::NodeSettings,
        limits: &lightning_client::settings::Limits,
        config: NodeConfig,
    ) -> Result<Self> {
        check_config(settings, &config, Backend::LndRest)?;
        Self::pin(
            transport::Rest::connect(settings, limits)?,
            config,
            limits.pagination.snapshot_max_items,
        )
        .await
    }
}
fn check_config(
    settings: &lightning_client::settings::NodeSettings,
    c: &NodeConfig,
    b: Backend,
) -> Result<()> {
    if settings.backend != b
        || c.backend != b
        || settings.id != c.binding.node_id
        || settings.expected_pubkey.as_deref() != Some(c.binding.identity_pubkey.as_str())
        || settings.network != intent::network(&c.binding)
    {
        return Err(failure(ErrorCode::NotConfigured));
    }
    Ok(())
}
impl<T: Wire> LndAdapter<T> {
    async fn pin(transport: T, config: NodeConfig, max_items: usize) -> Result<Self> {
        let adapter = Self {
            transport,
            config,
            max_items,
            watchtower: tokio::sync::OnceCell::new(),
        };
        Ok(adapter)
    }
    async fn call(&self, rpc: Rpc, p: Value, budget: &mut usize) -> Result<Value> {
        let (v, n) = self.transport.call(rpc, p, *budget).await.unary()?;
        *budget = budget
            .checked_sub(n)
            .ok_or_else(|| failure(ErrorCode::NodeOffline))?;
        Ok(v)
    }
    async fn info(&self, budget: &mut usize) -> Result<InfoObservation> {
        let info = reads::info(&self.call(Rpc::Info, json!({}), budget).await?)?;
        if info.identity != self.config.binding.identity_pubkey {
            return Err(failure(ErrorCode::IdentityChanged));
        }
        if info.network != intent::network(&self.config.binding) {
            return Err(failure(ErrorCode::NetworkMismatch));
        }
        let now = Utc::now();
        Ok(InfoObservation {
            identity_pubkey: info.identity,
            network: info.network,
            alias: info.alias,
            version: info.version,
            status: NodeStatus {
                node_id: self.config.binding.node_id.clone(),
                status: NodeConnection::Online,
                synced_to_chain: info.synced,
                synced_to_graph: info.graph_synced,
                block_height: info.height,
                observed_at: Some(now),
                checked_at: now,
                stale: false,
                error_code: None,
            },
        })
    }
    async fn inventory(&self, b: &mut usize) -> Result<(Collection<Channel>, Value)> {
        let open = self.call(Rpc::Channels, json!({}), b).await?;
        let pending = self
            .call(Rpc::PendingChannels, json!({"include_raw_tx":false}), b)
            .await?;
        let closed = self.call(Rpc::ClosedChannels, json!({}), b).await?;
        Ok((
            reads::channels(&open, &pending, &closed, self.max_items)?,
            closed,
        ))
    }
    async fn read_inner(&self, q: ReadQuery) -> Result<ReadResult> {
        if q.is_watchtower() {
            return self.read_watchtower(q).await;
        }
        let mut b = self.transport.byte_budget();
        let info = self.info(&mut b).await?;
        let now = Utc::now();
        let node = &self.config.binding.node_id;
        let count = self
            .max_items
            .checked_add(1)
            .ok_or_else(|| failure(ErrorCode::NotConfigured))?
            .to_string();
        Ok(match q {
            ReadQuery::Info => ReadResult::Info(info),
            ReadQuery::Balances => {
                let w = self.call(Rpc::Wallet, json!({}), &mut b).await?;
                let c = self.call(Rpc::ChannelBalance, json!({}), &mut b).await?;
                ReadResult::Balances(reads::balances(
                    &w,
                    &c,
                    node,
                    intent::network(&self.config.binding),
                    now,
                )?)
            }
            ReadQuery::Invoices => ReadResult::Invoices(reads::invoices(
                &self
                    .call(
                        Rpc::Invoices,
                        json!({"num_max_invoices":count,"reversed":true}),
                        &mut b,
                    )
                    .await?,
                self.max_items,
            )?),
            ReadQuery::Payments => ReadResult::Payments(reads::payments(
                &self
                    .call(
                        Rpc::Payments,
                        json!({"include_incomplete":true,"max_payments":count,"reversed":true}),
                        &mut b,
                    )
                    .await?,
                self.max_items,
            )?),
            ReadQuery::Peers => ReadResult::Peers(reads::peers(
                &self.call(Rpc::Peers, json!({}), &mut b).await?,
                self.max_items,
            )?),
            ReadQuery::Channels => ReadResult::Channels(self.inventory(&mut b).await?.0),
            ReadQuery::Transactions => ReadResult::Transactions(reads::transactions(
                &self.call(Rpc::Transactions, json!({}), &mut b).await?,
                self.max_items,
            )?),
            // Confirmation targets are unresolved in the approved specification.
            ReadQuery::Fees => ReadResult::Fees(reads::fees(node, now)),
            ReadQuery::Bitcoin | ReadQuery::BitcoinPeers => {
                return Err(failure(ErrorCode::Unsupported))
            }
            ReadQuery::WatchtowerServer
            | ReadQuery::WatchtowerClient
            | ReadQuery::WatchtowerTowers
            | ReadQuery::WatchtowerTower(_) => {
                unreachable!("watchtower reads have their own surface")
            }
        })
    }
    async fn prepare_inner(&self, request: &OperationRequest) -> Result<ReadFacts> {
        let mut b = self.transport.byte_budget();
        let info = self.info(&mut b).await?;
        let rpc = mutation_rpc(request);
        // LND answers `InvalidArgument: permission denied` (or PermissionDenied/Unauthenticated)
        // when the macaroon lacks the checked permission instead of returning `valid:false`.
        // Both are a refusal of this mutation, not a transport failure.
        let permission = match self
            .call(
                Rpc::CheckPermissions,
                json!({"macaroon":base64::engine::general_purpose::STANDARD.encode(zeroize::Zeroizing::new(hex::decode(self.transport.macaroon()).map_err(|_|failure(ErrorCode::NotConfigured))?)),"permissions":rpc.permissions(),"full_method":rpc.method()}),
                &mut b,
            )
            .await
        {
            Ok(value) => reads::boolean(&value, "valid")?.ok_or_else(reads::invalid)?,
            // `InvalidArgument` here is LND's refusal for the checked permission.
            Err(error) if error.code() == ErrorCode::UpstreamRejected => false,
            Err(error) => return Err(error),
        };
        let mut facts = ReadFacts {
            binding: self.config.binding.clone(),
            generation: self.config.generation,
            observed_at: info.status.checked_at,
            connection: NodeConnection::Online,
            sync_usable: info.status.synced_to_chain == Some(true),
            permission,
            peer_connected: false,
            close_target: None,
            close_peer: None,
        };
        if let OperationRequest::OpenChannel(p) = request {
            let peers = reads::peers(
                &self.call(Rpc::Peers, json!({}), &mut b).await?,
                self.max_items,
            )?;
            facts.peer_connected = !peers.truncated
                && peers
                    .items
                    .iter()
                    .any(|peer| peer.pubkey == p.peer_pubkey && peer.connected);
        }
        if let OperationRequest::CloseChannel(p) = request {
            let channels = self.inventory(&mut b).await?.0;
            if !channels.truncated {
                if let Some(c) = channels.items.iter().find(|c| {
                    c.id == p.channel_id
                        || c.short_channel_id.as_ref() == Some(&p.channel_id)
                        || c.funding_outpoint.as_ref() == Some(&p.channel_id)
                }) {
                    if matches!(c.state, ChannelState::Active | ChannelState::Inactive) {
                        facts.close_target = c.funding_outpoint.clone();
                        facts.close_peer = Some(c.peer_pubkey.clone());
                    }
                }
            }
        }
        Ok(facts)
    }
    async fn execute(&self, permit: ClaimPermit) -> Evidence {
        let mut e = Evidence {
            operation_id: permit.intent.operation.id,
            binding: permit.intent.operation.review.node.clone(),
            generation: permit.intent.connection_generation,
            kind: permit.intent.operation.request.kind(),
            claim_id: permit.claim_id,
            sequence: 0,
            reference: RecoveryReference::planned(&permit.intent),
            class: Class::Lost,
            facts: None,
        };
        if e.binding != self.config.binding || e.generation != self.config.generation {
            e.class = Class::Conflict;
            return e;
        }
        let (rpc, p) = match command(&permit, self.transport.deadline().as_secs()) {
            Ok(c) => c,
            Err(_) => {
                e.class = Class::Partial;
                return e;
            }
        };
        let reply = self
            .transport
            .call(rpc, p, self.transport.byte_budget())
            .await;
        let mut terminal = false;
        let mut accepted = false;
        let mut progress = false;
        for value in &reply.frames {
            match dispatch(&permit.intent, value, &mut e.reference) {
                Ok(Dispatch::Facts(mut f)) => {
                    if let (
                        Some(Facts::Close { txids: old, .. }),
                        Facts::Close { txids: new, .. },
                    ) = (&e.facts, &mut f)
                    {
                        new.extend(old.iter().cloned());
                        new.sort();
                        new.dedup();
                        if new.len() > 64 {
                            e.class = Class::Partial;
                            e.facts = None;
                            break;
                        }
                    }
                    terminal = matches!(f, Facts::Payment { settled: true, .. });
                    accepted = true;
                    e.class = Class::Positive;
                    e.facts = Some(f);
                    if terminal {
                        break;
                    }
                }
                Ok(Dispatch::Failed(r)) => {
                    e.class = Class::Rejected(r);
                    e.facts = None;
                    terminal = true;
                    break;
                }
                Ok(Dispatch::Pending) => progress = true,
                Err(_) => {
                    if !accepted {
                        e.class = Class::Partial;
                    }
                }
            }
        }
        if let Some(error) = reply.error {
            if !terminal {
                e.class = if accepted || progress {
                    Class::Lost
                } else {
                    error.mutation_class()
                };
                e.facts = None;
            }
        }
        e
    }
    async fn observe(&self, q: ObservationQuery) -> Evidence {
        let mut e = Evidence {
            operation_id: q.operation_id,
            binding: q.binding,
            generation: q.generation,
            kind: q.kind,
            claim_id: q.claim_id,
            sequence: q.sequence,
            reference: q.reference,
            class: Class::NotFound,
            facts: None,
        };
        if e.binding != self.config.binding || e.generation != self.config.generation {
            e.class = Class::Conflict;
            return e;
        }
        let mut b = self.transport.byte_budget();
        if self.info(&mut b).await.is_err() {
            e.class = Class::Lost;
            return e;
        }
        if e.kind == OperationKind::PayInvoice {
            if self.observe_payment(&mut e, b).await.is_err() {
                e.class = Class::Lost;
            }
            return e;
        }
        match self
            .observe_inner(&e, &q.request, &q.close_txids, &mut b)
            .await
        {
            Ok(Some(f)) => {
                e.class = Class::Positive;
                e.facts = Some(f);
            }
            Ok(None) => {}
            Err(_) => e.class = Class::Lost,
        }
        e
    }
    async fn observe_payment(&self, e: &mut Evidence, b: usize) -> Result<()> {
        let Some(hash) = e.reference.payment_hash.clone() else {
            return Ok(());
        };
        let reply = self
            .transport
            .call(
                Rpc::TrackPayment,
                json!({"payment_hash_hex":hash,"no_inflight_updates":false}),
                b,
            )
            .await;
        for v in &reply.frames {
            if reads::hash(v, "payment_hash")? != hash {
                continue;
            }
            let linked = e.reference.attempt.is_some() && attempt(v)? == e.reference.attempt;
            match reads::text(v, "status")? {
                "SUCCEEDED" if linked => {
                    e.facts = Some(Facts::Payment {
                        payment_hash: hash,
                        amount_msat: Msat(
                            reads::amount(v, "value_msat")?.ok_or_else(reads::invalid)?,
                        ),
                        fee_msat: reads::amount(v, "fee_msat")?.map(Msat),
                        settled: true,
                    });
                    e.class = Class::Positive;
                    return Ok(());
                }
                "SUCCEEDED" => {
                    e.class = Class::PaidElsewhere;
                    return Ok(());
                }
                "FAILED" if linked => {
                    e.class = Class::Rejected(payment_rejection(v)?);
                    return Ok(());
                }
                _ => {}
            }
        }
        if reply.error.is_some() {
            e.class = Class::Lost;
        }
        Ok(())
    }
    async fn observe_inner(
        &self,
        e: &Evidence,
        request: &OperationRequest,
        close_txids: &[String],
        b: &mut usize,
    ) -> Result<Option<Facts>> {
        let r = &e.reference;
        Ok(match e.kind {
            OperationKind::CreateInvoice => {
                let Some(hash) = &r.payment_hash else {
                    return Ok(None);
                };
                let v = self
                    .call(Rpc::LookupInvoice, json!({"r_hash_str":hash}), b)
                    .await?;
                if reads::bytes_hash(&v, "r_hash")? != *hash {
                    return Ok(None);
                }
                Some(Facts::Invoice {
                    payment_hash: hash.clone(),
                    bolt11: reads::text(&v, "payment_request")?.into(),
                })
            }
            OperationKind::PayInvoice => None,
            OperationKind::ConnectPeer | OperationKind::DisconnectPeer => {
                let Some(peer) = &r.peer else { return Ok(None) };
                let peers =
                    reads::peers(&self.call(Rpc::Peers, json!({}), b).await?, self.max_items)?;
                if peers.truncated {
                    return Ok(None);
                }
                let connected = peers.items.iter().any(|p| &p.pubkey == peer);
                if connected != (e.kind == OperationKind::ConnectPeer) {
                    return Ok(None);
                }
                Some(Facts::Peer {
                    pubkey: peer.clone(),
                    connected,
                    complete: true,
                })
            }
            OperationKind::OpenChannel | OperationKind::CloseChannel => {
                let Some(reference) = &r.channel else {
                    return Ok(None);
                };
                let (channels, closed) = self.inventory(b).await?;
                let Some(c) = channels
                    .items
                    .iter()
                    .find(|c| c.funding_outpoint.as_ref() == Some(reference) || &c.id == reference)
                else {
                    return Ok(None);
                };
                if e.kind == OperationKind::OpenChannel {
                    Some(Facts::Open {
                        channel_id: Some(c.id.clone()),
                        funding_outpoint: c.funding_outpoint.clone(),
                        active: c.state == ChannelState::Active,
                        published: true,
                    })
                } else {
                    let mut txids = Vec::new();
                    if let Some(row) = reads::array(&closed, "channels")?
                        .iter()
                        .find(|row| row["channel_point"] == *reference)
                    {
                        let txid = reads::hash(row, "closing_tx_hash")?;
                        if c.close_type == Some(CloseType::Cooperative)
                            && !close_txids.is_empty()
                            && !close_txids.contains(&txid)
                        {
                            return Ok(None);
                        }
                        txids.push(txid);
                    }
                    Some(Facts::Close {
                        channel: reference.clone(),
                        close_type: c.close_type.unwrap_or(CloseType::Unknown),
                        txids,
                        confirmations: None,
                        closed: c.state == ChannelState::Closed,
                        published: c.state == ChannelState::Closed,
                    })
                }
            }
            OperationKind::SendOnchain => {
                let Some(txid) = &r.txid else { return Ok(None) };
                let txs = reads::transactions(
                    &self.call(Rpc::Transactions, json!({}), b).await?,
                    self.max_items,
                )?;
                let Some(tx) = txs.items.iter().find(|tx| &tx.txid == txid) else {
                    return Ok(None);
                };
                let OperationRequest::SendOnchain(p) = request else {
                    return Err(reads::invalid());
                };
                Some(Facts::Send {
                    txid: txid.clone(),
                    amount_sat: p.amount_sat,
                    fee_sat: tx.fee_sat,
                    confirmations: tx.confirmations,
                    published: true,
                })
            }
            OperationKind::NewAddress => None,
        })
    }
}
impl<T: Wire> Reads for LndAdapter<T> {
    fn availability(&self) -> ResponseFuture<'_, ReadAvailability> {
        Box::pin(async { self.watchtower_probe().await.availability.clone() })
    }
    fn read(&self, q: ReadQuery) -> ResponseFuture<'_, Result<ReadResult>> {
        Box::pin(async move {
            tokio::time::timeout(self.transport.deadline(), self.read_inner(q))
                .await
                .map_err(|_| failure(ErrorCode::NodeOffline))?
        })
    }
}

impl<T: Wire> Adapter for LndAdapter<T> {
    fn prepare<'a>(&'a self, r: &'a OperationRequest) -> ResponseFuture<'a, Result<ReadFacts>> {
        Box::pin(async move {
            tokio::time::timeout(self.transport.deadline(), self.prepare_inner(r))
                .await
                .map_err(|_| failure(ErrorCode::NodeOffline))?
        })
    }
    fn execute_once(&self, p: ClaimPermit) -> ResponseFuture<'_, Evidence> {
        Box::pin(self.execute(p))
    }
    fn observe_exact(&self, q: ObservationQuery) -> ResponseFuture<'_, Evidence> {
        Box::pin(async move {
            let fallback = Evidence {
                operation_id: q.operation_id,
                binding: q.binding.clone(),
                generation: q.generation,
                kind: q.kind,
                claim_id: q.claim_id,
                sequence: q.sequence,
                reference: q.reference.clone(),
                class: Class::Lost,
                facts: None,
            };
            tokio::time::timeout(self.transport.deadline(), self.observe(q))
                .await
                .unwrap_or(fallback)
        })
    }
}
fn mutation_rpc(r: &OperationRequest) -> Rpc {
    match r {
        OperationRequest::CreateInvoice(_) => Rpc::AddInvoice,
        OperationRequest::PayInvoice(_) => Rpc::Pay,
        OperationRequest::ConnectPeer(_) => Rpc::Connect,
        OperationRequest::DisconnectPeer(_) => Rpc::Disconnect,
        OperationRequest::OpenChannel(_) => Rpc::Open,
        OperationRequest::CloseChannel(_) => Rpc::Close,
        OperationRequest::NewAddress(_) => Rpc::Address,
        OperationRequest::SendOnchain(_) => Rpc::Send,
    }
}
fn command(p: &ClaimPermit, seconds: u64) -> Result<(Rpc, Value)> {
    let op = &p.intent.operation;
    let v = match &op.request {
        OperationRequest::CreateInvoice(r) => {
            json!({"value_msat":r.amount_msat.0.to_string(),"memo":r.description,"expiry":r.expiry_seconds.to_string(),"r_preimage":base64::engine::general_purpose::STANDARD.encode(&p.secret.as_ref().ok_or_else(reads::invalid)?[..])})
        }
        OperationRequest::PayInvoice(r) => {
            let mut v = json!({"payment_request":r.bolt11,"fee_limit_msat":r.max_fee_msat.0.to_string(),"timeout_seconds":i32::try_from(seconds).map_err(|_|reads::invalid())?});
            if let Some(amount) = r.amount_msat {
                v["amt_msat"] = json!(amount.0.to_string());
            }
            v
        }
        OperationRequest::ConnectPeer(r) => {
            json!({"addr":{"pubkey":r.pubkey,"host":op.review.destination.as_ref().ok_or_else(reads::invalid)?},"perm":false,"timeout":"0"})
        }
        OperationRequest::DisconnectPeer(r) => json!({"pub_key":r.pubkey}),
        OperationRequest::OpenChannel(r) => {
            json!({"node_pubkey":base64::engine::general_purpose::STANDARD.encode(hex::decode(&r.peer_pubkey).map_err(|_|reads::invalid())?),"local_funding_amount":r.amount_sat.0.to_string(),"sat_per_vbyte":r.fee_rate_sat_vbyte.to_string(),"private":r.private})
        }
        OperationRequest::CloseChannel(r) => {
            json!({"channel_point":p.intent.close_target.as_ref().ok_or_else(reads::invalid)?,"force":false,"sat_per_vbyte":r.fee_rate_sat_vbyte.to_string(),"no_wait":false})
        }
        OperationRequest::NewAddress(_) => json!({"type":"WITNESS_PUBKEY_HASH"}),
        OperationRequest::SendOnchain(r) => {
            json!({"addr":r.address,"amount":r.amount_sat.0.to_string(),"sat_per_vbyte":r.fee_rate_sat_vbyte.to_string(),"send_all":false})
        }
    };
    Ok((mutation_rpc(&op.request), v))
}
enum Dispatch {
    Facts(Facts),
    Failed(Rejection),
    Pending,
}
fn attempt(v: &Value) -> Result<Option<String>> {
    Ok(reads::amount(v, "payment_index")?
        .filter(|n| *n != Decimal::ZERO)
        .map(|n| format!("lnd-payment:{n}")))
}
fn dispatch(intent: &ReviewedIntent, v: &Value, r: &mut RecoveryReference) -> Result<Dispatch> {
    let op = &intent.operation;
    let facts = match &op.request {
        OperationRequest::CreateInvoice(_) => {
            let hash = reads::bytes_hash(v, "r_hash")?;
            if Some(&hash) != op.review.payment_hash.as_ref() {
                return Err(reads::invalid());
            }
            r.payment_hash = Some(hash.clone());
            Facts::Invoice {
                payment_hash: hash,
                bolt11: reads::text(v, "payment_request")?.into(),
            }
        }
        OperationRequest::PayInvoice(p) => {
            let hash = reads::hash(v, "payment_hash")?;
            if Some(&hash) != op.review.payment_hash.as_ref() {
                return Err(reads::invalid());
            }
            let new = attempt(v)?;
            if r.attempt.is_some() && r.attempt != new {
                return Err(reads::invalid());
            }
            r.attempt = new;
            match reads::text(v, "status")? {
                "FAILED" => return Ok(Dispatch::Failed(payment_rejection(v)?)),
                "INITIATED" | "IN_FLIGHT" | "SUCCEEDED" => {}
                _ => return Err(reads::invalid()),
            }
            let amount = Msat(reads::amount(v, "value_msat")?.ok_or_else(reads::invalid)?);
            let fee = reads::amount(v, "fee_msat")?.map(Msat);
            if Some(amount) != op.review.amount_msat || fee.is_some_and(|f| f > p.max_fee_msat) {
                return Err(reads::invalid());
            }
            Facts::Payment {
                payment_hash: hash,
                amount_msat: amount,
                fee_msat: fee,
                settled: reads::text(v, "status")? == "SUCCEEDED",
            }
        }
        OperationRequest::ConnectPeer(_) | OperationRequest::DisconnectPeer(_) => {
            // Handled separately below; the wire success message must be empty.
            return peer_dispatch(op, v);
        }
        OperationRequest::OpenChannel(_) => {
            let point = reads::channel_point(v)?;
            r.channel = Some(point.clone());
            Facts::Open {
                channel_id: None,
                funding_outpoint: Some(point),
                active: false,
                published: true,
            }
        }
        OperationRequest::CloseChannel(_) => {
            let txid = if v.get("close_pending").is_some() {
                reads::txid_bytes(&v["close_pending"], "txid")?
            } else if v.get("chan_close").is_some() {
                reads::txid_bytes(&v["chan_close"], "closing_txid")?
            } else {
                return Ok(Dispatch::Pending);
            };
            Facts::Close {
                channel: intent.close_target.clone().ok_or_else(reads::invalid)?,
                close_type: CloseType::Unknown,
                txids: vec![txid],
                confirmations: None,
                closed: false,
                published: true,
            }
        }
        OperationRequest::NewAddress(_) => {
            let address = reads::text(v, "address")?.to_string();
            if intent::address(&address, &op.review.node)?.address_type()
                != Some(bitcoin::AddressType::P2wpkh)
            {
                return Err(reads::invalid());
            }
            r.address = Some(address.clone());
            Facts::Address { address }
        }
        OperationRequest::SendOnchain(p) => {
            let txid = reads::hash(v, "txid")?;
            r.txid = Some(txid.clone());
            Facts::Send {
                txid,
                amount_sat: p.amount_sat,
                fee_sat: None,
                confirmations: None,
                published: true,
            }
        }
    };
    Ok(Dispatch::Facts(facts))
}
fn peer_dispatch(op: &Operation, v: &Value) -> Result<Dispatch> {
    if !v.as_object().is_some_and(|o| o.is_empty()) {
        return Err(reads::invalid());
    }
    Ok(Dispatch::Facts(Facts::Peer {
        pubkey: op.review.peer_pubkey.clone().ok_or_else(reads::invalid)?,
        connected: matches!(op.request, OperationRequest::ConnectPeer(_)),
        complete: true,
    }))
}
fn payment_rejection(v: &Value) -> Result<Rejection> {
    Ok(match reads::text(v, "failure_reason")? {
        "FAILURE_REASON_NO_ROUTE" => Rejection::NoRoute,
        "FAILURE_REASON_INSUFFICIENT_BALANCE" => Rejection::InsufficientFunds,
        _ => Rejection::Refused,
    })
}
