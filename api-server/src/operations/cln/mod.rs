mod reads;
#[cfg(test)]
mod tests;
mod transport;

use super::*;
use evidence::{Class, Facts, Rejection};
use lightning_client::money::{Decimal, Msat};
use serde_json::{json, Value};
use transport::{Rpc, Transport};

enum ObservedFacts {
    Positive(Facts),
    Rejected(Rejection),
}

// Only the operation engine can obtain this adapter or construct its claim permit.
pub(super) struct ClnAdapter {
    transport: Transport,
    config: NodeConfig,
    max_items: usize,
}
impl ClnAdapter {
    pub async fn connect(
        settings: &lightning_client::settings::NodeSettings,
        limits: &lightning_client::settings::Limits,
        config: NodeConfig,
    ) -> Result<Self> {
        if settings.backend != Backend::ClnRest
            || config.backend != Backend::ClnRest
            || settings.id != config.binding.node_id
            || settings.expected_pubkey.as_deref() != Some(config.binding.identity_pubkey.as_str())
            || settings.network != intent::network(&config.binding)
        {
            return Err(failure(ErrorCode::NotConfigured));
        }
        let adapter = Self {
            transport: Transport::connect(settings, limits)?,
            config,
            max_items: limits.pagination.snapshot_max_items,
        };
        Ok(adapter)
    }

    async fn call(&self, rpc: Rpc, params: Value) -> Result<Value> {
        self.transport
            .call(rpc, params)
            .await
            .map_err(|e| failure(e.read_code()))
    }

    async fn info(&self) -> Result<InfoObservation> {
        let info = reads::info(&self.call(Rpc::GetInfo, json!({})).await?)?;
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
            status: NodeStatus {
                node_id: self.config.binding.node_id.clone(),
                status: NodeConnection::Online,
                synced_to_chain: info.synced,
                synced_to_graph: None,
                block_height: info.height,
                observed_at: Some(now),
                checked_at: now,
                stale: false,
                error_code: None,
            },
            alias: info.alias,
            version: info.version,
        })
    }

    async fn inventory(&self) -> Result<Collection<Channel>> {
        let open = self.call(Rpc::ListPeerChannels, json!({})).await?;
        let closed = self.call(Rpc::ListClosedChannels, json!({})).await?;
        reads::channels(&open, &closed, self.max_items)
    }

    async fn read_inner(&self, query: ReadQuery) -> Result<ReadResult> {
        // The outer deadline includes discovery plus all exact-hash enrichment calls.
        let info = self.info().await?;
        let now = Utc::now();
        let node = &self.config.binding.node_id;
        Ok(match query {
            ReadQuery::Info => ReadResult::Info(info),
            ReadQuery::Balances => ReadResult::Balances(reads::balances(
                &self.call(Rpc::ListFunds, json!({})).await?,
                node,
                intent::network(&self.config.binding),
                now,
                self.max_items,
            )?),
            ReadQuery::Invoices => ReadResult::Invoices(reads::invoices(
                &self.call(Rpc::ListInvoices, json!({})).await?,
                self.max_items,
            )?),
            ReadQuery::Payments => {
                let mut budget = self.transport.byte_budget();
                let (discovery, bytes) = self
                    .transport
                    .call_sized(Rpc::ListPays, json!({}), budget)
                    .await
                    .map_err(|e| failure(e.read_code()))?;
                budget -= bytes;
                let rows = reads::array(&discovery, "pays")?;
                if rows.len() > self.max_items {
                    return Err(failure(ErrorCode::NodeOffline));
                }
                let hashes = rows
                    .iter()
                    .map(|row| reads::hash(row, "payment_hash"))
                    .collect::<Result<std::collections::BTreeSet<_>>>()?;
                let mut items = Vec::new();
                let mut truncated = false;
                for hash in hashes {
                    let (exact, bytes) = self
                        .transport
                        .call_sized(Rpc::ListPays, json!({"payment_hash":hash}), budget)
                        .await
                        .map_err(|e| failure(e.read_code()))?;
                    budget -= bytes;
                    if reads::array(&exact, "pays")?
                        .iter()
                        .any(|r| r["payment_hash"] != hash)
                    {
                        return Err(failure(ErrorCode::UpstreamInvalidResponse));
                    }
                    let projected = reads::payments(&exact, self.max_items)?;
                    truncated |= projected.truncated || projected.items.is_empty();
                    items.extend(projected.items);
                }
                reads::sort_payments(&mut items);
                ReadResult::Payments(Collection { items, truncated })
            }
            ReadQuery::Peers => ReadResult::Peers(reads::peers(
                &self.call(Rpc::ListPeers, json!({})).await?,
                self.max_items,
            )?),
            ReadQuery::Channels => ReadResult::Channels(self.inventory().await?),
            ReadQuery::Transactions => ReadResult::Transactions(reads::transactions(
                &self.call(Rpc::ListTransactions, json!({})).await?,
                self.max_items,
            )?),
            ReadQuery::Fees => {
                let value = self.call(Rpc::FeeRates, json!({"style":"perkb"})).await?;
                reads::fees(&value, node, now).map(ReadResult::Fees)?
            }
        })
    }

    async fn prepare_inner(&self, request: &OperationRequest) -> Result<ReadFacts> {
        let info = self.info().await?;
        let mut facts = ReadFacts {
            binding: self.config.binding.clone(),
            generation: self.config.generation,
            observed_at: info.status.checked_at,
            connection: NodeConnection::Online,
            sync_usable: info.status.synced_to_chain == Some(true),
            // A method-only check is insufficient for param-restricted runes. The REST
            // gate checks the actual command again immediately before its one invocation.
            permission: false,
            peer_connected: false,
            close_target: None,
            close_peer: None,
        };
        if let OperationRequest::OpenChannel(p) = request {
            let peers = reads::peers(
                &self
                    .call(Rpc::ListPeers, json!({"id":p.peer_pubkey}))
                    .await?,
                self.max_items,
            )?;
            facts.peer_connected = !peers.truncated
                && peers
                    .items
                    .iter()
                    .any(|peer| peer.pubkey == p.peer_pubkey && peer.connected);
        }
        if let OperationRequest::CloseChannel(p) = request {
            let channels = self.inventory().await?;
            if !channels.truncated {
                if let Some(channel) = channels.items.iter().find(|c| {
                    c.id == p.channel_id || c.funding_outpoint.as_ref() == Some(&p.channel_id)
                }) {
                    // `close` takes a peer id, short channel id or channel id; a funding
                    // outpoint such as `txid:0` is rejected with -32602. `Channel::id` is
                    // the CLN channel id when the node reports one.
                    facts.close_target = Some(channel.id.clone());
                    facts.close_peer = Some(channel.peer_pubkey.clone());
                }
            }
        }
        // Exact parameter permission is checked by prepare_review, after the
        // operation-derived invoice label and canonical close target exist.
        Ok(facts)
    }

    async fn execute(&self, permit: ClaimPermit) -> Evidence {
        let operation = &permit.intent.operation;
        let mut evidence = Evidence {
            operation_id: operation.id,
            binding: operation.review.node.clone(),
            generation: permit.intent.connection_generation,
            kind: operation.request.kind(),
            claim_id: permit.claim_id,
            sequence: 0,
            reference: RecoveryReference::planned(&permit.intent),
            class: Class::Lost,
            facts: None,
        };
        if evidence.binding != self.config.binding || evidence.generation != self.config.generation
        {
            evidence.class = Class::Conflict;
            return evidence;
        }
        let command = command(
            &operation.request,
            permit.intent.invoice_label.as_deref(),
            permit.intent.close_target.as_deref(),
        );
        let (rpc, params) = match command {
            Ok(command) => command,
            Err(_) => {
                evidence.class = Class::Partial;
                return evidence;
            }
        };
        match self.transport.call(rpc, params).await {
            Ok(value) => match dispatch_facts(&permit.intent, &value, &mut evidence.reference) {
                Ok(facts) => {
                    evidence.class = Class::Positive;
                    evidence.facts = Some(facts);
                }
                Err(_) => evidence.class = Class::Partial,
            },
            Err(error) => evidence.class = error.mutation_class(rpc),
        }
        evidence
    }

    async fn observe(&self, query: ObservationQuery) -> Evidence {
        let close_type = query.close_type;
        let close_txids = query.close_txids;
        let mut evidence = Evidence {
            operation_id: query.operation_id,
            binding: query.binding,
            generation: query.generation,
            kind: query.kind,
            claim_id: query.claim_id,
            sequence: query.sequence,
            reference: query.reference,
            class: Class::NotFound,
            facts: None,
        };
        if evidence.binding != self.config.binding || evidence.generation != self.config.generation
        {
            evidence.class = Class::Conflict;
            return evidence;
        }
        if self.info().await.is_err() {
            evidence.class = Class::Lost;
            return evidence;
        }
        match self
            .observe_facts(&evidence, close_type, &close_txids)
            .await
        {
            Ok(Some(ObservedFacts::Positive(facts))) => {
                evidence.class = Class::Positive;
                evidence.facts = Some(facts);
            }
            Ok(None) => {}
            Ok(Some(ObservedFacts::Rejected(rejection))) => {
                evidence.class = Class::Rejected(rejection);
            }
            Err(_) => evidence.class = Class::Lost,
        }
        evidence
    }

    async fn observe_facts(
        &self,
        evidence: &Evidence,
        close_type: Option<CloseType>,
        close_txids: &[String],
    ) -> Result<Option<ObservedFacts>> {
        let r = &evidence.reference;
        match evidence.kind {
            OperationKind::CreateInvoice => {
                let Some(label) = &r.invoice_label else {
                    return Ok(None);
                };
                let value = self.call(Rpc::ListInvoices, json!({"label":label})).await?;
                let rows = reads::array(&value, "invoices")?;
                if rows.len() != 1 || rows[0]["label"] != *label {
                    return Ok(None);
                }
                let hash = reads::hash(&rows[0], "payment_hash")?;
                if r.payment_hash.as_ref().is_some_and(|h| h != &hash) {
                    return Ok(None);
                }
                let bolt11 = reads::text(&rows[0], "bolt11")?.to_string();
                Ok(Some(ObservedFacts::Positive(Facts::Invoice {
                    payment_hash: hash,
                    bolt11,
                })))
            }
            OperationKind::PayInvoice => {
                let Some(hash) = &r.payment_hash else {
                    return Ok(None);
                };
                let value = self
                    .call(Rpc::ListPays, json!({"payment_hash":hash}))
                    .await?;
                let projected = reads::payments(&value, self.max_items)?;
                // listpays has no invocation/group token from xpay. Do not attribute
                // old settlements or failures to this claim, even for the same hash.
                let _ = projected;
                Ok(None)
            }
            OperationKind::ConnectPeer | OperationKind::DisconnectPeer => {
                let Some(peer) = &r.peer else { return Ok(None) };
                let value = self.call(Rpc::ListPeers, json!({"id":peer})).await?;
                let peers = reads::peers(&value, self.max_items)?;
                if peers.truncated || peers.items.iter().any(|p| &p.pubkey != peer) {
                    return Ok(None);
                }
                let connected = peers
                    .items
                    .iter()
                    .find(|p| &p.pubkey == peer)
                    .map(|p| p.connected)
                    .unwrap_or(false);
                if connected != (evidence.kind == OperationKind::ConnectPeer) {
                    return Ok(None);
                }
                Ok(Some(ObservedFacts::Positive(Facts::Peer {
                    pubkey: peer.clone(),
                    connected,
                    complete: true,
                })))
            }
            OperationKind::OpenChannel | OperationKind::CloseChannel => {
                let Some(reference) = &r.channel else {
                    return Ok(None);
                };
                let open = self.call(Rpc::ListPeerChannels, json!({})).await?;
                let closed = self.call(Rpc::ListClosedChannels, json!({})).await?;
                let channels = reads::channels(&open, &closed, self.max_items)?;
                let Some(channel) = channels
                    .items
                    .iter()
                    .find(|c| &c.id == reference || c.funding_outpoint.as_ref() == Some(reference))
                else {
                    return Ok(None);
                };
                // Only an exact, forgotten closed channel whose funding was
                // explicitly withheld proves an abandoned open. Absence, age,
                // ONCHAIN alone, and close_cause alone cannot exclude a prior
                // successful opening. Older CLN versions without this fact stay
                // unknown. Never infer failure from a peer/capacity match.
                if evidence.kind == OperationKind::OpenChannel
                    && channel.state == ChannelState::Closed
                    && reads::array(&closed, "closedchannels")?.iter().any(|row| {
                        let exact_id = row.get("channel_id").and_then(Value::as_str)
                            == Some(reference.as_str());
                        let exact_outpoint = row
                            .get("funding_txid")
                            .and_then(Value::as_str)
                            .zip(row.get("funding_outnum").and_then(Value::as_u64))
                            .is_some_and(|(txid, outnum)| format!("{txid}:{outnum}") == *reference);
                        (exact_id || exact_outpoint)
                            && row.get("funding_withheld").and_then(Value::as_bool) == Some(true)
                    })
                {
                    return Ok(Some(ObservedFacts::Rejected(Rejection::Refused)));
                }
                if evidence.kind == OperationKind::OpenChannel {
                    if channel.state != ChannelState::Active
                        && channel.state != ChannelState::Opening
                    {
                        return Ok(None);
                    }
                    Ok(Some(ObservedFacts::Positive(Facts::Open {
                        channel_id: Some(channel.id.clone()),
                        funding_outpoint: channel.funding_outpoint.clone(),
                        active: channel.state == ChannelState::Active,
                        published: true,
                    })))
                } else {
                    // A prior mutual response does not rule out later unilateral
                    // negotiation failure. Only the same closing transaction in
                    // closed history can carry that stored type into completion.
                    let linked = reads::array(&closed, "closedchannels")?.iter().any(|row| {
                        let exact = row.get("channel_id").and_then(Value::as_str)
                            == Some(channel.id.as_str());
                        exact
                            && row
                                .get("last_commitment_txid")
                                .and_then(Value::as_str)
                                .is_some_and(|txid| close_txids.iter().any(|known| known == txid))
                    });
                    Ok(Some(ObservedFacts::Positive(Facts::Close {
                        channel: reference.clone(),
                        close_type: if linked {
                            close_type.unwrap_or(CloseType::Unknown)
                        } else {
                            CloseType::Unknown
                        },
                        txids: vec![],
                        confirmations: None,
                        closed: channel.state == ChannelState::Closed,
                        published: false,
                    })))
                }
            }
            // CLN transactions cannot prove the reviewed wallet-net send semantics;
            // an address derivation cannot be recovered by issuing another newaddr.
            OperationKind::SendOnchain => {
                let Some(txid) = &r.txid else { return Ok(None) };
                let value = self.call(Rpc::ListTransactions, json!({})).await?;
                let transactions = reads::transactions(&value, self.max_items)?;
                let _exact = transactions.items.iter().find(|tx| &tx.txid == txid);
                Ok(None)
            }
            OperationKind::NewAddress => Ok(None),
        }
    }
}
impl Adapter for ClnAdapter {
    fn read(&self, query: ReadQuery) -> ResponseFuture<'_, Result<ReadResult>> {
        Box::pin(async move {
            tokio::time::timeout(self.transport.deadline(), self.read_inner(query))
                .await
                .map_err(|_| failure(ErrorCode::NodeOffline))?
        })
    }
    fn prepare<'a>(
        &'a self,
        request: &'a OperationRequest,
    ) -> ResponseFuture<'a, Result<ReadFacts>> {
        Box::pin(async move {
            tokio::time::timeout(self.transport.deadline(), self.prepare_inner(request))
                .await
                .map_err(|_| failure(ErrorCode::NodeOffline))?
        })
    }
    fn execute_once(&self, permit: ClaimPermit) -> ResponseFuture<'_, Evidence> {
        Box::pin(self.execute(permit))
    }
    fn prepare_review<'a>(
        &'a self,
        operation: &'a Operation,
    ) -> ResponseFuture<'a, Result<ReadFacts>> {
        Box::pin(async move {
            tokio::time::timeout(self.transport.deadline(), async {
                let mut facts = self.prepare_inner(&operation.request).await?;
                if operation.review.node != self.config.binding {
                    return Err(failure(ErrorCode::IdentityChanged));
                }
                let label = format!("ld-{}", operation.id);
                let (rpc, params) = command(
                    &operation.request,
                    Some(&label),
                    facts.close_target.as_deref(),
                )?;
                facts.permission = self
                    .transport
                    .check_permission(rpc, params)
                    .await
                    .map_err(|e| failure(e.read_code()))?;
                Ok(facts)
            })
            .await
            .map_err(|_| failure(ErrorCode::NodeOffline))?
        })
    }
    fn observe_exact(&self, query: ObservationQuery) -> ResponseFuture<'_, Evidence> {
        Box::pin(async move {
            let fallback = Evidence {
                operation_id: query.operation_id,
                binding: query.binding.clone(),
                generation: query.generation,
                kind: query.kind,
                claim_id: query.claim_id,
                sequence: query.sequence,
                reference: query.reference.clone(),
                class: Class::Lost,
                facts: None,
            };
            tokio::time::timeout(self.transport.deadline(), self.observe(query))
                .await
                .unwrap_or(fallback)
        })
    }
}

fn feerate(rate: Decimal) -> Result<String> {
    let perkb = rate
        .positive()
        .and_then(|r| r.checked_mul(1000))
        .map_err(|_| failure(ErrorCode::InvalidAmount))?;
    u32::try_from(perkb.get()).map_err(|_| failure(ErrorCode::InvalidAmount))?;
    Ok(format!("{perkb}perkb"))
}
fn command(
    request: &OperationRequest,
    label: Option<&str>,
    close_target: Option<&str>,
) -> Result<(Rpc, Value)> {
    Ok(match request {
        OperationRequest::CreateInvoice(p) => (
            Rpc::Invoice,
            json!({"amount_msat":p.amount_msat.0.get(),"label":label.ok_or_else(||failure(ErrorCode::InternalError))?,"description":p.description,"expiry":p.expiry_seconds}),
        ),
        OperationRequest::PayInvoice(p) => {
            let mut value = json!({"invstring":p.bolt11,"maxfee":p.max_fee_msat.0.get()});
            if let Some(amount) = p.amount_msat {
                value["amount_msat"] = json!(amount.0.get());
            }
            (Rpc::XPay, value)
        }
        OperationRequest::ConnectPeer(p) => (
            Rpc::Connect,
            json!({"id":p.pubkey,"host":p.host,"port":p.port}),
        ),
        OperationRequest::DisconnectPeer(p) => (Rpc::Disconnect, json!({"id":p.pubkey})),
        OperationRequest::OpenChannel(p) => (
            Rpc::FundChannel,
            json!({"id":p.peer_pubkey,"amount":p.amount_sat.0.get(),"feerate":feerate(p.fee_rate_sat_vbyte)?,"announce":!p.private}),
        ),
        OperationRequest::CloseChannel(p) => {
            let _ = p;
            (
                Rpc::Close,
                // Cooperative by default: CLN treats `unilateraltimeout: 0` as "force close
                // now", which broadcasts our commitment and leaves the channel onchain for
                // the CSV delay. Omitting it keeps the fee-negotiated close and its 48-hour
                // force fallback; a peer that never answers ends at the RPC deadline.
                json!({"id":close_target.ok_or_else(||failure(ErrorCode::NotFound))?}),
            )
        }
        OperationRequest::NewAddress(_) => (Rpc::NewAddr, json!({"addresstype":"bech32"})),
        OperationRequest::SendOnchain(p) => (
            Rpc::Withdraw,
            json!({"destination":p.address,"satoshi":p.amount_sat.0.get(),"feerate":feerate(p.fee_rate_sat_vbyte)?}),
        ),
    })
}

fn dispatch_facts(
    intent: &ReviewedIntent,
    value: &Value,
    reference: &mut RecoveryReference,
) -> Result<Facts> {
    let invalid = || failure(ErrorCode::UpstreamInvalidResponse);
    let op = &intent.operation;
    Ok(match &op.request {
        OperationRequest::CreateInvoice(_) => {
            let hash = reads::hash(value, "payment_hash")?;
            if op.review.payment_hash.as_ref().is_some_and(|h| h != &hash) {
                return Err(invalid());
            }
            reads::required_time(value, "expires_at")?;
            let bolt11 = reads::text(value, "bolt11")?.to_string();
            reference.payment_hash = Some(hash.clone());
            Facts::Invoice {
                payment_hash: hash,
                bolt11,
            }
        }
        OperationRequest::PayInvoice(p) => {
            use sha2::Digest;
            let preimage = zeroize::Zeroizing::new(
                hex::decode(reads::text(value, "payment_preimage")?).map_err(|_| invalid())?,
            );
            let hash = hex::encode(sha2::Sha256::digest(&preimage[..]));
            if preimage.len() != 32 || Some(&hash) != op.review.payment_hash.as_ref() {
                return Err(invalid());
            }
            let amount = reads::amount(value, "amount_msat")?.ok_or_else(invalid)?;
            let sent = reads::amount(value, "amount_sent_msat")?.ok_or_else(invalid)?;
            let fee = sent.checked_sub(amount).map_err(|_| invalid())?;
            if Some(Msat(amount)) != op.review.amount_msat || Msat(fee) > p.max_fee_msat {
                return Err(invalid());
            }
            if reads::uint(value, "successful_parts")?.is_none_or(|n| n == 0)
                || reads::uint(value, "failed_parts")?.is_none()
            {
                return Err(invalid());
            }
            Facts::Payment {
                payment_hash: hash,
                amount_msat: Msat(amount),
                fee_msat: Some(Msat(fee)),
                settled: true,
            }
        }
        OperationRequest::ConnectPeer(p) => {
            if reads::pubkey(value, "id")? != p.pubkey {
                return Err(invalid());
            }
            Facts::Peer {
                pubkey: p.pubkey.clone(),
                connected: true,
                complete: true,
            }
        }
        OperationRequest::DisconnectPeer(p) => {
            if !value.as_object().is_some_and(|object| object.is_empty()) {
                return Err(invalid());
            }
            Facts::Peer {
                pubkey: p.pubkey.clone(),
                connected: false,
                complete: true,
            }
        }
        OperationRequest::OpenChannel(_) => {
            let txid = reads::txid(value, "txid")?;
            let outnum = reads::uint(value, "outnum")?
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(invalid)?;
            let channel = reads::hash(value, "channel_id")?;
            let point = format!("{txid}:{outnum}");
            reference.channel = Some(point.clone());
            Facts::Open {
                channel_id: Some(channel),
                funding_outpoint: Some(point),
                active: false,
                published: true,
            }
        }
        OperationRequest::CloseChannel(_) => {
            let close_type = match reads::text(value, "type")? {
                "mutual" => CloseType::Cooperative,
                "unilateral" => CloseType::Unilateral,
                "unopened" => CloseType::Unknown,
                _ => return Err(invalid()),
            };
            let mut txids = Vec::new();
            if close_type != CloseType::Unknown {
                for tx in reads::array(value, "txids")? {
                    txids.push(reads::txid(&json!({"txid":tx}), "txid")?);
                }
                if txids.is_empty() || txids.len() > 64 {
                    return Err(invalid());
                }
            }
            txids.sort();
            txids.dedup();
            // A returned close transaction is publication, not a closed channel.
            Facts::Close {
                channel: intent.close_target.clone().ok_or_else(invalid)?,
                close_type,
                txids: txids.clone(),
                confirmations: None,
                closed: false,
                published: !txids.is_empty(),
            }
        }
        OperationRequest::NewAddress(_) => {
            let address = reads::text(value, "bech32")?.to_string();
            if intent::address(&address, &op.review.node)?.address_type()
                != Some(bitcoin::AddressType::P2wpkh)
            {
                return Err(invalid());
            }
            reference.address = Some(address.clone());
            Facts::Address { address }
        }
        OperationRequest::SendOnchain(p) => {
            let txid = reads::txid(value, "txid")?;
            reference.txid = Some(txid.clone());
            Facts::Send {
                txid,
                amount_sat: p.amount_sat,
                fee_sat: None,
                confirmations: None,
                published: true,
            }
        }
    })
}
