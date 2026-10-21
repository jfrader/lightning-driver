use super::*;
use lnd_grpc_rust::{lnrpc as ln, routerrpc as router, walletrpc as wallet};
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tonic::{
    codegen::{http, Body, Bytes, Service, StdError},
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};
use transport::{CallError, Credentials, Reply, Rpc, Wire};

// Bound raw HTTP/2 DATA across the entire unary/stream response before prost
// decoding. Tonic 0.7's per-message limit alone cannot bound a long stream.
#[derive(Clone)]
struct BoundedChannel {
    channel: Channel,
    budget: usize,
    received: Arc<AtomicUsize>,
}
struct BoundedBody<B> {
    inner: Pin<Box<B>>,
    remaining: usize,
    received: Arc<AtomicUsize>,
}
impl<B: Body<Data = Bytes>> Body for BoundedBody<B>
where
    B::Error: Into<StdError>,
{
    type Data = Bytes;
    type Error = tonic::Status;
    fn poll_data(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Bytes, Self::Error>>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_data(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                if bytes.len() > this.remaining {
                    return Poll::Ready(Some(Err(tonic::Status::unavailable(
                        "Response budget exceeded",
                    ))));
                }
                this.remaining -= bytes.len();
                this.received.fetch_add(bytes.len(), Ordering::Relaxed);
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(_))) => Poll::Ready(Some(Err(tonic::Status::unavailable(
                "Node stream unavailable",
            )))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_trailers(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<Option<http::HeaderMap>, Self::Error>> {
        self.get_mut()
            .inner
            .as_mut()
            .poll_trailers(cx)
            .map_err(|_| tonic::Status::unavailable("Node stream unavailable"))
    }
}
impl Service<http::Request<tonic::body::BoxBody>> for BoundedChannel {
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = tonic::transport::Error;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.channel.poll_ready(cx)
    }
    fn call(&mut self, req: http::Request<tonic::body::BoxBody>) -> Self::Future {
        let fut = self.channel.call(req);
        let budget = self.budget;
        let received = self.received.clone();
        Box::pin(async move {
            let response = fut.await?;
            Ok(response.map(|body| {
                BoundedBody {
                    inner: Box::pin(body),
                    remaining: budget,
                    received,
                }
                .boxed_unsync()
            }))
        })
    }
}
pub(super) struct Grpc {
    channel: Channel,
    macaroon: zeroize::Zeroizing<String>,
    deadline: Duration,
    max_bytes: usize,
}
impl Grpc {
    pub async fn connect(
        settings: &lightning_client::settings::NodeSettings,
        limits: &lightning_client::settings::Limits,
    ) -> Result<Self> {
        let c = Credentials::load(settings, limits)?;
        let channel = Endpoint::from_shared(c.endpoint.to_string())
            .map_err(|_| failure(ErrorCode::NotConfigured))?
            .connect_timeout(c.deadline)
            .timeout(c.deadline)
            .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(c.certificate)))
            .map_err(|_| failure(ErrorCode::NotConfigured))?
            .connect()
            .await
            .map_err(|_| failure(ErrorCode::NodeOffline))?;
        Ok(Self {
            channel,
            macaroon: c.macaroon,
            deadline: c.deadline,
            max_bytes: c.max_bytes,
        })
    }
    fn request<T>(&self, message: T) -> std::result::Result<tonic::Request<T>, CallError> {
        let mut req = tonic::Request::new(message);
        let mut mac = tonic::metadata::MetadataValue::try_from(self.macaroon.as_str())
            .map_err(|_| CallError::Invalid)?;
        mac.set_sensitive(true);
        req.metadata_mut().insert("macaroon", mac);
        req.set_timeout(self.deadline);
        Ok(req)
    }
    async fn invoke(
        &self,
        rpc: Rpc,
        p: Value,
        budget: usize,
        reply: &mut Reply,
    ) -> std::result::Result<(), CallError> {
        let received = Arc::new(AtomicUsize::new(0));
        let channel = BoundedChannel {
            channel: self.channel.clone(),
            budget: budget.min(self.max_bytes),
            received: received.clone(),
        };
        let mut ln = ln::lightning_client::LightningClient::new(channel.clone());
        let mut router = router::router_client::RouterClient::new(channel.clone());
        let mut wallet = wallet::wallet_kit_client::WalletKitClient::new(channel);
        macro_rules! unary {
            ($method:ident,$request:expr,$map:expr) => {{
                let response = ln
                    .$method(self.request($request)?)
                    .await
                    .map_err(|e| CallError::Status(e.code()))?
                    .into_inner();
                reply.frames.push(($map)(response));
            }};
        }
        let result: std::result::Result<(), CallError> = async {
            match rpc {
                Rpc::Info => unary!(get_info, ln::GetInfoRequest {}, project_info),
                Rpc::Wallet => unary!(wallet_balance, ln::WalletBalanceRequest::default(), project_wallet),
                Rpc::ChannelBalance => unary!(channel_balance, ln::ChannelBalanceRequest {}, project_balances),
                Rpc::Invoices => unary!(list_invoices, ln::ListInvoiceRequest {
                    num_max_invoices: u(&p, "num_max_invoices")?, reversed: true, ..Default::default()
                }, |v: ln::ListInvoiceResponse| json!({"invoices": v.invoices.into_iter().map(invoice).collect::<Vec<_>>()})),
                Rpc::LookupInvoice => unary!(lookup_invoice, ln::PaymentHash {
                    r_hash: hex::decode(s(&p, "r_hash_str")?).map_err(|_| CallError::Invalid)?, ..Default::default()
                }, invoice),
                Rpc::Payments => unary!(list_payments, ln::ListPaymentsRequest {
                    include_incomplete: true, max_payments: u(&p, "max_payments")?, reversed: true, ..Default::default()
                }, |v: ln::ListPaymentsResponse| json!({"payments": v.payments.into_iter().map(payment).collect::<Vec<_>>()})),
                Rpc::Peers => unary!(list_peers, ln::ListPeersRequest::default(), project_peers),
                Rpc::Channels => unary!(list_channels, ln::ListChannelsRequest::default(), project_channels),
                Rpc::PendingChannels => unary!(pending_channels, ln::PendingChannelsRequest { include_raw_tx: false }, pending),
                Rpc::ClosedChannels => unary!(closed_channels, ln::ClosedChannelsRequest::default(), project_closed),
                Rpc::Transactions => unary!(get_transactions, ln::GetTransactionsRequest::default(), project_transactions),
                Rpc::CheckPermissions => unary!(check_macaroon_permissions, ln::CheckMacPermRequest {
                    macaroon: hex::decode(&*self.macaroon).map_err(|_| CallError::Invalid)?,
                    full_method: s(&p, "full_method")?.into(),
                    permissions: p["permissions"].as_array().ok_or(CallError::Invalid)?.iter().map(|r| Ok(ln::MacaroonPermission {
                        entity: s(r, "entity")?.into(), action: s(r, "action")?.into()
                    })).collect::<std::result::Result<Vec<_>, CallError>>()?,
                }, |v: ln::CheckMacPermResponse| json!({"valid": v.valid})),
                Rpc::AddInvoice => unary!(add_invoice, ln::Invoice {
                    value_msat: i(&p, "value_msat")?, memo: s(&p, "memo")?.into(), expiry: i(&p, "expiry")?,
                    r_preimage: b(&p, "r_preimage")?, ..Default::default()
                }, |v: ln::AddInvoiceResponse| json!({"r_hash": base64(v.r_hash), "payment_request": v.payment_request})),
                Rpc::Connect => unary!(connect_peer, ln::ConnectPeerRequest {
                    addr: Some(ln::LightningAddress { pubkey: s(&p["addr"], "pubkey")?.into(), host: s(&p["addr"], "host")?.into() }),
                    ..Default::default()
                }, |_: ln::ConnectPeerResponse| json!({})),
                Rpc::Disconnect => unary!(disconnect_peer, ln::DisconnectPeerRequest {
                    pub_key: s(&p, "pub_key")?.into()
                }, |_: ln::DisconnectPeerResponse| json!({})),
                Rpc::Open => unary!(open_channel_sync, ln::OpenChannelRequest {
                    node_pubkey: b(&p, "node_pubkey")?, local_funding_amount: i(&p, "local_funding_amount")?,
                    sat_per_vbyte: u(&p, "sat_per_vbyte")?, private: p["private"].as_bool().ok_or(CallError::Invalid)?,
                    ..Default::default()
                }, channel_point),
                Rpc::Address => unary!(new_address, ln::NewAddressRequest {
                    r#type: ln::AddressType::WitnessPubkeyHash as i32, ..Default::default()
                }, |v: ln::NewAddressResponse| json!({"address": v.address})),
                Rpc::Send => unary!(send_coins, ln::SendCoinsRequest {
                    addr: s(&p, "addr")?.into(), amount: i(&p, "amount")?, sat_per_vbyte: u(&p, "sat_per_vbyte")?,
                    send_all: false, ..Default::default()
                }, |v: ln::SendCoinsResponse| json!({"txid": v.txid})),
                Rpc::EstimateFee => {
                    let target = p["conf_target"].as_u64().and_then(|n| i32::try_from(n).ok()).filter(|n| *n > 0).ok_or(CallError::Invalid)?;
                    let v = wallet.estimate_fee(self.request(wallet::EstimateFeeRequest { conf_target: target })?).await.map_err(|e| CallError::Status(e.code()))?.into_inner();
                    reply.frames.push(json!({"sat_per_kw": v.sat_per_kw.to_string(), "min_relay_fee_sat_per_kw": v.min_relay_fee_sat_per_kw.to_string()}));
                }
                Rpc::Pay => {
                    let request = router::SendPaymentRequest {
                        payment_request: s(&p, "payment_request")?.into(),
                        amt_msat: if p.get("amt_msat").is_some() { i(&p, "amt_msat")? } else { 0 },
                        fee_limit_msat: i(&p, "fee_limit_msat")?,
                        timeout_seconds: i32::try_from(p["timeout_seconds"].as_i64().ok_or(CallError::Invalid)?).map_err(|_| CallError::Invalid)?,
                        ..Default::default()
                    };
                    let mut stream = router.send_payment_v2(self.request(request)?).await.map_err(|e| CallError::Status(e.code()))?.into_inner();
                    while let Some(v) = stream.message().await.map_err(|e| CallError::Status(e.code()))? { reply.frames.push(payment(v)); }
                }
                Rpc::TrackPayment => {
                    let request = router::TrackPaymentRequest {
                        payment_hash: hex::decode(s(&p, "payment_hash_hex")?).map_err(|_| CallError::Invalid)?, no_inflight_updates: false
                    };
                    let mut stream = router.track_payment_v2(self.request(request)?).await.map_err(|e| CallError::Status(e.code()))?.into_inner();
                    while let Some(v) = stream.message().await.map_err(|e| CallError::Status(e.code()))? { reply.frames.push(payment(v)); }
                }
                Rpc::Close => {
                    let point = s(&p, "channel_point")?.parse::<bitcoin::OutPoint>().map_err(|_| CallError::Invalid)?;
                    let request = ln::CloseChannelRequest {
                        channel_point: Some(ln::ChannelPoint {
                            funding_txid: Some(ln::channel_point::FundingTxid::FundingTxidStr(point.txid.to_string())), output_index: point.vout
                        }),
                        force: false, no_wait: false, sat_per_vbyte: u(&p, "sat_per_vbyte")?, ..Default::default()
                    };
                    let mut stream = ln.close_channel(self.request(request)?).await.map_err(|e| CallError::Status(e.code()))?.into_inner();
                    while let Some(v) = stream.message().await.map_err(|e| CallError::Status(e.code()))? {
                        reply.frames.push(match v.update {
                            Some(ln::close_status_update::Update::ClosePending(r)) => json!({"close_pending": {"txid": base64(r.txid), "output_index": r.output_index}}),
                            Some(ln::close_status_update::Update::ChanClose(r)) => json!({"chan_close": {"closing_txid": base64(r.closing_txid), "success": r.success}}),
                            Some(ln::close_status_update::Update::CloseInstant(_)) => json!({"close_instant": {}}), None => json!({}),
                        });
                    }
                }
            }
            Ok(())
        }.await;
        reply.bytes = received.load(Ordering::Relaxed);
        result
    }
}
fn s<'a>(v: &'a Value, key: &str) -> std::result::Result<&'a str, CallError> {
    v[key].as_str().ok_or(CallError::Invalid)
}
fn u(v: &Value, key: &str) -> std::result::Result<u64, CallError> {
    s(v, key)?.parse().map_err(|_| CallError::Invalid)
}
fn i(v: &Value, key: &str) -> std::result::Result<i64, CallError> {
    s(v, key)?.parse().map_err(|_| CallError::Invalid)
}
fn b(v: &Value, key: &str) -> std::result::Result<Vec<u8>, CallError> {
    base64::engine::general_purpose::STANDARD
        .decode(s(v, key)?)
        .map_err(|_| CallError::Invalid)
}
fn base64(b: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
// Explicit ProtoJSON bridge: never serialize generated Rust messages wholesale.
// Only this allowlist reaches shared LND normalization; wire secrets/raw data do not.
fn project_info(v: ln::GetInfoResponse) -> Value {
    json!({
        "identity_pubkey": v.identity_pubkey, "alias": v.alias, "version": v.version,
        "chains": v.chains.iter().map(|c| json!({"network": c.network})).collect::<Vec<_>>(),
        "synced_to_chain": v.synced_to_chain, "synced_to_graph": v.synced_to_graph, "block_height": v.block_height
    })
}
fn project_wallet(v: ln::WalletBalanceResponse) -> Value {
    json!({
        "confirmed_balance": v.confirmed_balance.to_string(), "unconfirmed_balance": v.unconfirmed_balance.to_string(),
        "locked_balance": v.locked_balance.to_string(), "reserved_balance_anchor_chan": v.reserved_balance_anchor_chan.to_string()
    })
}
fn project_balances(v: ln::ChannelBalanceResponse) -> Value {
    json!({
        "local_balance": v.local_balance.map(|a| json!({"msat": a.msat.to_string()})),
        "remote_balance": v.remote_balance.map(|a| json!({"msat": a.msat.to_string()}))
    })
}
fn project_peers(v: ln::ListPeersResponse) -> Value {
    json!({"peers": v.peers.iter().map(|r| json!({
        "pub_key": r.pub_key, "address": r.address, "inbound": r.inbound
    })).collect::<Vec<_>>()})
}
fn project_channels(v: ln::ListChannelsResponse) -> Value {
    json!({"channels": v.channels.iter().map(|r| json!({
        "remote_pubkey": r.remote_pubkey, "channel_point": r.channel_point, "chan_id": r.chan_id.to_string(),
        "capacity": r.capacity.to_string(), "local_balance": r.local_balance.to_string(),
        "remote_balance": r.remote_balance.to_string(), "active": r.active, "private": r.private
    })).collect::<Vec<_>>()})
}
fn project_closed(v: ln::ClosedChannelsResponse) -> Value {
    json!({"channels": v.channels.iter().map(|r| json!({
        "remote_pubkey": r.remote_pubkey, "channel_point": r.channel_point, "chan_id": r.chan_id.to_string(),
        "capacity": r.capacity.to_string(), "close_type": closure_name(r.close_type), "closing_tx_hash": r.closing_tx_hash
    })).collect::<Vec<_>>()})
}
fn project_transactions(v: ln::TransactionDetails) -> Value {
    json!({"transactions": v.transactions.iter().map(|r| json!({
        "tx_hash": r.tx_hash, "amount": r.amount.to_string(), "total_fees": r.total_fees.to_string(),
        "num_confirmations": r.num_confirmations, "block_height": r.block_height, "time_stamp": r.time_stamp.to_string(),
        "output_details": r.output_details.iter().map(|o| json!({
            "output_index": o.output_index, "address": o.address, "amount": o.amount.to_string(), "is_our_address": o.is_our_address
        })).collect::<Vec<_>>()
    })).collect::<Vec<_>>()})
}
fn invoice(mut v: ln::Invoice) -> Value {
    use zeroize::Zeroize;
    v.r_preimage.zeroize();
    use ln::invoice::InvoiceState;
    let state = match InvoiceState::from_i32(v.state) {
        Some(InvoiceState::Open) => "OPEN".into(),
        Some(InvoiceState::Settled) => "SETTLED".into(),
        Some(InvoiceState::Canceled) => "CANCELED".into(),
        Some(InvoiceState::Accepted) => "ACCEPTED".into(),
        None => v.state.to_string(),
    };
    json!({
        "r_hash": base64(v.r_hash), "value_msat": v.value_msat.to_string(), "amt_paid_msat": v.amt_paid_msat.to_string(),
        "state": state, "creation_date": v.creation_date.to_string(), "settle_date": v.settle_date.to_string(),
        "expiry": v.expiry.to_string(), "payment_request": v.payment_request, "memo": v.memo
    })
}
fn payment(mut v: ln::Payment) -> Value {
    use zeroize::Zeroize;
    v.payment_preimage.zeroize();
    for h in &mut v.htlcs {
        h.preimage.zeroize();
    }
    use ln::{payment::PaymentStatus, PaymentFailureReason};
    let state = match PaymentStatus::from_i32(v.status) {
        Some(PaymentStatus::Unknown) => "UNKNOWN".into(),
        Some(PaymentStatus::InFlight) => "IN_FLIGHT".into(),
        Some(PaymentStatus::Succeeded) => "SUCCEEDED".into(),
        Some(PaymentStatus::Failed) => "FAILED".into(),
        Some(PaymentStatus::Initiated) => "INITIATED".into(),
        None => v.status.to_string(),
    };
    let reason = match PaymentFailureReason::from_i32(v.failure_reason) {
        Some(PaymentFailureReason::FailureReasonTimeout) => "FAILURE_REASON_TIMEOUT",
        Some(PaymentFailureReason::FailureReasonNoRoute) => "FAILURE_REASON_NO_ROUTE",
        Some(PaymentFailureReason::FailureReasonError) => "FAILURE_REASON_ERROR",
        Some(PaymentFailureReason::FailureReasonIncorrectPaymentDetails) => {
            "FAILURE_REASON_INCORRECT_PAYMENT_DETAILS"
        }
        Some(PaymentFailureReason::FailureReasonInsufficientBalance) => {
            "FAILURE_REASON_INSUFFICIENT_BALANCE"
        }
        Some(PaymentFailureReason::FailureReasonCanceled) => "FAILURE_REASON_CANCELED",
        _ => "FAILURE_REASON_NONE",
    };
    json!({
        "payment_hash": v.payment_hash, "value_msat": v.value_msat.to_string(), "fee_msat": v.fee_msat.to_string(),
        "creation_time_ns": v.creation_time_ns.to_string(), "payment_index": v.payment_index.to_string(),
        "status": state, "failure_reason": reason
    })
}
fn channel_point(v: ln::ChannelPoint) -> Value {
    let mut out = json!({"output_index":v.output_index});
    match v.funding_txid {
        Some(ln::channel_point::FundingTxid::FundingTxidStr(s)) => {
            out["funding_txid_str"] = json!(s)
        }
        Some(ln::channel_point::FundingTxid::FundingTxidBytes(b)) => {
            out["funding_txid_bytes"] = json!(base64(b))
        }
        None => {}
    }
    out
}
fn closure_name(n: i32) -> &'static str {
    use ln::channel_close_summary::ClosureType;
    match ClosureType::from_i32(n) {
        Some(ClosureType::CooperativeClose) => "COOPERATIVE_CLOSE",
        Some(ClosureType::LocalForceClose) => "LOCAL_FORCE_CLOSE",
        Some(ClosureType::RemoteForceClose) => "REMOTE_FORCE_CLOSE",
        Some(ClosureType::BreachClose) => "BREACH_CLOSE",
        Some(ClosureType::FundingCanceled) => "FUNDING_CANCELED",
        Some(ClosureType::Abandoned) => "ABANDONED",
        _ => "UNKNOWN",
    }
}
fn pending_channel(c: Option<ln::pending_channels_response::PendingChannel>) -> Value {
    c.map(|r| json!({
        "remote_node_pub": r.remote_node_pub, "channel_point": r.channel_point, "capacity": r.capacity.to_string(),
        "local_balance": r.local_balance.to_string(), "remote_balance": r.remote_balance.to_string(), "private": r.private
    })).unwrap_or(Value::Null)
}
#[allow(deprecated)] // The tagged pending_closing_channels list still carries lifecycle data.
fn pending(v: ln::PendingChannelsResponse) -> Value {
    json!({
        "pending_open_channels": v.pending_open_channels.into_iter().map(|r| json!({"channel": pending_channel(r.channel)})).collect::<Vec<_>>(),
        "pending_closing_channels": v.pending_closing_channels.into_iter().map(|r| json!({"channel": pending_channel(r.channel), "closing_txid": r.closing_txid})).collect::<Vec<_>>(),
        "pending_force_closing_channels": v.pending_force_closing_channels.into_iter().map(|r| json!({"channel": pending_channel(r.channel), "closing_txid": r.closing_txid})).collect::<Vec<_>>(),
        "waiting_close_channels": v.waiting_close_channels.into_iter().map(|r| json!({"channel": pending_channel(r.channel), "closing_txid": r.closing_txid})).collect::<Vec<_>>()
    })
}
impl Wire for Grpc {
    fn call<'a>(&'a self, rpc: Rpc, p: Value, budget: usize) -> ResponseFuture<'a, Reply> {
        Box::pin(async move {
            let mut reply = Reply {
                frames: vec![],
                error: None,
                bytes: 0,
            };
            if budget == 0 {
                return Reply::failed(CallError::Limit);
            }
            match tokio::time::timeout(self.deadline, self.invoke(rpc, p, budget, &mut reply)).await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => reply.error = Some(e),
                Err(_) => reply.error = Some(CallError::Offline),
            }
            reply
        })
    }
    fn deadline(&self) -> Duration {
        self.deadline
    }
    fn byte_budget(&self) -> usize {
        self.max_bytes
    }
    fn macaroon(&self) -> &str {
        &self.macaroon
    }
    fn backend(&self) -> Backend {
        Backend::LndGrpc
    }
}
