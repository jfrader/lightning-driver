use super::*;
use lightning_client::settings::{read_protected, Limits, NodeSettings};
use reqwest::{header::HeaderValue, redirect::Policy};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Rpc {
    Info,
    Wallet,
    ChannelBalance,
    Invoices,
    LookupInvoice,
    Payments,
    TrackPayment,
    Peers,
    Channels,
    PendingChannels,
    ClosedChannels,
    Transactions,
    CheckPermissions,
    AddInvoice,
    Pay,
    Connect,
    Disconnect,
    Open,
    Close,
    Address,
    Send,
    EstimateFee,
    TowerInfo,
    TowerStats,
    TowerPolicy,
    Towers,
    Tower,
}
impl Rpc {
    pub fn streamed(self) -> bool {
        matches!(self, Self::Pay | Self::TrackPayment | Self::Close)
    }
    pub fn method(self) -> &'static str {
        match self {
            Self::Info => "/lnrpc.Lightning/GetInfo",
            Self::Wallet => "/lnrpc.Lightning/WalletBalance",
            Self::ChannelBalance => "/lnrpc.Lightning/ChannelBalance",
            Self::Invoices => "/lnrpc.Lightning/ListInvoices",
            Self::LookupInvoice => "/lnrpc.Lightning/LookupInvoice",
            Self::Payments => "/lnrpc.Lightning/ListPayments",
            Self::TrackPayment => "/routerrpc.Router/TrackPaymentV2",
            Self::Peers => "/lnrpc.Lightning/ListPeers",
            Self::Channels => "/lnrpc.Lightning/ListChannels",
            Self::PendingChannels => "/lnrpc.Lightning/PendingChannels",
            Self::ClosedChannels => "/lnrpc.Lightning/ClosedChannels",
            Self::Transactions => "/lnrpc.Lightning/GetTransactions",
            Self::CheckPermissions => "/lnrpc.Lightning/CheckMacaroonPermissions",
            Self::AddInvoice => "/lnrpc.Lightning/AddInvoice",
            Self::Pay => "/routerrpc.Router/SendPaymentV2",
            Self::Connect => "/lnrpc.Lightning/ConnectPeer",
            Self::Disconnect => "/lnrpc.Lightning/DisconnectPeer",
            Self::Open => "/lnrpc.Lightning/OpenChannelSync",
            Self::Close => "/lnrpc.Lightning/CloseChannel",
            Self::Address => "/lnrpc.Lightning/NewAddress",
            Self::Send => "/lnrpc.Lightning/SendCoins",
            Self::EstimateFee => "/walletrpc.WalletKit/EstimateFee",
            Self::TowerInfo => "/watchtowerrpc.Watchtower/GetInfo",
            Self::TowerStats => "/wtclientrpc.WatchtowerClient/Stats",
            Self::TowerPolicy => "/wtclientrpc.WatchtowerClient/Policy",
            Self::Towers => "/wtclientrpc.WatchtowerClient/ListTowers",
            Self::Tower => "/wtclientrpc.WatchtowerClient/GetTowerInfo",
        }
    }
    pub fn permissions(self) -> Vec<Value> {
        let entities: &[&str] = match self {
            Self::AddInvoice => &["invoices"],
            Self::Pay => &["offchain"],
            Self::Connect | Self::Disconnect => &["peers"],
            Self::Open | Self::Close => &["onchain", "offchain"],
            Self::Address => &["address"],
            Self::Send => &["onchain"],
            _ => &[],
        };
        entities
            .iter()
            .map(|e| json!({"entity":e,"action":"write"}))
            .collect()
    }
    fn route(self, p: &Value) -> std::result::Result<(reqwest::Method, String), CallError> {
        use reqwest::Method;
        let get = Method::GET;
        let post = Method::POST;
        let required = |key| p.get(key).and_then(Value::as_str).ok_or(CallError::Invalid);
        Ok(match self {
            Self::Info => (get, "v1/getinfo".into()),
            Self::Wallet => (get, "v1/balance/blockchain".into()),
            Self::ChannelBalance => (get, "v1/balance/channels".into()),
            Self::Invoices => (get, "v1/invoices".into()),
            Self::LookupInvoice => (get, format!("v1/invoice/{}", required("r_hash_str")?)),
            Self::Payments => (get, "v1/payments".into()),
            Self::TrackPayment => (
                get,
                format!(
                    "v2/router/track/{}",
                    base64::engine::general_purpose::URL_SAFE.encode(
                        hex::decode(required("payment_hash_hex")?)
                            .map_err(|_| CallError::Invalid)?
                    )
                ),
            ),
            Self::Peers => (get, "v1/peers".into()),
            Self::Channels => (get, "v1/channels".into()),
            Self::PendingChannels => (get, "v1/channels/pending".into()),
            Self::ClosedChannels => (get, "v1/channels/closed".into()),
            Self::Transactions => (get, "v1/transactions".into()),
            Self::TowerInfo => (get, "v2/watchtower/server".into()),
            Self::TowerStats => (get, "v2/watchtower/client/stats".into()),
            Self::TowerPolicy => (get, "v2/watchtower/client/policy".into()),
            Self::Towers => (get, "v2/watchtower/client".into()),
            Self::Tower => (
                get,
                format!(
                    "v2/watchtower/client/info/{}",
                    base64::engine::general_purpose::URL_SAFE.encode(
                        base64::engine::general_purpose::STANDARD
                            .decode(required("pubkey")?)
                            .map_err(|_| CallError::Invalid)?
                    )
                ),
            ),
            Self::CheckPermissions => (post, "v1/macaroon/checkpermissions".into()),
            Self::AddInvoice => (post, "v1/invoices".into()),
            Self::Pay => (post, "v2/router/send".into()),
            Self::Connect => (post, "v1/peers".into()),
            Self::Disconnect => (Method::DELETE, format!("v1/peers/{}", required("pub_key")?)),
            Self::Open => (post, "v1/channels".into()),
            Self::Close => {
                let point = required("channel_point")?
                    .parse::<bitcoin::OutPoint>()
                    .map_err(|_| CallError::Invalid)?;
                (
                    Method::DELETE,
                    format!("v1/channels/{}/{}", point.txid, point.vout),
                )
            }
            Self::Address => (get, "v1/newaddress".into()),
            Self::Send => (post, "v1/transactions".into()),
            Self::EstimateFee => (
                get,
                format!(
                    "v2/wallet/estimatefee/{}",
                    p.get("conf_target")
                        .and_then(Value::as_u64)
                        .filter(|n| *n > 0 && *n <= i32::MAX as u64)
                        .ok_or(CallError::Invalid)?
                ),
            ),
        })
    }
}
#[derive(Clone, Copy, Debug)]
pub(super) enum CallError {
    Inactive,
    UnregisteredPolicy,
    Offline,
    Limit,
    Invalid,
    Status(tonic::Code),
}
impl CallError {
    pub fn status(rpc: Rpc, code: tonic::Code, message: &str) -> Self {
        if matches!(
            rpc,
            Rpc::TowerInfo | Rpc::TowerStats | Rpc::TowerPolicy | Rpc::Towers | Rpc::Tower
        ) && code == tonic::Code::Unknown
        {
            // LND's macaroon bakery may return a plain error (gRPC Unknown).
            if message == "permission denied" {
                return Self::Status(tonic::Code::PermissionDenied);
            }
            if matches!(
                message,
                "watchtower not active" | "watchtower client not active"
            ) {
                return Self::Inactive;
            }
            if rpc == Rpc::TowerPolicy && message == "no client for the given blob type" {
                return Self::UnregisteredPolicy;
            }
        }
        Self::Status(code)
    }
    pub fn read_code(self) -> ErrorCode {
        match self {
            Self::Inactive => ErrorCode::NotConfigured,
            Self::UnregisteredPolicy => ErrorCode::UpstreamRejected,
            Self::Invalid => ErrorCode::UpstreamInvalidResponse,
            Self::Status(tonic::Code::PermissionDenied | tonic::Code::Unauthenticated) => {
                ErrorCode::NodeAuthError
            }
            Self::Status(tonic::Code::NotFound) => ErrorCode::NotFound,
            Self::Status(tonic::Code::ResourceExhausted) => ErrorCode::RateLimited,
            Self::Status(tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition) => {
                ErrorCode::UpstreamRejected
            }
            Self::Status(tonic::Code::Unimplemented) => ErrorCode::Unsupported,
            _ => ErrorCode::NodeOffline,
        }
    }
    pub fn mutation_class(self) -> Class {
        match self {
            Self::Invalid => Class::Partial,
            Self::Status(tonic::Code::PermissionDenied | tonic::Code::Unauthenticated) => {
                Class::Rejected(Rejection::Auth)
            }
            Self::Status(tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition) => {
                Class::Rejected(Rejection::Refused)
            }
            _ => Class::Lost,
        }
    }
}
pub(super) struct Reply {
    pub frames: Vec<Value>,
    pub error: Option<CallError>,
    pub bytes: usize,
}
impl Reply {
    pub fn failed(e: CallError) -> Self {
        Self {
            frames: vec![],
            error: Some(e),
            bytes: 0,
        }
    }
    pub fn unary(self) -> Result<(Value, usize)> {
        if let Some(e) = self.error {
            return Err(failure(e.read_code()));
        }
        if self.frames.len() != 1 {
            return Err(reads::invalid());
        }
        Ok((
            self.frames.into_iter().next().ok_or_else(reads::invalid)?,
            self.bytes,
        ))
    }
}
pub(super) trait Wire: Send + Sync {
    fn call<'a>(&'a self, rpc: Rpc, params: Value, budget: usize) -> ResponseFuture<'a, Reply>;
    fn deadline(&self) -> Duration;
    fn byte_budget(&self) -> usize;
    fn macaroon(&self) -> &str;
    fn backend(&self) -> Backend;
}
pub(super) struct Credentials {
    pub certificate: Vec<u8>,
    pub macaroon: zeroize::Zeroizing<String>,
    pub endpoint: url::Url,
    pub deadline: Duration,
    pub max_bytes: usize,
}
impl Credentials {
    pub fn load(settings: &NodeSettings, limits: &Limits) -> Result<Self> {
        let u = &settings.endpoint;
        if u.scheme() != "https"
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
            || u.path() != "/"
            || limits.rpc_seconds == 0
            || limits.rpc_seconds > i32::MAX as u32
            || limits.max_response_bytes == 0
            || limits.pagination.snapshot_max_items == 0
        {
            return Err(failure(ErrorCode::NotConfigured));
        }
        let certificate = read_protected(&settings.certificate_file, false)
            .map_err(|_| failure(ErrorCode::NotConfigured))?;
        let bytes = zeroize::Zeroizing::new(
            read_protected(&settings.credential_file, true)
                .map_err(|_| failure(ErrorCode::NotConfigured))?,
        );
        if bytes.is_empty() || certificate.is_empty() {
            return Err(failure(ErrorCode::NotConfigured));
        }
        Ok(Self {
            certificate,
            macaroon: zeroize::Zeroizing::new(hex::encode(&*bytes)),
            endpoint: u.clone(),
            deadline: Duration::from_secs(u64::from(limits.rpc_seconds)),
            max_bytes: limits.max_response_bytes,
        })
    }
}
pub(super) struct Rest {
    client: reqwest::Client,
    endpoint: url::Url,
    macaroon: zeroize::Zeroizing<String>,
    deadline: Duration,
    max_bytes: usize,
}
impl Rest {
    pub fn connect(settings: &NodeSettings, limits: &Limits) -> Result<Self> {
        let c = Credentials::load(settings, limits)?;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(c.deadline)
            .https_only(true)
            .tls_built_in_root_certs(false);
        let client = match settings.tls_verification {
            lightning_client::settings::TlsVerification::Ca => client.add_root_certificate(
                reqwest::Certificate::from_pem(&c.certificate)
                    .map_err(|_| failure(ErrorCode::NotConfigured))?,
            ),
            lightning_client::settings::TlsVerification::Pinned => {
                client.use_preconfigured_tls(super::tls::pinned_config(&c.certificate)?)
            }
        }
        .build()
        .map_err(|_| failure(ErrorCode::NotConfigured))?;
        Ok(Self {
            client,
            endpoint: c.endpoint,
            macaroon: c.macaroon,
            deadline: c.deadline,
            max_bytes: c.max_bytes,
        })
    }
    async fn request(&self, rpc: Rpc, mut params: Value, budget: usize) -> Reply {
        let mut reply = Reply {
            frames: vec![],
            error: None,
            bytes: 0,
        };
        let result = self
            .request_inner(rpc, &mut params, budget, &mut reply)
            .await;
        if let Err(e) = result {
            reply.error = Some(e);
        }
        reply
    }
    async fn request_inner(
        &self,
        rpc: Rpc,
        p: &mut Value,
        budget: usize,
        reply: &mut Reply,
    ) -> std::result::Result<(), CallError> {
        let budget = budget.min(self.max_bytes);
        if budget == 0 {
            return Err(CallError::Limit);
        }
        let (method, path) = rpc.route(p)?;
        let url = self.endpoint.join(&path).map_err(|_| CallError::Invalid)?;
        let mut header = HeaderValue::from_str(&self.macaroon).map_err(|_| CallError::Invalid)?;
        header.set_sensitive(true);
        let mut req = self
            .client
            .request(method.clone(), url)
            .header("Grpc-Metadata-macaroon", header);
        // Path-only fields never become a body, particularly cooperative DELETE.
        if let Some(obj) = p.as_object_mut() {
            if rpc == Rpc::Disconnect {
                obj.remove("pub_key");
            }
            if rpc == Rpc::Tower {
                obj.remove("pubkey");
            }
            // LND's REST gateway accepts the protobuf JSON name for this field only.
            if rpc == Rpc::CheckPermissions {
                if let Some(value) = obj.remove("full_method") {
                    obj.insert("fullMethod".into(), value);
                }
            }
            for key in [
                "channel_point",
                "payment_hash_hex",
                "r_hash_str",
                "conf_target",
            ] {
                obj.remove(key);
            }
        }
        if method == reqwest::Method::POST {
            req = req.json(p);
        } else {
            let query: Vec<_> = p
                .as_object()
                .ok_or(CallError::Invalid)?
                .iter()
                .map(|(k, v)| {
                    let value = match v {
                        Value::String(s) => s.clone(),
                        _ => v.to_string(),
                    };
                    (k.clone(), value)
                })
                .collect();
            req = req.query(&query);
        }
        let mut response = req.send().await.map_err(|_| CallError::Offline)?;
        let status = response.status();
        if status.is_redirection() {
            return Err(CallError::Offline);
        }
        let success = matches!(status.as_u16(), 200 | 201);
        if response.content_length().is_some_and(|n| n > budget as u64) {
            return Err(CallError::Limit);
        }
        let mut buffer = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| CallError::Offline)? {
            if chunk.len() > budget.saturating_sub(reply.bytes) {
                return Err(CallError::Limit);
            }
            reply.bytes += chunk.len();
            buffer.extend_from_slice(&chunk);
            if rpc.streamed() && success {
                while let Some(pos) = buffer.iter().position(|b| *b == b'\n') {
                    let frame: Value =
                        serde_json::from_slice(&buffer[..pos]).map_err(|_| CallError::Invalid)?;
                    parse_frame(frame, reply)?;
                    buffer.drain(..=pos);
                }
            }
        }
        if !success {
            let v: Value = serde_json::from_slice(&buffer).map_err(|_| CallError::Invalid)?;
            let error = status_error(&v)?;
            return Err(match error {
                CallError::Status(code) => {
                    CallError::status(rpc, code, v["message"].as_str().unwrap_or_default())
                }
                error => error,
            });
        }
        if rpc.streamed() {
            if !buffer.is_empty() {
                parse_frame(
                    serde_json::from_slice(&buffer).map_err(|_| CallError::Invalid)?,
                    reply,
                )?;
            }
            if reply.frames.is_empty() {
                return Err(CallError::Invalid);
            }
        } else {
            let v: Value = serde_json::from_slice(&buffer).map_err(|_| CallError::Invalid)?;
            if !v.is_object() || v.get("error").is_some() || v.get("result").is_some() {
                return Err(CallError::Invalid);
            }
            reply.frames.push(v);
        }
        Ok(())
    }
}
fn status_error(v: &Value) -> std::result::Result<CallError, CallError> {
    let code = v
        .get("code")
        .and_then(Value::as_i64)
        .and_then(|c| i32::try_from(c).ok())
        .filter(|c| (1..=16).contains(c))
        .ok_or(CallError::Invalid)?;
    Ok(CallError::Status(tonic::Code::from_i32(code)))
}
fn parse_frame(v: Value, reply: &mut Reply) -> std::result::Result<(), CallError> {
    if let Some(e) = v.get("error") {
        return Err(status_error(e)?);
    }
    let value = v
        .get("result")
        .filter(|v| v.is_object())
        .ok_or(CallError::Invalid)?;
    reply.frames.push(value.clone());
    Ok(())
}
impl Wire for Rest {
    fn call<'a>(&'a self, rpc: Rpc, p: Value, budget: usize) -> ResponseFuture<'a, Reply> {
        Box::pin(self.request(rpc, p, budget))
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
        Backend::LndRest
    }
}
