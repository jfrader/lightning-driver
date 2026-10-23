use super::*;
use lightning_client::settings::{read_protected, Limits, NodeSettings};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    redirect::Policy,
    Client, StatusCode,
};
use std::time::Duration;

#[derive(Clone, Copy)]
pub(super) enum Rpc {
    GetInfo,
    ListFunds,
    ListInvoices,
    ListPays,
    ListPeers,
    ListPeerChannels,
    ListClosedChannels,
    ListTransactions,
    FeeRates,
    CheckRune,
    Invoice,
    XPay,
    Connect,
    Disconnect,
    FundChannel,
    Close,
    NewAddr,
    Withdraw,
}
impl Rpc {
    fn method(self) -> &'static str {
        match self {
            Self::GetInfo => "getinfo",
            Self::ListFunds => "listfunds",
            Self::ListInvoices => "listinvoices",
            Self::ListPays => "listpays",
            Self::ListPeers => "listpeers",
            Self::ListPeerChannels => "listpeerchannels",
            Self::ListClosedChannels => "listclosedchannels",
            Self::ListTransactions => "listtransactions",
            Self::FeeRates => "feerates",
            Self::CheckRune => "checkrune",
            Self::Invoice => "invoice",
            Self::XPay => "xpay",
            Self::Connect => "connect",
            Self::Disconnect => "disconnect",
            Self::FundChannel => "fundchannel",
            Self::Close => "close",
            Self::NewAddr => "newaddr",
            Self::Withdraw => "withdraw",
        }
    }
}
#[derive(Debug)]
pub(super) enum CallError {
    Offline,
    Limit,
    Invalid,
    Rpc { status: u16, code: Option<i64> },
}
impl CallError {
    pub fn read_code(&self) -> ErrorCode {
        match self {
            Self::Offline | Self::Limit => ErrorCode::NodeOffline,
            Self::Invalid => ErrorCode::UpstreamInvalidResponse,
            Self::Rpc {
                status: 401 | 403, ..
            } => ErrorCode::NodeAuthError,
            // A rune refused the method: checkrune answers 500 with CLN's not-permitted code.
            Self::Rpc {
                code: Some(1501..=1503),
                ..
            } => ErrorCode::NodeAuthError,
            Self::Rpc {
                status: 404,
                code: Some(-32601),
            } => ErrorCode::Unsupported,
            Self::Rpc {
                status: 500,
                code: Some(-32602),
            } => ErrorCode::UpstreamRejected,
            _ => ErrorCode::NodeOffline,
        }
    }
    pub fn mutation_class(&self, rpc: Rpc) -> Class {
        use Rejection::*;
        let rejection = match self {
            Self::Rpc {
                status: 403,
                code: Some(1501),
            }
            | Self::Rpc {
                status: 401,
                code: Some(1501..=1503),
            } => Some(Auth),
            Self::Rpc {
                status: 404,
                code: Some(-32601),
            } => Some(Unsupported),
            Self::Rpc {
                status: 500,
                code: Some(-32602),
            } => Some(Refused),
            Self::Rpc {
                status: 500,
                code: Some(900 | 901),
            } if matches!(rpc, Rpc::Invoice) => Some(Conflict),
            Self::Rpc {
                status: 500,
                code: Some(400..=402),
            } if matches!(rpc, Rpc::Connect) => Some(PeerUnavailable),
            // Tagged xpay.c checks expiry before preapproval and routing starts.
            Self::Rpc {
                status: 500,
                code: Some(207),
            } if matches!(rpc, Rpc::XPay) => Some(Expired),
            // Tagged withdraw schema explicitly says errors create no transaction.
            Self::Rpc {
                status: 500,
                code: Some(301),
            } if matches!(rpc, Rpc::Withdraw) => Some(InsufficientFunds),
            Self::Rpc {
                status: 500,
                code: Some(-1 | 302 | 313),
            } if matches!(rpc, Rpc::Withdraw) => Some(Refused),
            Self::Rpc {
                status: 500,
                code: Some(-1 | 902),
            } if matches!(rpc, Rpc::Invoice) => Some(Refused),
            // Other xpay errors do not establish pre-execution refusal here.
            // In particular, an old-group error or PAY_IN_PROGRESS never releases a claim.
            _ => None,
        };
        match rejection {
            Some(r) => Class::Rejected(r),
            None if matches!(self, Self::Invalid) => Class::Partial,
            None => Class::Lost,
        }
    }
}

pub(super) struct Transport {
    client: Client,
    endpoint: url::Url,
    rune: zeroize::Zeroizing<String>,
    max_bytes: usize,
    timeout: Duration,
}
impl Transport {
    pub fn connect(settings: &NodeSettings, limits: &Limits) -> Result<Self> {
        let endpoint = &settings.endpoint;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || limits.rpc_seconds == 0
            || limits.max_response_bytes == 0
            || limits.pagination.snapshot_max_items == 0
        {
            return Err(failure(ErrorCode::NotConfigured));
        }
        let certificate = read_protected(
            settings
                .certificate_file
                .as_deref()
                .ok_or_else(|| failure(ErrorCode::NotConfigured))?,
            false,
        )
        .map_err(|_| failure(ErrorCode::NotConfigured))?;
        let certificate = reqwest::Certificate::from_pem(&certificate)
            .map_err(|_| failure(ErrorCode::NotConfigured))?;
        let bytes = zeroize::Zeroizing::new(
            read_protected(&settings.credential_file, true)
                .map_err(|_| failure(ErrorCode::NotConfigured))?,
        );
        let rune = zeroize::Zeroizing::new(
            std::str::from_utf8(&bytes)
                .map_err(|_| failure(ErrorCode::NotConfigured))?
                .trim_end_matches(['\r', '\n'])
                .to_owned(),
        );
        let client = Self::builder(limits)
            .https_only(true)
            .tls_built_in_root_certs(false)
            .add_root_certificate(certificate)
            .build()
            .map_err(|_| failure(ErrorCode::NotConfigured))?;
        Self::new(client, endpoint.clone(), rune, limits)
    }
    fn builder(limits: &Limits) -> reqwest::ClientBuilder {
        Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(u64::from(limits.rpc_seconds)))
    }
    fn new(
        client: Client,
        endpoint: url::Url,
        rune: zeroize::Zeroizing<String>,
        limits: &Limits,
    ) -> Result<Self> {
        if rune.is_empty() || rune.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(failure(ErrorCode::NotConfigured));
        }
        HeaderValue::from_str(&rune).map_err(|_| failure(ErrorCode::NotConfigured))?;
        Ok(Self {
            client,
            endpoint,
            rune,
            max_bytes: limits.max_response_bytes,
            timeout: Duration::from_secs(u64::from(limits.rpc_seconds)),
        })
    }
    pub fn deadline(&self) -> Duration {
        self.timeout
    }
    pub async fn check_permission(
        &self,
        rpc: Rpc,
        params: Value,
    ) -> std::result::Result<bool, CallError> {
        let value = self
            .call(
                Rpc::CheckRune,
                json!({"rune":&*self.rune,"method":rpc.method(),"params":params}),
            )
            .await?;
        value
            .get("valid")
            .and_then(Value::as_bool)
            .ok_or(CallError::Invalid)
    }
    pub async fn call(&self, rpc: Rpc, params: Value) -> std::result::Result<Value, CallError> {
        self.call_sized(rpc, params, self.max_bytes)
            .await
            .map(|(value, _)| value)
    }
    pub fn byte_budget(&self) -> usize {
        self.max_bytes
    }
    pub async fn call_sized(
        &self,
        rpc: Rpc,
        params: Value,
        budget: usize,
    ) -> std::result::Result<(Value, usize), CallError> {
        let budget = budget.min(self.max_bytes);
        if budget == 0 {
            return Err(CallError::Offline);
        }
        let mut headers = HeaderMap::new();
        let mut rune = HeaderValue::from_str(&self.rune).map_err(|_| CallError::Invalid)?;
        rune.set_sensitive(true);
        headers.insert("Rune", rune);
        let url = self
            .endpoint
            .join(&format!("v1/{}", rpc.method()))
            .map_err(|_| CallError::Invalid)?;
        let mut response = self
            .client
            .post(url)
            .headers(headers)
            .json(&params)
            .send()
            .await
            .map_err(|_| CallError::Offline)?;
        let status = response.status();
        if status.is_redirection() {
            return Err(CallError::Offline);
        }
        if response.content_length().is_some_and(|n| n > budget as u64) {
            return Err(CallError::Limit);
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| CallError::Offline)? {
            if chunk.len() > budget.saturating_sub(bytes.len()) {
                return Err(CallError::Limit);
            }
            bytes.extend_from_slice(&chunk);
        }
        if status != StatusCode::CREATED {
            #[derive(Deserialize)]
            struct RpcError {
                code: Option<i64>,
            }
            let error =
                serde_json::from_slice::<RpcError>(&bytes).map_err(|_| CallError::Invalid)?;
            return Err(CallError::Rpc {
                status: status.as_u16(),
                code: error.code,
            });
        }
        let result: Value = serde_json::from_slice(&bytes).map_err(|_| CallError::Invalid)?;
        if !result.is_object() || result.get("result").is_some() || result.get("error").is_some() {
            return Err(CallError::Invalid);
        }
        Ok((result, bytes.len()))
    }
    #[cfg(test)]
    pub fn synthetic(endpoint: url::Url, limits: &Limits) -> Self {
        Self::new(
            Self::builder(limits).build().unwrap(),
            endpoint,
            zeroize::Zeroizing::new("SYNTHETIC_RUNE_CANARY".into()),
            limits,
        )
        .unwrap()
    }
}
