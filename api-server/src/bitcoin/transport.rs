use crate::operations::{failure, Result};
use lightning_client::{
    model::ErrorCode,
    settings::{read_protected, Limits, NodeSettings, TlsVerification},
};
use serde_json::{json, Value};
use std::{
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::Duration,
};

// There is deliberately no arbitrary method or params entry point, including wallet RPCs.
#[derive(Clone, Copy)]
pub(super) enum Rpc {
    Blockchain,
    Network,
    Mempool,
    Peers,
    Uptime,
    Genesis,
}
impl Rpc {
    fn request(self, id: u64) -> Value {
        let (method, params) = match self {
            Self::Blockchain => ("getblockchaininfo", json!([])),
            Self::Network => ("getnetworkinfo", json!([])),
            Self::Mempool => ("getmempoolinfo", json!([])),
            Self::Peers => ("getpeerinfo", json!([])),
            Self::Uptime => ("uptime", json!([])),
            Self::Genesis => ("getblockhash", json!([0])),
        };
        json!({"jsonrpc":"1.0", "id":id, "method":method, "params":params})
    }
}

type Stamp = (u64, i64, i64, i64, i64);
struct Credential {
    stamp: Stamp,
    value: zeroize::Zeroizing<String>,
}
pub(super) struct Transport {
    client: reqwest::Client,
    endpoint: url::Url,
    credential_file: PathBuf,
    credential: Mutex<Option<Credential>>,
    max_bytes: usize,
    next_id: AtomicU64,
}
impl Transport {
    pub async fn connect(node: &NodeSettings, limits: &Limits) -> Result<Self> {
        let invalid = || failure(ErrorCode::NotConfigured);
        let endpoint = &node.endpoint;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || limits.max_response_bytes == 0
            || limits.rpc_seconds == 0
        {
            return Err(invalid());
        }
        let deadline = Duration::from_secs(u64::from(limits.rpc_seconds));
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(deadline);
        if endpoint.scheme() == "http" {
            let host = endpoint
                .host_str()
                .ok_or_else(invalid)?
                .trim_matches(['[', ']']);
            let port = endpoint.port_or_known_default().ok_or_else(invalid)?;
            let addresses: Vec<_> =
                tokio::time::timeout(deadline, tokio::net::lookup_host((host, port)))
                    .await
                    .map_err(|_| invalid())?
                    .map_err(|_| invalid())?
                    .collect();
            if addresses.is_empty() || addresses.iter().any(|address| !address.ip().is_loopback()) {
                return Err(invalid());
            }
            // Pin the checked resolution: a second DNS lookup must not bypass the loopback check.
            builder = builder.resolve_to_addrs(host, &addresses);
        } else {
            let certificate =
                read_protected(&node.certificate_file, false).map_err(|_| invalid())?;
            builder = builder.https_only(true).tls_built_in_root_certs(false);
            builder = match node.tls_verification {
                TlsVerification::Ca => builder.add_root_certificate(
                    reqwest::Certificate::from_pem(&certificate).map_err(|_| invalid())?,
                ),
                TlsVerification::Pinned => builder.use_preconfigured_tls(
                    crate::operations::lnd::tls::pinned_config(&certificate)?,
                ),
            };
        }
        let transport = Self {
            client: builder.build().map_err(|_| invalid())?,
            endpoint: endpoint.clone(),
            credential_file: node.credential_file.clone(),
            credential: Mutex::new(None),
            max_bytes: limits.max_response_bytes,
            next_id: AtomicU64::new(1),
        };
        transport.credentials()?;
        Ok(transport)
    }
    fn credentials(&self) -> Result<zeroize::Zeroizing<String>> {
        let invalid = || failure(ErrorCode::NotConfigured);
        let meta = std::fs::symlink_metadata(&self.credential_file).map_err(|_| invalid())?;
        let stamp = (
            meta.ino(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
        );
        let mut cache = self.credential.lock().map_err(|_| invalid())?;
        if cache
            .as_ref()
            .is_none_or(|credential| credential.stamp != stamp)
        {
            let bytes = zeroize::Zeroizing::new(
                read_protected(&self.credential_file, true).map_err(|_| invalid())?,
            );
            let value = zeroize::Zeroizing::new(
                std::str::from_utf8(&bytes)
                    .map_err(|_| invalid())?
                    .trim_end_matches(['\r', '\n'])
                    .to_owned(),
            );
            let (user, password) = value.split_once(':').ok_or_else(invalid)?;
            if user.is_empty() || password.is_empty() || value.contains(['\r', '\n']) {
                return Err(invalid());
            }
            *cache = Some(Credential { stamp, value });
        }
        Ok(cache.as_ref().ok_or_else(invalid)?.value.clone())
    }
    pub async fn call(&self, rpc: Rpc) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let credential = self.credentials()?;
        let (user, password) = credential
            .split_once(':')
            .ok_or_else(|| failure(ErrorCode::NotConfigured))?;
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .basic_auth(user, Some(password))
            .json(&rpc.request(id))
            .send()
            .await
            .map_err(|_| failure(ErrorCode::NodeOffline))?;
        let status = response.status();
        if status.is_redirection() {
            return Err(failure(ErrorCode::NodeOffline));
        }
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(failure(ErrorCode::NodeAuthError));
        }
        let invalid = || failure(ErrorCode::UpstreamInvalidResponse);
        if response
            .content_length()
            .is_some_and(|size| size > self.max_bytes as u64)
        {
            return Err(invalid());
        }
        let mut body = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| failure(ErrorCode::NodeOffline))?
        {
            if chunk.len() > self.max_bytes.saturating_sub(body.len()) {
                return Err(invalid());
            }
            body.extend_from_slice(&chunk);
        }
        let envelope: Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
        if envelope.get("id") != Some(&json!(id)) {
            return Err(invalid());
        }
        let error = envelope.get("error").ok_or_else(invalid)?;
        if !error.is_null() {
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .ok_or_else(invalid)?;
            return Err(failure(match code {
                -13 | -14 => ErrorCode::NodeAuthError,
                -32601 => ErrorCode::Unsupported,
                _ => ErrorCode::UpstreamRejected,
            }));
        }
        if !status.is_success() {
            return Err(invalid());
        }
        envelope.get("result").cloned().ok_or_else(invalid)
    }
}
