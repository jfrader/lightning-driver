use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::{service::service_fn, Body, Method, Request, Response, StatusCode};
use lightning_client::settings::NodeSettings;
use serde_json::{json, Value};
use std::{
    convert::Infallible,
    io,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};

const GENESIS: &str = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
const CREDENTIAL: &str = "__cookie__:SYNTHETIC_BITCOIN_ONLY";
const MAX_REQUEST_BYTES: u64 = 4096;
#[derive(Clone, Debug, Default)]
pub enum BitcoinFault {
    #[default]
    None,
    Auth,
    Rpc500,
    Oversized(usize),
    ChunkedOversized(usize),
    WrongId,
    Redirect,
}
pub struct BitcoinScenario {
    pub ibd: bool,
    pub pruned: bool,
    pub wrong_genesis: bool,
    pub legacy_warnings: bool,
    pub fault: BitcoinFault,
    pub fault_method: Option<String>,
    pub calls: Vec<String>,
    pub wallet_sentinel_calls: usize,
    credential: String,
}
impl Default for BitcoinScenario {
    fn default() -> Self {
        Self {
            ibd: false,
            pruned: false,
            wrong_genesis: false,
            legacy_warnings: false,
            fault: BitcoinFault::None,
            fault_method: None,
            calls: vec![],
            wallet_sentinel_calls: 0,
            credential: CREDENTIAL.into(),
        }
    }
}
pub struct BitcoinHarness {
    directory: tempfile::TempDir,
    address: std::net::SocketAddr,
    task: JoinHandle<()>,
    pub scenario: Arc<Mutex<BitcoinScenario>>,
}
impl BitcoinHarness {
    pub async fn start() -> io::Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("bitcoin-synthetic-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp/opencode")?;
        let credential = directory.path().join("cookie");
        std::fs::write(&credential, CREDENTIAL)?;
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600))?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let scenario = Arc::new(Mutex::new(BitcoinScenario::default()));
        let state = scenario.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((socket,_)) = accepted else { break };
                        if connections.len() >= 64 { continue; }
                        let state = state.clone();
                        connections.spawn(async move {
                            let service = service_fn(move |request| serve(request,state.clone()));
                            let _ = hyper::server::conn::Http::new().http1_only(true).serve_connection(socket,service).await;
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Ok(Self {
            directory,
            address,
            task,
            scenario,
        })
    }
    pub fn settings(&self) -> NodeSettings {
        serde_json::from_value(json!({"id":"bitcoin-lab","label":"Synthetic Bitcoin Core","backend":"bitcoin_rpc",
            "endpoint":format!("http://{}/",self.address),"certificate_file":self.directory.path().join("unused"),
            "credential_file":self.directory.path().join("cookie"),"expected_genesis":GENESIS,"network":"regtest"})).unwrap()
    }
    pub fn rotate_cookie(&self) -> io::Result<()> {
        let value = "__cookie__:SYNTHETIC_ROTATED_COOKIE";
        let path = self.directory.path().join("rotated");
        std::fs::write(&path, value)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(path, self.directory.path().join("cookie"))?;
        self.scenario.lock().unwrap().credential = value.into();
        Ok(())
    }
}
impl Drop for BitcoinHarness {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn serve(
    request: Request<Body>,
    state: Arc<Mutex<BitcoinScenario>>,
) -> Result<Response<Body>, Infallible> {
    use hyper::body::HttpBody;
    let response = |status, body| {
        Response::builder()
            .status(status)
            .body(Body::from(body))
            .unwrap()
    };
    if request.method() != Method::POST || request.uri().path() != "/" {
        return Ok(response(StatusCode::NOT_FOUND, String::new()));
    }
    let auth = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let mut body = request.into_body();
    if body
        .size_hint()
        .upper()
        .is_some_and(|n| n > MAX_REQUEST_BYTES)
    {
        return Ok(response(StatusCode::PAYLOAD_TOO_LARGE, String::new()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else {
            return Ok(response(StatusCode::BAD_REQUEST, String::new()));
        };
        if chunk.len() as u64 > MAX_REQUEST_BYTES.saturating_sub(bytes.len() as u64) {
            return Ok(response(StatusCode::PAYLOAD_TOO_LARGE, String::new()));
        }
        bytes.extend_from_slice(&chunk);
    }
    let Ok(call) = serde_json::from_slice::<Value>(&bytes) else {
        return Ok(response(StatusCode::BAD_REQUEST, String::new()));
    };
    let mut state = state.lock().unwrap();
    let method = call["method"].as_str().unwrap_or("");
    state.calls.push(method.into());
    let fault_applies = state
        .fault_method
        .as_deref()
        .is_none_or(|target| target == method);
    if auth != format!("Basic {}", STANDARD.encode(&state.credential))
        || (fault_applies && matches!(state.fault, BitcoinFault::Auth))
    {
        return Ok(response(StatusCode::UNAUTHORIZED, String::new()));
    }
    if call["jsonrpc"] != "1.0" || !call["params"].is_array() {
        return Ok(response(StatusCode::BAD_REQUEST, String::new()));
    }
    if fault_applies {
        match state.fault {
            BitcoinFault::Rpc500 => return Ok(response(StatusCode::INTERNAL_SERVER_ERROR,json!({"id":call["id"],"result":null,"error":{"code":-13,"message":"Synthetic denied"}}).to_string())),
            BitcoinFault::Oversized(size) => return Ok(response(StatusCode::OK," ".repeat(size))),
            BitcoinFault::ChunkedOversized(size) => {
                let (mut sender, body) = Body::channel();
                tokio::spawn(async move {
                    let mut remaining = size;
                    while remaining > 0 {
                        let bytes = vec![b' '; remaining.min(1024)];
                        remaining -= bytes.len();
                        if sender.send_data(bytes.into()).await.is_err() { break; }
                    }
                });
                return Ok(Response::new(body));
            }
            BitcoinFault::Redirect => return Ok(Response::builder().status(StatusCode::TEMPORARY_REDIRECT).header("location","/wallet/loaded").body(Body::empty()).unwrap()),
            _ => {}
        }
    }
    let result = match method {
        "getblockhash" if call["params"] == json!([0]) => json!(if state.wrong_genesis {
            "ab".repeat(32)
        } else {
            GENESIS.into()
        }),
        "getblockchaininfo" => {
            json!({"chain":"regtest","blocks":200,"headers":if state.ibd {400} else {200},"bestblockhash":"ab".repeat(32),
            "verificationprogress":if state.ibd {0.5} else {1.0},"initialblockdownload":state.ibd,"pruned":state.pruned,
            "size_on_disk":123456,"warnings":if state.legacy_warnings {json!("Chain warning")} else {json!(["Chain warning"])} })
        }
        "getnetworkinfo" => {
            json!({"version":290000,"subversion":"/Satoshi:29.0.0/","connections":1,
            "warnings":if state.legacy_warnings {json!("Network warning")} else {json!(["Network warning"])} })
        }
        "getmempoolinfo" => json!({"size":2,"bytes":300,"usage":500}),
        "uptime" => json!(1200),
        "getpeerinfo" => json!([{"id":0,"addr":"127.0.0.1:18444","network":"ipv4","inbound":false,
            "connection_type":"outbound-full-relay","version":70016,"subver":"/Satoshi:29.0.0/","pingtime":0.012,
            "conntime":1760000000,"bytessent":100,"bytesrecv":200}]),
        _ => {
            state.wallet_sentinel_calls += 1;
            return Ok(response(StatusCode::INTERNAL_SERVER_ERROR,json!({"id":call["id"],"result":null,"error":{"code":-32601,"message":"Loaded wallet sentinel"}}).to_string()));
        }
    };
    let mut result = result;
    if method == "getblockchaininfo" && state.pruned {
        result["pruneheight"] = json!(100);
    }
    let id = if fault_applies && matches!(state.fault, BitcoinFault::WrongId) {
        json!("wrong")
    } else {
        call["id"].clone()
    };
    Ok(response(
        StatusCode::OK,
        json!({"id":id,"error":null,"result":result}).to_string(),
    ))
}
