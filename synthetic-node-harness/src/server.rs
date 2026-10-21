use crate::{
    grpc,
    scenario::{MACAROON, RUNE},
    Fault, Scenario, PEER,
};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use chrono::{DateTime, Utc};
use hyper::{service::service_fn, Body, Method, Request, Response, StatusCode};
use lightning_client::{model::Backend, settings::NodeSettings};
use serde_json::{json, Value};
use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{
    rustls::{Certificate, PrivateKey, ServerConfig},
    TlsAcceptor,
};

const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_CONNECTIONS: usize = 64;
const LOST_RESPONSE_DELAY: Duration = Duration::from_secs(5);

pub struct Harness {
    directory: tempfile::TempDir,
    address: SocketAddr,
    backend: Backend,
    task: JoinHandle<()>,
    pub scenario: Arc<Mutex<Scenario>>,
}
impl Harness {
    /// The executable additionally requires an acknowledgement flag. This library
    /// is linked only by tests or explicitly opted-in synthetic tooling.
    pub async fn start(
        backend: Backend,
        bind: SocketAddr,
        seed: u8,
        now: DateTime<Utc>,
    ) -> io::Result<Self> {
        if !bind.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic listeners require loopback",
            ));
        }
        let directory = tempfile::Builder::new()
            .prefix("lightning-synthetic-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp/opencode")?;
        certificates(directory.path())?;
        write_private(&directory.path().join("rune"), RUNE.as_bytes())?;
        write_private(&directory.path().join("macaroon"), MACAROON)?;
        let cert = std::fs::read(directory.path().join("leaf.der"))?;
        let key = std::fs::read(directory.path().join("leaf-key.der"))?;
        let mut tls = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![Certificate(cert)], PrivateKey(key))
            .map_err(io::Error::other)?;
        let is_grpc = backend == Backend::LndGrpc;
        tls.alpn_protocols = if is_grpc {
            vec![b"h2".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind(bind).await?;
        let address = listener.local_addr()?;
        let scenario = Arc::new(Mutex::new(Scenario::new(seed, now)));
        let state = scenario.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((socket, peer)) = accepted else {break};
                        if !peer.ip().is_loopback() || connections.len() >= MAX_CONNECTIONS {continue;}
                        let acceptor = acceptor.clone(); let state = state.clone();
                        connections.spawn(async move {
                            let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(2), acceptor.accept(socket)).await else {return};
                            let service = service_fn(move |request| serve(request, backend, state.clone()));
                            let mut http = hyper::server::conn::Http::new(); http.http2_only(is_grpc);
                            let _ = tokio::time::timeout(Duration::from_secs(60),http.serve_connection(tls,service)).await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Ok(Self {
            directory,
            address,
            backend,
            task,
            scenario,
        })
    }
    pub fn directory(&self) -> &Path {
        self.directory.path()
    }
    pub fn node(&self, id: &str) -> NodeSettings {
        serde_json::from_value(self.node_configuration(id)).expect("synthetic settings")
    }
    pub fn node_configuration(&self, id: &str) -> Value {
        let examples: Value = serde_json::from_str(include_str!(
            "../../api-server/tests/fixtures/api-examples.json"
        ))
        .expect("frozen example fixture");
        let policy: lightning_client::settings::NodePolicy =
            serde_json::from_value(examples["fixtures"]["node_policy"]["value"].clone())
                .expect("fixture policy");
        json!({"id":id,"label":format!("Synthetic {id}"),"backend":self.backend,"endpoint":format!("https://localhost:{}/",self.address.port()),"certificate_file":self.directory.path().join("ca.pem"),"credential_file":self.directory.path().join(if self.backend == Backend::ClnRest {"rune"} else {"macaroon"}),"expected_pubkey":PEER,"network":"regtest","read_only":false,"policy":policy.limits,"peer_policy":{"allowed_hosts":["peer.example.invalid"],"allowed_ports":[9735]}})
    }
    pub async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)
}
fn openssl(directory: &Path, args: &[&str]) -> io::Result<()> {
    let status = Command::new("openssl")
        .current_dir(directory)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("synthetic TLS generation failed"))
    }
}
fn certificates(d: &Path) -> io::Result<()> {
    write_private(&d.join("extensions"),b"subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")?;
    openssl(
        d,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca-key.pem",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Synthetic development CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
    )?;
    openssl(
        d,
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "leaf-key.pem",
            "-out",
            "leaf.csr",
            "-subj",
            "/CN=localhost",
        ],
    )?;
    openssl(
        d,
        &[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca-key.pem",
            "-CAcreateserial",
            "-out",
            "leaf.pem",
            "-days",
            "1",
            "-extfile",
            "extensions",
        ],
    )?;
    openssl(
        d,
        &[
            "x509", "-in", "leaf.pem", "-outform", "DER", "-out", "leaf.der",
        ],
    )?;
    openssl(
        d,
        &[
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            "leaf-key.pem",
            "-outform",
            "DER",
            "-out",
            "leaf-key.der",
        ],
    )?;
    for entry in std::fs::read_dir(d)? {
        std::fs::set_permissions(entry?.path(), std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn route(method: &Method, path: &str) -> Option<&'static str> {
    Some(match (method, path) {
        (&Method::GET, "/v1/getinfo") => "GetInfo",
        (&Method::GET, "/v1/balance/blockchain") => "WalletBalance",
        (&Method::GET, "/v1/balance/channels") => "ChannelBalance",
        (&Method::GET, "/v1/invoices") => "ListInvoices",
        (&Method::POST, "/v1/invoices") => "AddInvoice",
        (&Method::GET, "/v1/payments") => "ListPayments",
        (&Method::POST, "/v2/router/send") => "SendPaymentV2",
        (&Method::GET, "/v1/peers") => "ListPeers",
        (&Method::POST, "/v1/peers") => "ConnectPeer",
        (&Method::GET, "/v1/channels") => "ListChannels",
        (&Method::POST, "/v1/channels") => "OpenChannelSync",
        (&Method::GET, "/v1/channels/pending") => "PendingChannels",
        (&Method::GET, "/v1/channels/closed") => "ClosedChannels",
        (&Method::GET, "/v1/transactions") => "GetTransactions",
        (&Method::POST, "/v1/transactions") => "SendCoins",
        (&Method::GET, "/v1/newaddress") => "NewAddress",
        (&Method::POST, "/v1/macaroon/checkpermissions") => "CheckMacaroonPermissions",
        (&Method::GET, p) if p.starts_with("/v1/invoice/") => "LookupInvoice",
        (&Method::GET, p) if p.starts_with("/v2/router/track/") => "TrackPaymentV2",
        (&Method::GET, p) if p.starts_with("/v2/wallet/estimatefee/") => "EstimateFee",
        (&Method::DELETE, p) if p.starts_with("/v1/peers/") => "DisconnectPeer",
        (&Method::DELETE, p) if p.starts_with("/v1/channels/") => "CloseChannel",
        _ => return None,
    })
}
async fn serve(
    mut request: Request<Body>,
    backend: Backend,
    state: Arc<Mutex<Scenario>>,
) -> Result<Response<Body>, Infallible> {
    use hyper::body::HttpBody;
    let grpc = backend == Backend::LndGrpc;
    let cln = backend == Backend::ClnRest;
    let credential = if cln {
        RUNE.into()
    } else {
        hex::encode(MACAROON)
    };
    let header = if cln {
        "rune"
    } else if grpc {
        "macaroon"
    } else {
        "grpc-metadata-macaroon"
    };
    if request.headers().get(header).and_then(|h| h.to_str().ok()) != Some(&credential) {
        return Ok(error(grpc, cln, 7));
    }
    let path = request.uri().path().to_owned();
    let method = if grpc {
        path.rsplit('/').next()
    } else if cln && request.method() == Method::POST {
        path.strip_prefix("/v1/")
    } else {
        route(request.method(), &path)
    };
    let Some(method) = method else {
        return Ok(error(grpc, cln, 12));
    };
    let mut bytes = Vec::new();
    while let Some(chunk) = request.body_mut().data().await {
        let Ok(chunk) = chunk else {
            return Ok(error(grpc, cln, 3));
        };
        if chunk.len() > MAX_REQUEST_BYTES.saturating_sub(bytes.len()) {
            return Ok(error(grpc, cln, 8));
        }
        bytes.extend_from_slice(&chunk);
    }
    let params = if grpc {
        crate::grpc::decode(method, &bytes)
    } else if bytes.is_empty() {
        Some(json!({}))
    } else {
        serde_json::from_slice(&bytes).ok()
    };
    let Some(mut params) = params else {
        return Ok(error(grpc, cln, 3));
    };
    if !grpc && !cln {
        if method == "LookupInvoice" {
            params["r_hash_str"] = json!(path.strip_prefix("/v1/invoice/").unwrap_or_default());
        }
        if method == "TrackPaymentV2" {
            let hash = path
                .strip_prefix("/v2/router/track/")
                .and_then(|s| URL_SAFE.decode(s).ok());
            let Some(hash) = hash else {
                return Ok(error(false, false, 3));
            };
            params["payment_hash_hex"] = json!(hex::encode(hash));
        }
        if method == "DisconnectPeer" {
            params["pub_key"] = json!(path.strip_prefix("/v1/peers/").unwrap_or_default());
        }
        if method == "CloseChannel" {
            if request
                .uri()
                .query()
                .is_some_and(|q| q.split('&').any(|part| part == "force=true"))
            {
                return Ok(error(false, false, 3));
            }
            params["channel_point"] = json!(path
                .strip_prefix("/v1/channels/")
                .unwrap_or_default()
                .replace('/', ":"));
        }
    }
    let fault = state.lock().expect("scenario mutex").begin(method);
    match fault {
        Some(Fault::TimeoutBeforeEffect) => {
            tokio::time::sleep(LOST_RESPONSE_DELAY).await;
            return Ok(error(grpc, cln, 4));
        }
        Some(Fault::Reject) => return Ok(error(grpc, cln, 3)),
        Some(Fault::PermissionDenied) => return Ok(error(grpc, cln, 7)),
        _ => {}
    }
    let result = state.lock().expect("scenario mutex").reply(method, &params);
    if matches!(fault, Some(Fault::TimeoutAfterEffect)) {
        tokio::time::sleep(LOST_RESPONSE_DELAY).await;
        return Ok(error(grpc, cln, 4));
    }
    let Some(result) = result else {
        return Ok(error(grpc, cln, 5));
    };
    if matches!(fault, Some(Fault::Malformed)) {
        return Ok(response(grpc, cln, b"not a valid response".to_vec(), 0));
    }
    if matches!(fault, Some(Fault::Oversized)) {
        return Ok(response(grpc, cln, vec![b'x'; 2 * 1024 * 1024], 0));
    }
    let streamed = matches!(method, "SendPaymentV2" | "TrackPaymentV2" | "CloseChannel");
    if grpc {
        let Some(body) = grpc::encode(method, &result) else {
            return Ok(error(true, false, 13));
        };
        Ok(response(
            true,
            false,
            body,
            if matches!(fault, Some(Fault::StreamError)) {
                14
            } else {
                0
            },
        ))
    } else if streamed {
        let mut bytes = serde_json::to_vec(&json!({"result":result})).expect("wire JSON");
        bytes.push(b'\n');
        if matches!(fault, Some(Fault::StreamError)) {
            bytes.extend_from_slice(br#"{"error":{"code":14,"message":"Synthetic stream error"}}"#);
        }
        Ok(response(false, cln, bytes, 0))
    } else {
        Ok(response(
            false,
            cln,
            serde_json::to_vec(&result).expect("wire JSON"),
            0,
        ))
    }
}
fn response(grpc: bool, cln: bool, bytes: Vec<u8>, code: i32) -> Response<Body> {
    if grpc {
        let (mut sender, body) = Body::channel();
        tokio::spawn(async move {
            if !bytes.is_empty() && sender.send_data(bytes.into()).await.is_err() {
                return;
            }
            let mut trailers = hyper::HeaderMap::new();
            trailers.insert(
                "grpc-status",
                code.to_string().parse().expect("gRPC status"),
            );
            let _ = sender.send_trailers(trailers).await;
        });
        Response::builder()
            .header("content-type", "application/grpc")
            .body(body)
            .expect("gRPC response")
    } else {
        Response::builder()
            .status(if cln {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            })
            .header("content-type", "application/json")
            .body(Body::from(bytes))
            .expect("REST response")
    }
}
fn error(grpc: bool, cln: bool, code: i32) -> Response<Body> {
    if grpc {
        return response(true, false, vec![], code);
    }
    let status = if code == 7 {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    let code = if cln {
        match code {
            7 => 1501,
            12 => -32601,
            3 => -32602,
            _ => -1,
        }
    } else {
        code
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"code":code,"message":"Synthetic rejection"}).to_string(),
        ))
        .expect("error response")
}
