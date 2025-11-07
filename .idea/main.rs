use actix_web::{
    get, post,
    web::{Data, Json},
    App, HttpResponse, HttpServer, Responder,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use config::Config as AppConfig;
use reqwest::{Certificate, ClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

// ---------------------------------------------------------------------
// Config structs
// ---------------------------------------------------------------------
#[derive(Debug, Deserialize)]
struct NodeConfig {
    #[serde(rename = "type")]
    node_type: String,
}

#[derive(Debug, Deserialize)]
struct LndGrpcConfig {
    host: String,
    macaroon_hex: String,
    #[serde(default)]
    cert_hex: String,
}

#[derive(Debug, Deserialize)]
struct LndRestConfig {
    host: String,
    macaroon_hex: String,
    cert_hex: String, // required
}

#[derive(Debug, Deserialize)]
struct ClnConfig {
    host: String,
}

#[derive(Debug, Deserialize)]
struct Settings {
    node: NodeConfig,
    #[serde(rename = "lnd-grpc")]
    lnd_grpc: Option<LndGrpcConfig>,
    #[serde(rename = "lnd-rest")]
    lnd_rest: Option<LndRestConfig>,
    cln: Option<ClnConfig>,
}

// ---------------------------------------------------------------------
// Lightning trait
// ---------------------------------------------------------------------
#[async_trait]
pub trait LightningClient {
    async fn get_info(&mut self) -> Result<NodeInfo>;
    async fn create_invoice(
        &mut self,
        msat: u64,
        _label: Option<&str>,
        desc: Option<&str>,
    ) -> Result<String>;
}

#[derive(Debug, Serialize)]
pub struct NodeInfo {
    pub alias: String,
    pub identity_pubkey: String,
}

// ---------------------------------------------------------------------
// LND gRPC
// ---------------------------------------------------------------------
mod lnd_grpc {
    use super::*;
    use lnd_grpc_rust::lnrpc::{GetInfoRequest, Invoice};

    pub struct LndGrpcWrapper {
        client: lnd_grpc_rust::LndClient,
    }

    impl LndGrpcWrapper {
        pub async fn connect(cert_hex: &str, macaroon_hex: &str, addr: &str) -> Result<Self> {
            let mac =
                hex::decode(macaroon_hex).map_err(|e| anyhow!("Invalid macaroon hex: {}", e))?;

            let cert_arg = if cert_hex.trim().is_empty() {
                "".to_string()
            } else {
                hex::decode(cert_hex)
                    .map_err(|e| anyhow!("Invalid cert hex: {}", e))?
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect()
            };

            let client = lnd_grpc_rust::connect(cert_arg, hex::encode(mac), addr.to_string())
                .await
                .map_err(|e| anyhow!("LND gRPC connect failed: {}", e))?;

            Ok(Self { client })
        }
    }

    #[async_trait]
    impl crate::LightningClient for LndGrpcWrapper {
        async fn get_info(&mut self) -> Result<NodeInfo> {
            let req = GetInfoRequest {};
            let res = self.client.lightning().get_info(req).await?.into_inner();
            Ok(NodeInfo {
                alias: res.alias,
                identity_pubkey: res.identity_pubkey,
            })
        }

        async fn create_invoice(
            &mut self,
            msat: u64,
            _label: Option<&str>,
            desc: Option<&str>,
        ) -> Result<String> {
            let req = Invoice {
                value_msat: msat as i64,
                memo: desc.unwrap_or("rust").to_string(),
                ..Default::default()
            };
            let res = self.client.lightning().add_invoice(req).await?.into_inner();
            Ok(res.payment_request)
        }
    }
}

// ---------------------------------------------------------------------
// LND REST
// ---------------------------------------------------------------------
mod lnd_rest {
    use super::*;

    fn der_to_pem(der: &[u8]) -> Result<String> {
        let b64 = general_purpose::STANDARD.encode(der);
        let mut pem = String::new();
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        Ok(pem)
    }

    pub struct LndRestClient {
        url: String,
        client: reqwest::Client,
        macaroon: String,
    }

    impl LndRestClient {
        pub fn new(host: &str, macaroon_hex: &str, cert_hex: &str) -> Result<Self> {
            if cert_hex.trim().is_empty() {
                return Err(anyhow!("cert_hex is required for LND REST"));
            }

            let macaroon = hex::encode(hex::decode(macaroon_hex)?);
            let der = hex::decode(cert_hex)?;
            let pem = der_to_pem(&der)?;

            let mut builder = ClientBuilder::new();

            // Add CA cert
            let cert = Certificate::from_pem(pem.as_bytes())
                .map_err(|e| anyhow!("Failed to parse PEM: {}", e))?;
            builder = builder.add_root_certificate(cert);

            // Disable hostname verification (LND uses IP or localhost)
            builder = builder.danger_accept_invalid_certs(true);

            let client = builder.build()?;

            Ok(Self {
                url: host.trim_end_matches('/').to_string(),
                client,
                macaroon,
            })
        }
    }

    #[async_trait]
    impl crate::LightningClient for LndRestClient {
        async fn get_info(&mut self) -> Result<NodeInfo> {
            let res: Value = self
                .client
                .get(format!("{}/v1/getinfo", self.url))
                .header("Grpc-Metadata-macaroon", &self.macaroon)
                .send()
                .await?
                .json()
                .await?;

            Ok(NodeInfo {
                alias: res["alias"].as_str().unwrap_or("LND").to_string(),
                identity_pubkey: res["identity_pubkey"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
            })
        }

        async fn create_invoice(
            &mut self,
            msat: u64,
            _label: Option<&str>,
            desc: Option<&str>,
        ) -> Result<String> {
            let payload = json!({
                "value_msat": msat,
                "memo": desc.unwrap_or("rust")
            });

            let res: Value = self
                .client
                .post(format!("{}/v1/invoices", self.url))
                .header("Grpc-Metadata-macaroon", &self.macaroon)
                .json(&payload)
                .send()
                .await?
                .json()
                .await?;

            Ok(res["payment_request"]
                .as_str()
                .ok_or_else(|| anyhow!("no payment_request"))?
                .to_string())
        }
    }
}

// ---------------------------------------------------------------------
// CLN
// ---------------------------------------------------------------------
mod cln {
    use super::*;
    use reqwest::Client;

    pub struct ClnClient {
        url: String,
        http: Client,
    }

    impl ClnClient {
        pub fn new(url: &str) -> Self {
            Self {
                url: url.trim_end_matches('/').to_string(),
                http: Client::new(),
            }
        }
    }

    #[async_trait]
    impl crate::LightningClient for ClnClient {
        async fn get_info(&mut self) -> Result<NodeInfo> {
            let res: Value = self
                .http
                .get(format!("{}/v1/getinfo", self.url))
                .send()
                .await?
                .json()
                .await?;
            Ok(NodeInfo {
                alias: res["alias"].as_str().unwrap_or("CLN").to_string(),
                identity_pubkey: res["id"].as_str().unwrap_or("unknown").to_string(),
            })
        }

        async fn create_invoice(
            &mut self,
            msat: u64,
            _label: Option<&str>,
            desc: Option<&str>,
        ) -> Result<String> {
            let default_label = format!("rust-{}", chrono::Utc::now().timestamp());
            let payload = json!({
                "msatoshi": msat,
                "label": default_label,
                "description": desc.unwrap_or("rust")
            });
            let res: Value = self
                .http
                .post(format!("{}/v1/invoice", self.url))
                .json(&payload)
                .send()
                .await?
                .json()
                .await?;
            Ok(res["bolt11"]
                .as_str()
                .ok_or_else(|| anyhow!("no bolt11"))?
                .to_string())
        }
    }
}

// ---------------------------------------------------------------------
// Load config + factory
// ---------------------------------------------------------------------
async fn load_and_connect() -> Result<Arc<Mutex<Box<dyn LightningClient + Send + Sync>>>> {
    let settings = AppConfig::builder()
        .add_source(config::File::with_name("config.toml"))
        .build()?
        .try_deserialize::<Settings>()?;

    let driver: Box<dyn LightningClient + Send + Sync> = match settings.node.node_type.as_str() {
        "lnd-grpc" => {
            let lnd = settings
                .lnd_grpc
                .ok_or_else(|| anyhow!("LND gRPC config missing"))?;
            Box::new(
                lnd_grpc::LndGrpcWrapper::connect(&lnd.cert_hex, &lnd.macaroon_hex, &lnd.host)
                    .await?,
            )
        }
        "lnd-rest" => {
            let lnd = settings
                .lnd_rest
                .ok_or_else(|| anyhow!("LND REST config missing"))?;
            Box::new(lnd_rest::LndRestClient::new(
                &lnd.host,
                &lnd.macaroon_hex,
                &lnd.cert_hex,
            )?)
        }
        "cln" => {
            let cln = settings.cln.ok_or_else(|| anyhow!("CLN config missing"))?;
            Box::new(cln::ClnClient::new(&cln.host))
        }
        _ => return Err(anyhow!("Unsupported node type")),
    };

    Ok(Arc::new(Mutex::new(driver)))
}

// ---------------------------------------------------------------------
// API structs
// ---------------------------------------------------------------------
#[derive(Deserialize)]
struct InvoiceReq {
    msat: u64,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    desc: Option<String>,
}

#[derive(Serialize)]
struct InvoiceResp {
    bolt11: String,
}

// ---------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------
#[get("/api/info")]
async fn get_info(
    driver: Data<Arc<Mutex<Box<dyn LightningClient + Send + Sync>>>>,
) -> impl Responder {
    let mut guard = driver.lock().unwrap();
    match guard.get_info().await {
        Ok(info) => HttpResponse::Ok().json(info),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/api/invoice")]
async fn create_invoice(
    driver: Data<Arc<Mutex<Box<dyn LightningClient + Send + Sync>>>>,
    payload: Json<InvoiceReq>,
) -> impl Responder {
    let mut guard = driver.lock().unwrap();
    let desc = payload.desc.as_deref();

    match guard.create_invoice(payload.msat, None, desc).await {
        Ok(bolt11) => HttpResponse::Ok().json(InvoiceResp { bolt11 }),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// ---------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------
#[actix_web::main]
async fn main() -> Result<()> {
    let driver = load_and_connect().await?;

    let port = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    println!("Dashboard API → http://{}", addr);

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(driver.clone()))
            .service(get_info)
            .service(create_invoice)
    })
    .bind(addr)?
    .run()
    .await
    .map_err(|e| anyhow!("server error: {}", e))
}
