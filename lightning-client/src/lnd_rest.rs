// lightning-client/src/lnd_rest.rs
use super::*;
use anyhow::{anyhow, Result};
use reqwest::{Certificate, ClientBuilder};
use std::fs;

pub struct LndRestClient {
    url: String,
    client: reqwest::Client,
    macaroon: String,
}

impl LndRestClient {
    pub fn new(host: &str, macaroon_hex: &str, cert_path: &str) -> Result<Self> {
        let cert_path = cert_path.trim();
        if cert_path.is_empty() {
            return Err(anyhow!("cert_path is required"));
        }

        // --- Macaroon ---
        let macaroon = hex::encode(hex::decode(macaroon_hex)?);

        // --- Read PEM certificate ---
        let cert_pem = fs::read_to_string(cert_path)
            .map_err(|e| anyhow!("Failed to read cert file '{}': {}", cert_path, e))?;

        // --- Parse as PEM (your file is PEM!) ---
        let cert = Certificate::from_pem(cert_pem.as_bytes())
            .map_err(|e| anyhow!("Invalid PEM certificate in '{}': {}", cert_path, e))?;

        // --- Build client ---
        let client = ClientBuilder::new()
            .add_root_certificate(cert)
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| anyhow!("Failed to build TLS client: {}", e))?;

        Ok(Self {
            url: host.trim_end_matches('/').to_string(),
            client,
            macaroon,
        })
    }
}

// --- API calls (unchanged) ---
#[async_trait]
impl LightningClient for LndRestClient {
    async fn get_info(&mut self) -> Result<NodeInfo> {
        let res: serde_json::Value = self
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
        let payload = serde_json::json!({
            "value_msat": msat,
            "memo": desc.unwrap_or("rust")
        });

        let res: serde_json::Value = self
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
