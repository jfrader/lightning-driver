// lightning-client/src/lnd_rest.rs
use super::*;
use anyhow::{anyhow, Result};
use reqwest::{Certificate, ClientBuilder};
use serde_json::json;
use serde_json::Value;
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

    async fn get_balance(&mut self) -> Result<Balance> {
        let wallet_url = format!("{}/v1/balance/wallet", self.url);
        let wallet_res: Value = self
            .client
            .get(&wallet_url)
            .header("Grpc-Metadata-macaroon", &self.macaroon)
            .send()
            .await?
            .json()
            .await?;
        let onchain_sat = wallet_res["confirmed_balance"].as_u64().unwrap_or(0);

        let chan_url = format!("{}/v1/balance/channels", self.url);
        let chan_res: Value = self
            .client
            .get(&chan_url)
            .header("Grpc-Metadata-macaroon", &self.macaroon)
            .send()
            .await?
            .json()
            .await?;
        let channel_msat = chan_res["local_balance"].as_u64().unwrap_or(0);

        Ok(Balance {
            onchain_sat,
            channel_msat,
        })
    }

    async fn list_invoices(&mut self, limit: Option<usize>) -> Result<Vec<Invoice>> {
        let url = format!(
            "{}/v1/invoices?num_max_invoices={}",
            self.url,
            limit.unwrap_or(10)
        );
        let res: Value = self
            .client
            .get(&url)
            .header("Grpc-Metadata-macaroon", &self.macaroon)
            .send()
            .await?
            .json()
            .await?;

        let mut invoices = vec![];
        if let Some(inv_list) = res["invoices"].as_array() {
            for inv in inv_list {
                invoices.push(Invoice {
                    hash: inv["r_hash"].as_str().unwrap_or("").to_string(),
                    amount_msat: inv["value_msat"].as_u64().unwrap_or(0),
                    state: if inv["settled"].as_bool().unwrap_or(false) {
                        "paid".to_string()
                    } else {
                        "unpaid".to_string()
                    },
                    bolt11: inv["payment_request"].as_str().map(ToString::to_string),
                    desc: inv["memo"].as_str().and_then(|s| if s.is_empty() { None } else { Some(s.to_string()) }),
                });
            }
        }
        Ok(invoices)
    }

    async fn decode_invoice(&mut self, bolt11: &str) -> Result<DecodedInvoice> {
        let payload = json!({ "pay_req": bolt11 });
        let res: Value = self
            .client
            .post(format!("{}/v1/payreq", self.url))
            .header("Grpc-Metadata-macaroon", &self.macaroon)
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        let num_sat = res["num_satoshis"].as_u64().unwrap_or(0);
        let amount_msat = if num_sat == 0 { None } else { Some(num_sat * 1000) };
        let desc = res["description"].as_str().map(ToString::to_string);
        let payee = res["destination"].as_str().map(ToString::to_string);

        Ok(DecodedInvoice {
            amount_msat,
            desc,
            payee,
        })
    }

    async fn pay_invoice(&mut self, bolt11: &str) -> Result<PaymentResult> {
        let payload = json!({ "payment_request": bolt11 });
        let res: Value = self
            .client
            .post(format!("{}/v1/sendpaymentsync", self.url))
            .header("Grpc-Metadata-macaroon", &self.macaroon)
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = res["payment_error"].as_str() {
            return Err(anyhow!("Payment failed: {}", err));
        }

        let hash = res["payment_hash"].as_str().ok_or_else(|| anyhow!("no payment_hash"))?.to_string();
        let amount_msat = res["amount_msat"].as_u64().ok_or_else(|| anyhow!("no amount_msat"))?;
        let fee_msat = res["fee_msat"].as_u64();

        Ok(PaymentResult {
            hash,
            amount_msat,
            fee_msat,
        })
    }
}