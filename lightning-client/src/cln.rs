// lightning-client/src/cln.rs
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
impl LightningClient for ClnClient {
    async fn get_info(&mut self) -> Result<NodeInfo> {
        let res: serde_json::Value = self
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
        #[cfg(feature = "cln")]
        {
            let default_label = format!("rust-{}", chrono::Utc::now().timestamp());
            let payload = serde_json::json!({
                "msatoshi": msat,
                "label": default_label,
                "description": desc.unwrap_or("rust")
            });
            let res: serde_json::Value = self
                .http
                .post(format!("{}/v1/invoice", self.url))
                .json(&payload)
                .send()
                .await?
                .json()
                .await?;
            Ok(res["bolt11"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("no bolt11"))?
                .to_string())
        }

        #[cfg(not(feature = "cln"))]
        {
            Err(anyhow::anyhow!("CLN feature not enabled"))
        }
    }
}
