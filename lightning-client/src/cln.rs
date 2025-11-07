// lightning-client/src/cln.rs
use super::*;
use reqwest::Client;
use serde_json::{json, Value};

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
        #[cfg(feature = "cln")]
        {
            use chrono::Utc;
            let default_label = format!("rust-{}", Utc::now().timestamp());
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
                .ok_or_else(|| anyhow::anyhow!("no bolt11"))?
                .to_string())
        }
        #[cfg(not(feature = "cln"))]
        {
            Err(anyhow::anyhow!("CLN feature not enabled"))
        }
    }

    async fn get_balance(&mut self) -> Result<Balance> {
        let res: Value = self
            .http
            .post(format!("{}/v1/listfunds", self.url))
            .json(&json!({}))
            .send()
            .await?
            .json()
            .await?;

        let mut onchain_msat = 0u64;
        if let Some(outputs) = res["outputs"].as_array() {
            for out in outputs {
                if out["status"].as_str() == Some("confirmed") {
                    if let Some(msat) = out["msatoshi"].as_u64() {
                        onchain_msat += msat;
                    }
                }
            }
        }

        let mut channel_msat = 0u64;
        if let Some(chans) = res["channels"].as_array() {
            for ch in chans {
                if let Some(msat) = ch["our_msatoshi"].as_u64() {
                    channel_msat += msat;
                }
            }
        }

        Ok(Balance {
            onchain_sat: onchain_msat / 1000,
            channel_msat,
        })
    }

    async fn list_invoices(&mut self, limit: Option<usize>) -> Result<Vec<Invoice>> {
        #[cfg(feature = "cln")]
        {
            let payload = json!({ "count": limit.unwrap_or(10) });
            let res: Value = self
                .http
                .post(format!("{}/v1/listinvoices", self.url))
                .json(&payload)
                .send()
                .await?
                .json()
                .await?;

            let mut invoices = vec![];
            if let Some(inv_list) = res["invoices"].as_array() {
                for inv in inv_list {
                    let state_num: u32 = inv["state"].as_u64().unwrap_or(0) as u32;
                    let state_str = match state_num {
                        0 => "unpaid",
                        1 => "paid",
                        2 => "expired",
                        _ => "unknown",
                    };
                    invoices.push(Invoice {
                        hash: inv["payment_hash"].as_str().unwrap_or("").to_string(),
                        amount_msat: inv["msatoshi_received"].as_u64().unwrap_or(0),
                        state: state_str.to_string(),
                        bolt11: inv["bolt11"].as_str().map(ToString::to_string),
                        desc: None,
                    });
                }
            }
            Ok(invoices)
        }
        #[cfg(not(feature = "cln"))]
        {
            Err(anyhow::anyhow!("CLN feature not enabled"))
        }
    }

    async fn decode_invoice(&mut self, bolt11: &str) -> Result<DecodedInvoice> {
        #[cfg(feature = "cln")]
        {
            let payload = json!({ "bolt11": bolt11 });
            let res: Value = self
                .http
                .post(format!("{}/v1/decodepay", self.url))
                .json(&payload)
                .send()
                .await?
                .json()
                .await?;

            let amount_msat = res["msatoshi"].as_u64();
            let desc = res["description"].as_str().map(ToString::to_string);
            let payee = res["payee"].as_str().map(ToString::to_string);

            Ok(DecodedInvoice {
                amount_msat,
                desc,
                payee,
            })
        }
        #[cfg(not(feature = "cln"))]
        {
            Err(anyhow::anyhow!("CLN feature not enabled"))
        }
    }

    async fn pay_invoice(&mut self, bolt11: &str) -> Result<PaymentResult> {
        #[cfg(feature = "cln")]
        {
            let payload = json!({ "bolt11": bolt11 });
            let res: Value = self
                .http
                .post(format!("{}/v1/pay", self.url))
                .json(&payload)
                .send()
                .await?
                .json()
                .await?;

            if let Some(err) = res["error"].as_str() {
                return Err(anyhow::anyhow!("Payment failed: {}", err));
            }

            let hash = res["payment_hash"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("no payment_hash"))?
                .to_string();
            let amount_msat = res["amount_sent_msat"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("no amount_sent_msat"))?;
            let fee_msat = res["total_fees_msats"].as_u64();

            Ok(PaymentResult {
                hash,
                amount_msat,
                fee_msat,
            })
        }
        #[cfg(not(feature = "cln"))]
        {
            Err(anyhow::anyhow!("CLN feature not enabled"))
        }
    }
}
