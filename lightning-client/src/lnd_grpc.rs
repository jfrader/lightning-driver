#[cfg(feature = "lnd-grpc")]
use lnd_grpc_rust::lnrpc::{GetInfoRequest, Invoice};

use super::*;
use anyhow::{anyhow, Result};

#[cfg(feature = "lnd-grpc")]
pub struct LndGrpcWrapper {
    client: lnd_grpc_rust::LndClient,
}

#[cfg(feature = "lnd-grpc")]
impl LndGrpcWrapper {
    pub async fn connect(cert_hex: &str, macaroon_hex: &str, addr: &str) -> Result<Self> {
        let mac = hex::decode(macaroon_hex).map_err(|e| anyhow!("Invalid macaroon hex: {}", e))?;

        let cert_arg = if cert_hex.trim().is_empty() {
            "".to_string()
        } else {
            hex::decode(cert_hex)?
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

#[cfg_attr(feature = "lnd-grpc", async_trait)]
#[cfg_attr(not(feature = "lnd-grpc"), async_trait(?Send))]
impl LightningClient for LndGrpcWrapper {
    async fn get_info(&mut self) -> Result<NodeInfo> {
        #[cfg(feature = "lnd-grpc")]
        {
            let req = GetInfoRequest {};
            let res = self.client.lightning().get_info(req).await?.into_inner();
            Ok(NodeInfo {
                alias: res.alias,
                identity_pubkey: res.identity_pubkey,
            })
        }
        #[cfg(not(feature = "lnd-grpc"))]
        {
            Err(anyhow!("lnd-grpc feature not enabled"))
        }
    }

    async fn create_invoice(&mut self, msat: u64, _label: Option<&str>, desc: Option<&str>) -> Result<String> {
        #[cfg(feature = "lnd-grpc")]
        {
            let req = Invoice {
                value_msat: msat as i64,
                memo: desc.unwrap_or("rust").to_string(),
                ..Default::default()
            };
            let res = self.client.lightning().add_invoice(req).await?.into_inner();
            Ok(res.payment_request)
        }
        #[cfg(not(feature = "lnd-grpc"))]
        {
            Err(anyhow!("lnd-grpc feature not enabled"))
        }
    }
}