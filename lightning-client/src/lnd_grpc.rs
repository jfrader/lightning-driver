// lightning-client/src/lnd_grpc.rs
#[cfg(feature = "lnd-grpc")]
use lnd_grpc_rust::lnrpc::{
    AddInvoiceResponse, ChannelBalanceRequest, ChannelBalanceResponse, GetInfoRequest,
    GetInfoResponse, Invoice as LndInvoice, ListInvoiceRequest, ListInvoiceResponse,
    WalletBalanceRequest, WalletBalanceResponse,
};

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
            let res: GetInfoResponse = self.client.lightning().get_info(req).await?.into_inner();
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

    async fn create_invoice(
        &mut self,
        msat: u64,
        _label: Option<&str>,
        desc: Option<&str>,
    ) -> Result<String> {
        #[cfg(feature = "lnd-grpc")]
        {
            let req = LndInvoice {
                value_msat: msat as i64,
                memo: desc.unwrap_or("rust").to_string(),
                ..Default::default()
            };
            let res: AddInvoiceResponse =
                self.client.lightning().add_invoice(req).await?.into_inner();
            Ok(res.payment_request)
        }
        #[cfg(not(feature = "lnd-grpc"))]
        {
            Err(anyhow!("lnd-grpc feature not enabled"))
        }
    }

    async fn get_balance(&mut self) -> Result<Balance> {
        #[cfg(feature = "lnd-grpc")]
        {
            let wallet_req = WalletBalanceRequest {
                account: "".to_string(),
                min_confs: 1,
            };
            let wallet_res: WalletBalanceResponse = self
                .client
                .lightning()
                .wallet_balance(wallet_req)
                .await?
                .into_inner();
            let onchain_sat = wallet_res.confirmed_balance as u64;

            let chan_req = ChannelBalanceRequest {
                ..Default::default()
            };
            let chan_res: ChannelBalanceResponse = self
                .client
                .lightning()
                .channel_balance(chan_req)
                .await?
                .into_inner();
            let channel_msat = if let Some(amount) = chan_res.local_balance {
                if amount.msat > 0 {
                    amount.msat as u64
                } else {
                    amount.sat as u64 * 1000
                }
            } else {
                0u64
            };

            Ok(Balance {
                onchain_sat,
                channel_msat,
            })
        }
        #[cfg(not(feature = "lnd-grpc"))]
        {
            Err(anyhow!("lnd-grpc feature not enabled"))
        }
    }

    async fn list_invoices(&mut self, limit: Option<usize>) -> Result<Vec<Invoice>> {
        #[cfg(feature = "lnd-grpc")]
        {
            let req = ListInvoiceRequest {
                num_max_invoices: limit.unwrap_or(10) as u64,
                ..Default::default()
            };
            let res: ListInvoiceResponse = self
                .client
                .lightning()
                .list_invoices(req)
                .await?
                .into_inner();
            let invoices = res
                .invoices
                .into_iter()
                .map(|inv| Invoice {
                    hash: hex::encode(inv.r_hash),
                    amount_msat: std::cmp::max(inv.value_msat, 0) as u64,
                    state: match inv.state {
                        0 => "open".to_string(),
                        1 => "settled".to_string(),
                        2 => "canceled".to_string(),
                        3 => "accepted".to_string(),
                        _ => format!("unknown: {}", inv.state),
                    },
                    bolt11: if inv.payment_request.is_empty() {
                        None
                    } else {
                        Some(inv.payment_request)
                    },
                    desc: if inv.memo.is_empty() {
                        None
                    } else {
                        Some(inv.memo)
                    },
                })
                .collect();
            Ok(invoices)
        }
        #[cfg(not(feature = "lnd-grpc"))]
        {
            Err(anyhow!("lnd-grpc feature not enabled"))
        }
    }

    async fn decode_invoice(&mut self, _bolt11: &str) -> Result<DecodedInvoice> {
        #[cfg(feature = "lnd-grpc")]
        {
            Err(anyhow!(
                "decode_invoice not implemented in this gRPC binding version"
            ))
        }
        #[cfg(not(feature = "lnd-grpc"))]
        {
            Err(anyhow!("lnd-grpc feature not enabled"))
        }
    }

    async fn pay_invoice(&mut self, _bolt11: &str) -> Result<PaymentResult> {
        #[cfg(feature = "lnd-grpc")]
        {
            Err(anyhow!(
                "pay_invoice not implemented in this gRPC binding version"
            ))
        }
        #[cfg(not(feature = "lnd-grpc"))]
        {
            Err(anyhow!("lnd-grpc feature not enabled"))
        }
    }
}
