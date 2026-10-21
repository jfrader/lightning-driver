#[cfg(feature = "lnd-grpc")]
mod enabled {
    use crate::{Balance, DecodedInvoice, Invoice, LightningClient, NodeInfo, PaymentResult};
    use anyhow::{anyhow, Result};
    use async_trait::async_trait;
    use lnd_grpc_rust::lnrpc::{self, lightning_client::LightningClient as RpcClient};
    use tonic::{
        metadata::{Ascii, MetadataValue},
        transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
        Request,
    };

    pub struct LndGrpcWrapper {
        client: RpcClient<Channel>,
        macaroon: MetadataValue<Ascii>,
    }

    impl LndGrpcWrapper {
        pub async fn connect(cert_hex: &str, macaroon_hex: &str, addr: &str) -> Result<Self> {
            let certificate =
                hex::decode(cert_hex).map_err(|_| anyhow!("Invalid TLS certificate encoding"))?;
            if certificate.is_empty() {
                return Err(anyhow!("TLS certificate is required"));
            }
            let macaroon = hex::encode(
                hex::decode(macaroon_hex).map_err(|_| anyhow!("Invalid macaroon encoding"))?,
            );
            if macaroon.is_empty() {
                return Err(anyhow!("Macaroon is required"));
            }
            let mut macaroon = macaroon
                .parse::<MetadataValue<Ascii>>()
                .map_err(|_| anyhow!("Invalid macaroon metadata"))?;
            macaroon.set_sensitive(true);
            let address = if addr.starts_with("https://") {
                addr.to_owned()
            } else {
                format!("https://{addr}")
            };
            let url = url::Url::parse(&address).map_err(|_| anyhow!("Invalid gRPC endpoint"))?;
            if url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
            {
                return Err(anyhow!("gRPC endpoint must be an HTTPS origin"));
            }
            let endpoint = Endpoint::from_shared(address)
                .map_err(|_| anyhow!("Invalid gRPC endpoint"))?
                .tls_config(
                    ClientTlsConfig::new().ca_certificate(Certificate::from_pem(certificate)),
                )
                .map_err(|_| anyhow!("Invalid TLS trust configuration"))?
                .timeout(std::time::Duration::from_secs(u64::from(
                    crate::settings::Limits::default().rpc_seconds,
                )));
            Ok(Self {
                client: RpcClient::new(endpoint.connect_lazy()),
                macaroon,
            })
        }

        fn request<T>(&self, value: T) -> Request<T> {
            let mut request = Request::new(value);
            request
                .metadata_mut()
                .insert("macaroon", self.macaroon.clone());
            request
        }
    }

    #[async_trait]
    impl LightningClient for LndGrpcWrapper {
        async fn get_info(&self) -> Result<NodeInfo> {
            let response = self
                .client
                .clone()
                .get_info(self.request(lnrpc::GetInfoRequest {}))
                .await
                .map_err(|_| anyhow!("Node info unavailable"))?
                .into_inner();
            Ok(NodeInfo {
                alias: response.alias,
                identity_pubkey: response.identity_pubkey,
            })
        }

        async fn create_invoice(
            &self,
            msat: u64,
            _label: Option<&str>,
            desc: Option<&str>,
        ) -> Result<String> {
            let request = lnrpc::Invoice {
                value_msat: i64::try_from(msat).map_err(|_| anyhow!("Amount out of range"))?,
                memo: desc.unwrap_or_default().into(),
                ..Default::default()
            };
            Ok(self
                .client
                .clone()
                .add_invoice(self.request(request))
                .await
                .map_err(|_| anyhow!("Invoice outcome unavailable"))?
                .into_inner()
                .payment_request)
        }

        async fn get_balance(&self) -> Result<Balance> {
            let wallet = self
                .client
                .clone()
                .wallet_balance(self.request(lnrpc::WalletBalanceRequest {
                    account: String::new(),
                    min_confs: 1,
                }))
                .await
                .map_err(|_| anyhow!("Wallet balance unavailable"))?
                .into_inner();
            let channels = self
                .client
                .clone()
                .channel_balance(self.request(lnrpc::ChannelBalanceRequest {}))
                .await
                .map_err(|_| anyhow!("Channel balance unavailable"))?
                .into_inner();
            let local = channels
                .local_balance
                .ok_or_else(|| anyhow!("Missing channel balance"))?;
            Ok(Balance {
                onchain_sat: u64::try_from(wallet.confirmed_balance)
                    .map_err(|_| anyhow!("Invalid wallet balance"))?,
                channel_msat: local.msat,
            })
        }

        async fn list_invoices(&self, limit: Option<usize>) -> Result<Vec<Invoice>> {
            let request = lnrpc::ListInvoiceRequest {
                num_max_invoices: u64::try_from(limit.unwrap_or(10))
                    .map_err(|_| anyhow!("Invalid list limit"))?,
                ..Default::default()
            };
            let response = self
                .client
                .clone()
                .list_invoices(self.request(request))
                .await
                .map_err(|_| anyhow!("Invoices unavailable"))?
                .into_inner();
            response
                .invoices
                .into_iter()
                .map(|invoice| {
                    Ok(Invoice {
                        hash: hex::encode(invoice.r_hash),
                        amount_msat: u64::try_from(invoice.value_msat)
                            .map_err(|_| anyhow!("Invalid invoice amount"))?,
                        state: match invoice.state {
                            0 => "open".into(),
                            1 => "settled".into(),
                            2 => "canceled".into(),
                            3 => "accepted".into(),
                            other => format!("unknown:{other}"),
                        },
                        bolt11: (!invoice.payment_request.is_empty())
                            .then_some(invoice.payment_request),
                        desc: (!invoice.memo.is_empty()).then_some(invoice.memo),
                    })
                })
                .collect()
        }

        async fn decode_invoice(&self, bolt11: &str) -> Result<DecodedInvoice> {
            let response = self
                .client
                .clone()
                .decode_pay_req(self.request(lnrpc::PayReqString {
                    pay_req: bolt11.into(),
                }))
                .await
                .map_err(|_| anyhow!("Invoice decode failed"))?
                .into_inner();
            Ok(DecodedInvoice {
                amount_msat: match response.num_msat {
                    0 => None,
                    amount => {
                        Some(u64::try_from(amount).map_err(|_| anyhow!("Invalid invoice amount"))?)
                    }
                },
                desc: Some(response.description),
                payee: Some(response.destination),
            })
        }

        async fn pay_invoice(&self, _bolt11: &str) -> Result<PaymentResult> {
            Err(anyhow!(
                "Payment requires the versioned reviewed-operation API"
            ))
        }
    }
}

#[cfg(feature = "lnd-grpc")]
pub use enabled::LndGrpcWrapper;
