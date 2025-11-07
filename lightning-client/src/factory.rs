// lightning-client/src/factory.rs
use super::*;
use ::config::{Config as AppConfig, File}; // explicit crate import

pub async fn connect_from_config() -> Result<LightningClientDyn> {
    let settings = AppConfig::builder()
        .add_source(File::with_name("config.toml"))
        .build()?
        .try_deserialize::<Settings>()?;

    let driver: Box<dyn LightningClient + Send + Sync> = match settings.node.node_type.as_str() {
        "lnd-grpc" => {
            #[cfg(feature = "lnd-grpc")]
            {
                let lnd = settings
                    .lnd_grpc
                    .ok_or_else(|| anyhow::anyhow!("LND gRPC config missing"))?;
                Box::new(
                    lnd_grpc::LndGrpcWrapper::connect(&lnd.cert_hex, &lnd.macaroon_hex, &lnd.host)
                        .await?,
                )
            }
            #[cfg(not(feature = "lnd-grpc"))]
            {
                return Err(anyhow::anyhow!("lnd-grpc feature not enabled"));
            }
        }
        "lnd-rest" => {
            let lnd = settings
                .lnd_rest
                .ok_or_else(|| anyhow::anyhow!("LND REST config missing"))?;
            Box::new(lnd_rest::LndRestClient::new(
                &lnd.host,
                &lnd.macaroon_hex,
                &lnd.cert_path,
            )?)
        }
        "cln" => {
            let cln = settings
                .cln
                .ok_or_else(|| anyhow::anyhow!("CLN config missing"))?;
            Box::new(cln::ClnClient::new(&cln.host))
        }
        _ => return Err(anyhow::anyhow!("Unsupported node type")),
    };

    Ok(Arc::new(Mutex::new(driver)))
}
