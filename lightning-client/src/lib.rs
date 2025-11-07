// lightning-client/src/lib.rs
pub mod config;
pub mod lnd_grpc;
pub mod lnd_rest;
pub mod cln;
pub mod factory;

use anyhow::Result;
use async_trait::async_trait;
use serde::Serialize;
use std::sync::{Arc, Mutex};

#[derive(Debug, Serialize)]
pub struct NodeInfo {
    pub alias: String,
    pub identity_pubkey: String,
}

#[async_trait]
pub trait LightningClient {
    async fn get_info(&mut self) -> Result<NodeInfo>;
    async fn create_invoice(
        &mut self,
        msat: u64,
        label: Option<&str>,
        desc: Option<&str>,
    ) -> Result<String>;
}

pub type LightningClientDyn = Arc<Mutex<Box<dyn LightningClient + Send + Sync>>>;

pub use config::Settings;
pub use factory::connect_from_config;