// lightning-client/src/lib.rs
pub mod cln;
pub mod config;
pub mod factory;
pub mod lnd_grpc;
pub mod lnd_rest;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub alias: String,
    pub identity_pubkey: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Balance {
    pub onchain_sat: u64,
    pub channel_msat: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Invoice {
    pub hash: String,
    pub amount_msat: u64,
    pub state: String,
    pub bolt11: Option<String>,
    pub desc: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecodedInvoice {
    pub amount_msat: Option<u64>,
    pub desc: Option<String>,
    pub payee: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentResult {
    pub hash: String,
    pub amount_msat: u64,
    pub fee_msat: Option<u64>,
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
    async fn get_balance(&mut self) -> Result<Balance>;
    async fn list_invoices(&mut self, limit: Option<usize>) -> Result<Vec<Invoice>>;
    async fn decode_invoice(&mut self, bolt11: &str) -> Result<DecodedInvoice>;
    async fn pay_invoice(&mut self, bolt11: &str) -> Result<PaymentResult>;
}

pub type LightningClientDyn = Arc<Mutex<Box<dyn LightningClient + Send + Sync>>>;

pub use config::Settings;
pub use factory::connect_from_config;
