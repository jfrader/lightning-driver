use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    #[serde(rename = "type")]
    pub node_type: String,
}

#[derive(Debug, Deserialize)]
pub struct LndGrpcConfig {
    pub host: String,
    pub macaroon_hex: String,
    #[serde(default)]
    pub cert_hex: String,
}

// lightning-client/src/config.rs
#[derive(Debug, Deserialize)]
pub struct LndRestConfig {
    pub host: String,
    pub macaroon_hex: String,
    pub cert_path: String,  // ← path, not hex
}

#[derive(Debug, Deserialize)]
pub struct ClnConfig {
    pub host: String,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub node: NodeConfig,
    #[serde(rename = "lnd-grpc")]
    pub lnd_grpc: Option<LndGrpcConfig>,
    #[serde(rename = "lnd-rest")]
    pub lnd_rest: Option<LndRestConfig>,
    pub cln: Option<ClnConfig>,
}