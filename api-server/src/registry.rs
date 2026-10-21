use chrono::{DateTime, Utc};
use lightning_client::{
    model::{
        Capabilities, CapabilityReason, ErrorCode, Network, NodeConnection, NodeStatus, NodeSummary,
    },
    money::Decimal,
    settings::{NodePolicy, NodeSettings, Settings},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// No transport client or mutation method belongs in this configuration boundary.
#[derive(Default)]
pub struct Registry {
    nodes: BTreeMap<String, Entry>,
}

pub struct Entry {
    pub policy: NodePolicy,
    pub binding_revision: String,
    label: String,
    backend: lightning_client::model::Backend,
}

fn fingerprint(value: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

impl Registry {
    pub fn new(settings: &Settings) -> Result<Self, serde_json::Error> {
        let mut nodes = BTreeMap::new();
        for node in &settings.nodes {
            let binding_revision = binding(node)?;
            let revision = fingerprint(&(
                "policy-v1",
                &binding_revision,
                &node.policy,
                &node.peer_policy,
                node.read_only,
                &settings.api.public_origin,
                &settings.api.rp_id,
                settings.api.allow_insecure_loopback,
                &settings.api.reauth,
                &settings.api.limits,
            ))?;
            nodes.insert(
                node.id.clone(),
                Entry {
                    binding_revision,
                    label: node.label.clone(),
                    backend: node.backend,
                    policy: NodePolicy {
                        node_id: node.id.clone(),
                        revision,
                        read_only: node.read_only,
                        limits: node.policy.clone(),
                    },
                },
            );
        }
        Ok(Self { nodes })
    }
    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.nodes.get(id)
    }
    pub fn entries(&self) -> impl Iterator<Item = (&String, &Entry)> {
        self.nodes.iter()
    }
    pub fn scope(&self) -> String {
        let mut hash = Sha256::new();
        for (id, entry) in &self.nodes {
            hash.update(id.as_bytes());
            hash.update(entry.binding_revision.as_bytes());
            hash.update(entry.policy.revision.as_bytes());
        }
        hex::encode(hash.finalize())
    }
}

fn binding(node: &NodeSettings) -> Result<String, serde_json::Error> {
    fingerprint(&(
        "binding-v1",
        &node.id,
        node.backend,
        &node.expected_pubkey,
        node.network,
        &node.endpoint,
        &node.certificate_file,
        &node.credential_file,
    ))
}

impl Entry {
    pub fn summary(&self, now: DateTime<Utc>, unresolved: Decimal) -> NodeSummary {
        NodeSummary {
            id: self.policy.node_id.clone(),
            label: self.label.clone(),
            backend: self.backend,
            network: Network::Unknown,
            identity_pubkey: None,
            identity_revision: None,
            read_only: self.policy.read_only,
            status: NodeStatus {
                node_id: self.policy.node_id.clone(),
                status: NodeConnection::Unsupported,
                synced_to_chain: None,
                synced_to_graph: None,
                block_height: None,
                observed_at: None,
                checked_at: now,
                stale: true,
                error_code: Some(ErrorCode::NodeUnverified),
            },
            capabilities: Capabilities::uniform(Some(if self.policy.read_only {
                CapabilityReason::ReadOnly
            } else {
                CapabilityReason::Unverified
            })),
            unresolved_operation_count: unresolved,
        }
    }
    pub fn observed_network(&self) -> Network {
        Network::Unknown
    }
}
