use chrono::{DateTime, Utc};
use lightning_client::{
    model::{
        Capabilities, Capability, CapabilityReason, ErrorCode, Network, NodeConnection, NodeKind,
        NodeStatus, NodeSummary, ReadAvailability,
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
    retained: std::sync::Mutex<usize>,
}

pub struct Entry {
    read_availability: ReadAvailability,
    pub policy: NodePolicy,
    pub binding_revision: String,
    label: String,
    backend: lightning_client::model::Backend,
    unavailable: Option<ErrorCode>,
    freshness_seconds: u32,
    pub(crate) observation: std::sync::Mutex<Option<(crate::operations::InfoObservation, String)>>,
    pub(crate) reads: tokio::sync::Mutex<crate::live::Cache>,
    pub(crate) last_error: std::sync::Mutex<Option<(DateTime<Utc>, ErrorCode)>>,
}

#[cfg(test)]
impl Registry {
    /// Seeds one cached read and its byte accounting, returning the new total.
    pub(crate) async fn seed_read_for_test(&self, id: &str, bytes: usize) -> usize {
        let cached = self
            .nodes
            .get(id)
            .unwrap()
            .reads
            .lock()
            .await
            .seed_for_test("channels", bytes);
        self.set_retained_bytes(cached);
        cached
    }
}

impl Entry {
    /// Clears every cached read for this node and returns the bytes released.
    pub(crate) async fn invalidate_reads(&self) -> usize {
        self.reads.lock().await.invalidate()
    }
}

fn fingerprint(value: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("This runtime requires a Lightning node policy")]
    LightningPolicyRequired,
    #[error("Cannot fingerprint node configuration")]
    InvalidConfiguration,
}

impl From<serde_json::Error> for RegistryError {
    fn from(_: serde_json::Error) -> Self {
        Self::InvalidConfiguration
    }
}

impl Registry {
    pub fn new(settings: &Settings) -> Result<Self, RegistryError> {
        let mut nodes = BTreeMap::new();
        for node in &settings.nodes {
            let limits = node
                .policy
                .as_ref()
                .ok_or(RegistryError::LightningPolicyRequired)?;
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
                    read_availability: ReadAvailability::lightning(),
                    binding_revision,
                    label: node.label.clone(),
                    backend: node.backend,
                    unavailable: None,
                    freshness_seconds: settings.api.limits.rpc_seconds,
                    observation: std::sync::Mutex::new(None),
                    reads: tokio::sync::Mutex::new(crate::live::Cache::default()),
                    last_error: std::sync::Mutex::new(None),
                    policy: NodePolicy {
                        node_id: node.id.clone(),
                        revision,
                        read_only: node.read_only.unwrap_or(true),
                        limits: limits.clone(),
                    },
                },
            );
        }
        Ok(Self {
            nodes,
            retained: std::sync::Mutex::new(0),
        })
    }
    /// Bytes currently held by every cached node read, across all nodes.
    pub(crate) fn retained_bytes(&self) -> usize {
        *self
            .retained
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
    pub(crate) fn set_retained_bytes(&self, bytes: usize) {
        *self
            .retained
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = bytes;
    }
    /// Drops one node's cached reads after a committed change and releases their bytes.
    pub(crate) async fn invalidate_reads(&self, id: &str) -> usize {
        let Some(entry) = self.nodes.get(id) else {
            return 0;
        };
        let released = entry.invalidate_reads().await;
        let remaining = self.retained_bytes().saturating_sub(released);
        self.set_retained_bytes(remaining);
        remaining
    }
    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.nodes.get(id)
    }
    pub(crate) fn mark_unavailable(&mut self, id: &str, code: ErrorCode) {
        if let Some(entry) = self.nodes.get_mut(id) {
            entry.unavailable = Some(code);
        }
    }
    pub(crate) fn register_availability(&mut self, id: &str, availability: ReadAvailability) {
        if let Some(entry) = self.nodes.get_mut(id) {
            entry.read_availability = availability;
        }
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
    let ca_binding = fingerprint(&(
        "binding-v1",
        &node.id,
        node.backend,
        &node.expected_pubkey,
        node.network,
        &node.endpoint,
        &node.certificate_file,
        &node.credential_file,
    ))?;
    match node.tls_verification {
        lightning_client::settings::TlsVerification::Ca => Ok(ca_binding),
        lightning_client::settings::TlsVerification::Pinned => {
            fingerprint(&(ca_binding, node.tls_verification))
        }
    }
}

impl Entry {
    pub fn summary(&self, now: DateTime<Utc>, unresolved: Decimal) -> NodeSummary {
        let mut summary = NodeSummary {
            id: self.policy.node_id.clone(),
            kind: NodeKind::Lightning,
            read_availability: self.read_availability.clone(),
            label: self.label.clone(),
            backend: self.backend,
            network: Network::Unknown,
            identity_pubkey: None,
            identity_revision: None,
            read_only: self.policy.read_only,
            status: NodeStatus {
                node_id: self.policy.node_id.clone(),
                status: match self.unavailable {
                    Some(ErrorCode::NotConfigured) => NodeConnection::ConfigError,
                    _ => NodeConnection::Unsupported,
                },
                synced_to_chain: None,
                synced_to_graph: None,
                block_height: None,
                observed_at: None,
                checked_at: now,
                stale: true,
                error_code: Some(self.unavailable.unwrap_or(ErrorCode::NodeUnverified)),
            },
            capabilities: Capabilities::uniform(Some(if self.policy.read_only {
                CapabilityReason::ReadOnly
            } else {
                self.unavailable
                    .map(capability_reason)
                    .unwrap_or(CapabilityReason::Unverified)
            })),
            unresolved_operation_count: unresolved,
        };
        if let Ok(observation) = self.observation.lock() {
            if let Some((info, revision)) = observation.as_ref() {
                summary.network = info.network;
                summary.identity_pubkey = Some(info.identity_pubkey.clone());
                summary.identity_revision = Some(revision.clone());
                summary.status = info.status.clone();
                summary.status.stale |= info.status.observed_at.is_none_or(|at| {
                    now.signed_duration_since(at).num_seconds() >= i64::from(self.freshness_seconds)
                });
                let reason = if self.policy.read_only {
                    Some(CapabilityReason::ReadOnly)
                } else if let Some(code) = info.status.error_code {
                    Some(capability_reason(code))
                } else if summary.status.stale || info.status.status != NodeConnection::Online {
                    Some(CapabilityReason::NodeOffline)
                } else if info.status.synced_to_chain != Some(true) {
                    Some(CapabilityReason::Syncing)
                } else {
                    None
                };
                let payment_reason = reason.or_else(|| {
                    (info.status.synced_to_graph == Some(false))
                        .then_some(CapabilityReason::Syncing)
                });
                summary.capabilities = Capabilities {
                    pay_invoice: Capability {
                        enabled: payment_reason.is_none(),
                        reason: payment_reason,
                    },
                    ..Capabilities::uniform(reason)
                };
            }
        }
        if let Ok(error) = self.last_error.lock() {
            if let Some((checked, code)) = *error {
                summary.status.checked_at = checked;
                summary.status.error_code = Some(code);
                summary.status.stale = true;
                summary.status.status = match code {
                    ErrorCode::IdentityChanged | ErrorCode::NetworkMismatch => {
                        NodeConnection::IdentityMismatch
                    }
                    ErrorCode::NodeAuthError => NodeConnection::AuthError,
                    ErrorCode::NotConfigured => NodeConnection::ConfigError,
                    ErrorCode::Unsupported => NodeConnection::Unsupported,
                    _ => NodeConnection::Offline,
                };
                summary.capabilities = Capabilities::uniform(Some(if self.policy.read_only {
                    CapabilityReason::ReadOnly
                } else {
                    capability_reason(code)
                }));
            }
        }
        summary
    }
    pub fn observed_network(&self) -> Network {
        self.observation
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|(info, _)| info.network))
            .unwrap_or(Network::Unknown)
    }
}

fn capability_reason(code: ErrorCode) -> CapabilityReason {
    match code {
        ErrorCode::IdentityChanged | ErrorCode::NetworkMismatch | ErrorCode::NodeUnverified => {
            CapabilityReason::Unverified
        }
        ErrorCode::NotConfigured => CapabilityReason::NotConfigured,
        ErrorCode::Unsupported => CapabilityReason::Unsupported,
        ErrorCode::NodeAuthError => CapabilityReason::PermissionDenied,
        _ => CapabilityReason::NodeOffline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::InfoObservation;
    use lightning_client::model::Backend;

    fn observed_entry(now: DateTime<Utc>, backend: Backend, read_only: bool) -> Entry {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/api-examples.json")).unwrap();
        let mut policy: NodePolicy =
            serde_json::from_value(fixture["fixtures"]["node_policy"]["value"].clone()).unwrap();
        policy.read_only = read_only;
        let info = InfoObservation {
            identity_pubkey: "synthetic".into(),
            network: Network::Regtest,
            alias: None,
            version: None,
            status: NodeStatus {
                node_id: policy.node_id.clone(),
                status: NodeConnection::Online,
                synced_to_chain: Some(true),
                synced_to_graph: Some(false),
                block_height: None,
                observed_at: Some(now),
                checked_at: now,
                stale: false,
                error_code: None,
            },
        };
        Entry {
            read_availability: ReadAvailability::lightning(),
            policy,
            binding_revision: "synthetic-binding".into(),
            label: "Synthetic".into(),
            backend,
            unavailable: None,
            freshness_seconds: 30,
            observation: std::sync::Mutex::new(Some((info, "synthetic-revision".into()))),
            reads: tokio::sync::Mutex::new(crate::live::Cache::default()),
            last_error: std::sync::Mutex::new(None),
        }
    }

    fn assert_capabilities(
        summary: NodeSummary,
        common: Option<CapabilityReason>,
        payment: Option<CapabilityReason>,
    ) {
        assert_eq!(summary.kind, NodeKind::Lightning);
        let reads = serde_json::to_value(summary.read_availability).unwrap();
        for resource in [
            "payments",
            "invoices",
            "onchain",
            "channels",
            "peers",
            "operations",
        ] {
            assert_eq!(
                reads[resource],
                serde_json::json!({"enabled":true,"reason":null})
            );
        }
        let capabilities = serde_json::to_value(summary.capabilities).unwrap();
        assert_eq!(capabilities.as_object().unwrap().len(), 8);
        for (kind, capability) in capabilities.as_object().unwrap() {
            let reason = if kind == "pay_invoice" {
                payment
            } else {
                common
            };
            assert_eq!(
                *capability,
                serde_json::json!({"enabled": reason.is_none(), "reason": reason}),
                "{kind}"
            );
        }
    }

    #[test]
    fn registered_availability_is_independent_of_node_health() {
        let now = Utc::now();
        let entry = observed_entry(now, Backend::LndGrpc, false);
        let id = entry.policy.node_id.clone();
        let mut registry = Registry {
            nodes: BTreeMap::from([(id.clone(), entry)]),
            ..Registry::default()
        };
        let mut availability = ReadAvailability::lightning();
        availability.watchtower_client = Capability {
            enabled: false,
            reason: Some(CapabilityReason::PermissionDenied),
        };
        availability.watchtower_server = Capability {
            enabled: true,
            reason: None,
        };
        registry.register_availability(&id, availability.clone());
        let entry = registry.get(&id).unwrap();
        *entry.last_error.lock().unwrap() = Some((now, ErrorCode::NodeOffline));
        let summary = entry.summary(now, Decimal::ZERO);
        assert!(summary.status.stale);
        assert_eq!(
            serde_json::to_value(summary.read_availability).unwrap(),
            serde_json::to_value(availability).unwrap()
        );
    }

    #[test]
    fn sync_requirements_are_per_kind_on_every_backend() {
        let now = Utc::now();
        for backend in [Backend::ClnRest, Backend::LndRest, Backend::LndGrpc] {
            for read_only in [false, true] {
                for chain in [None, Some(false), Some(true)] {
                    for graph in [None, Some(false), Some(true)] {
                        let entry = observed_entry(now, backend, read_only);
                        {
                            let mut observation = entry.observation.lock().unwrap();
                            let status = &mut observation.as_mut().unwrap().0.status;
                            status.synced_to_chain = chain;
                            status.synced_to_graph = graph;
                        }
                        let common = if read_only {
                            Some(CapabilityReason::ReadOnly)
                        } else if chain != Some(true) {
                            Some(CapabilityReason::Syncing)
                        } else {
                            None
                        };
                        let payment = common.or_else(|| {
                            (graph == Some(false)).then_some(CapabilityReason::Syncing)
                        });
                        assert_capabilities(entry.summary(now, Decimal::ZERO), common, payment);
                    }
                }
            }
        }
    }

    #[test]
    fn common_failures_disable_every_kind_and_read_only_wins() {
        let now = Utc::now();
        for read_only in [false, true] {
            for (connection, stale, age, missing_time, error, expected) in [
                (
                    NodeConnection::Offline,
                    false,
                    0,
                    false,
                    None,
                    CapabilityReason::NodeOffline,
                ),
                (
                    NodeConnection::Online,
                    true,
                    0,
                    false,
                    None,
                    CapabilityReason::NodeOffline,
                ),
                (
                    NodeConnection::Online,
                    false,
                    30,
                    false,
                    None,
                    CapabilityReason::NodeOffline,
                ),
                (
                    NodeConnection::Online,
                    false,
                    0,
                    true,
                    None,
                    CapabilityReason::NodeOffline,
                ),
                (
                    NodeConnection::Offline,
                    true,
                    0,
                    false,
                    Some(ErrorCode::NodeAuthError),
                    CapabilityReason::PermissionDenied,
                ),
                (
                    NodeConnection::Online,
                    false,
                    0,
                    false,
                    Some(ErrorCode::IdentityChanged),
                    CapabilityReason::Unverified,
                ),
            ] {
                let entry = observed_entry(now, Backend::LndRest, read_only);
                {
                    let mut observation = entry.observation.lock().unwrap();
                    let status = &mut observation.as_mut().unwrap().0.status;
                    status.status = connection;
                    status.stale = stale;
                    status.observed_at =
                        (!missing_time).then_some(now - chrono::Duration::seconds(age));
                    status.error_code = error;
                }
                let reason = Some(if read_only {
                    CapabilityReason::ReadOnly
                } else {
                    expected
                });
                assert_capabilities(entry.summary(now, Decimal::ZERO), reason, reason);
            }
            for code in [
                ErrorCode::NodeOffline,
                ErrorCode::NodeAuthError,
                ErrorCode::IdentityChanged,
                ErrorCode::NetworkMismatch,
                ErrorCode::NotConfigured,
                ErrorCode::Unsupported,
            ] {
                let entry = observed_entry(now, Backend::LndGrpc, read_only);
                *entry.last_error.lock().unwrap() = Some((now, code));
                let summary = entry.summary(now, Decimal::ZERO);
                assert!(summary.status.stale);
                assert_eq!(summary.status.error_code, Some(code));
                let reason = Some(if read_only {
                    CapabilityReason::ReadOnly
                } else {
                    capability_reason(code)
                });
                assert_capabilities(summary, reason, reason);
            }
        }
    }
}
