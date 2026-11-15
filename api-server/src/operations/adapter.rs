use lightning_client::model::*;

pub(super) fn online_status(
    node_id: &str,
    synced_to_chain: Option<bool>,
    synced_to_graph: Option<bool>,
    block_height: Option<lightning_client::money::Decimal>,
    now: chrono::DateTime<chrono::Utc>,
) -> NodeStatus {
    NodeStatus {
        node_id: node_id.to_owned(),
        status: NodeConnection::Online,
        synced_to_chain,
        synced_to_graph,
        block_height,
        observed_at: Some(now),
        checked_at: now,
        stale: false,
        error_code: None,
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ReadQuery {
    Info,
    Balances,
    Invoices,
    Payments,
    Peers,
    Channels,
    Transactions,
    Fees,
    Bitcoin,
    BitcoinPeers,
    WatchtowerServer,
    WatchtowerClient,
    WatchtowerTowers,
    WatchtowerTower([u8; 33]),
}
impl ReadQuery {
    pub(crate) fn is_watchtower(self) -> bool {
        matches!(
            self,
            Self::WatchtowerServer
                | Self::WatchtowerClient
                | Self::WatchtowerTowers
                | Self::WatchtowerTower(_)
        )
    }
}
#[derive(Clone)]
pub(crate) struct Collection<T> {
    pub items: Vec<T>,
    pub truncated: bool,
}
// The adapter does not own registry policy, capability publication or journal counts.
#[derive(Clone)]
pub(crate) struct InfoObservation {
    pub identity_pubkey: String,
    pub network: Network,
    pub alias: Option<String>,
    pub version: Option<String>,
    pub status: NodeStatus,
}
#[derive(Clone)]
pub(crate) enum ReadResult {
    Info(InfoObservation),
    Balances(Balances),
    Invoices(Collection<Invoice>),
    Payments(Collection<Payment>),
    Peers(Collection<Peer>),
    Channels(Collection<Channel>),
    Transactions(Collection<Transaction>),
    Fees(FeeEstimates),
    Bitcoin(BitcoinNodeInfo),
    BitcoinPeers(Collection<BitcoinPeer>),
    WatchtowerServer(WatchtowerServerInfo),
    WatchtowerClient(WatchtowerClientInfo),
    WatchtowerTowers(Collection<WatchtowerTower>),
    WatchtowerTower(WatchtowerTowerDetail),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn online_status_keeps_optional_adapter_fields_and_observation_time() {
        let now = chrono::Utc::now();
        for (chain, graph, height) in [
            (None, None, None),
            (Some(false), Some(true), Some("42".parse().unwrap())),
            (Some(true), None, Some("0".parse().unwrap())),
        ] {
            let status = online_status("node", chain, graph, height, now);
            assert_eq!(status.node_id, "node");
            assert_eq!(status.status, NodeConnection::Online);
            assert_eq!(status.synced_to_chain, chain);
            assert_eq!(status.synced_to_graph, graph);
            assert_eq!(status.block_height, height);
            assert_eq!(status.observed_at, Some(now));
            assert_eq!(status.checked_at, now);
            assert!(!status.stale);
            assert_eq!(status.error_code, None);
        }
    }
}
