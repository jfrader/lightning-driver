use lightning_client::model::*;

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
