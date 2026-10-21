use lightning_client::model::*;

pub(super) enum ReadQuery {
    Info,
    Balances,
    Invoices,
    Payments,
    Peers,
    Channels,
    Transactions,
    Fees,
}
pub(super) struct Collection<T> {
    pub items: Vec<T>,
    pub truncated: bool,
}
// The adapter does not own registry policy, capability publication or journal counts.
pub(super) struct InfoObservation {
    pub identity_pubkey: String,
    pub network: Network,
    pub alias: Option<String>,
    pub version: Option<String>,
    pub status: NodeStatus,
}
pub(super) enum ReadResult {
    Info(InfoObservation),
    Balances(Balances),
    Invoices(Collection<Invoice>),
    Payments(Collection<Payment>),
    Peers(Collection<Peer>),
    Channels(Collection<Channel>),
    Transactions(Collection<Transaction>),
    Fees(FeeEstimates),
}
