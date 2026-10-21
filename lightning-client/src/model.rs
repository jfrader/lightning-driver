use crate::money::{Decimal, Msat, Sat};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type Timestamp = DateTime<Utc>;

macro_rules! wire_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}

wire_enum!(Network {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
    Unknown
});
wire_enum!(VerifiedNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest
});

#[derive(Debug, thiserror::Error)]
#[error("Node network has not been verified")]
pub struct UnverifiedNetwork;

impl TryFrom<Network> for VerifiedNetwork {
    type Error = UnverifiedNetwork;
    fn try_from(network: Network) -> Result<Self, Self::Error> {
        match network {
            Network::Mainnet => Ok(Self::Mainnet),
            Network::Testnet => Ok(Self::Testnet),
            Network::Signet => Ok(Self::Signet),
            Network::Regtest => Ok(Self::Regtest),
            Network::Unknown => Err(UnverifiedNetwork),
        }
    }
}
wire_enum!(Backend {
    LndGrpc,
    LndRest,
    ClnRest
});
wire_enum!(NodeConnection {
    Connecting,
    Online,
    Offline,
    AuthError,
    ConfigError,
    Unsupported,
    IdentityMismatch
});
wire_enum!(CapabilityReason {
    ReadOnly,
    Unsupported,
    NodeOffline,
    Unverified,
    NotConfigured,
    PermissionDenied,
    Syncing
});
wire_enum!(InvoiceState {
    Unpaid,
    Accepted,
    Paid,
    Expired,
    Canceled,
    Unknown
});
wire_enum!(PaymentState {
    Pending,
    Succeeded,
    Failed,
    Unknown
});
wire_enum!(ChannelState {
    Opening,
    Active,
    Inactive,
    Closing,
    Closed,
    Unknown
});
wire_enum!(CloseType {
    Cooperative,
    Unilateral,
    Unknown
});
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Incoming,
    Outgoing,
    #[serde(rename = "self")]
    SelfTransfer,
    Unknown,
}
wire_enum!(OperationKind {
    CreateInvoice,
    PayInvoice,
    ConnectPeer,
    DisconnectPeer,
    OpenChannel,
    CloseChannel,
    NewAddress,
    SendOnchain
});
wire_enum!(OperationState {
    AwaitingConfirmation,
    Dispatching,
    Pending,
    Unknown,
    Succeeded,
    Failed,
    Expired
});
wire_enum!(OperationStage {
    NotDispatched,
    Submitted,
    Reconciling,
    Broadcast,
    Confirmed,
    Settled,
    ChannelActive,
    ChannelClosed,
    Completed
});
wire_enum!(FeeControl {
    None,
    AbsoluteRoutingLimit,
    RequestedOnchainRate,
    CooperativeNegotiation
});
wire_enum!(AuthorizationState {
    NotRequired,
    Required,
    Authorized,
    Consumed
});
wire_enum!(ReauthMode {
    EveryOperation,
    Recent
});
wire_enum!(ErrorOutcome {
    NotApplicable,
    NotDispatched,
    DefiniteFailure,
    Unknown
});
wire_enum!(ErrorCode {
    InvalidRequest,
    InvalidCursor,
    CursorExpired,
    UnsupportedMediaType,
    SessionRequired,
    Csrf,
    Origin,
    AuthenticationFailed,
    ChallengeExpired,
    ChallengeInvalid,
    EnrollmentUnavailable,
    ReadOnly,
    NotFound,
    Unsupported,
    NotConfigured,
    NodeOffline,
    NodeAuthError,
    NodeSyncing,
    NodeUnverified,
    IdentityChanged,
    PolicyChanged,
    PolicyViolation,
    InvalidAmount,
    InvalidInvoice,
    InvoiceExpired,
    NetworkMismatch,
    InvalidAddress,
    InvalidPeer,
    IdempotencyConflict,
    ResourceBusy,
    AlreadyPaid,
    ReviewExpired,
    ReviewMismatch,
    ReauthRequired,
    AuthorizationInvalid,
    AuthorizationNotRequired,
    OperationNotReviewable,
    InsufficientFunds,
    NoRoute,
    FeeLimitExceeded,
    PeerUnavailable,
    UpstreamRejected,
    UpstreamInvalidResponse,
    OutcomeUnknown,
    UnexpectedUnilateralClose,
    StorageUnavailable,
    RateLimited,
    InternalError
});

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: ErrorCode,
    pub message: String,
    pub request_id: Uuid,
    pub operation_id: Option<Uuid>,
    pub outcome: ErrorOutcome,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    pub enabled: bool,
    pub reason: Option<CapabilityReason>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub create_invoice: Capability,
    pub pay_invoice: Capability,
    pub connect_peer: Capability,
    pub disconnect_peer: Capability,
    pub open_channel: Capability,
    pub close_channel: Capability,
    pub new_address: Capability,
    pub send_onchain: Capability,
}

impl Capabilities {
    pub fn uniform(reason: Option<CapabilityReason>) -> Self {
        let capability = Capability {
            enabled: reason.is_none(),
            reason,
        };
        Self {
            create_invoice: capability.clone(),
            pay_invoice: capability.clone(),
            connect_peer: capability.clone(),
            disconnect_peer: capability.clone(),
            open_channel: capability.clone(),
            close_channel: capability.clone(),
            new_address: capability.clone(),
            send_onchain: capability,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node_id: String,
    pub status: NodeConnection,
    pub synced_to_chain: Option<bool>,
    pub synced_to_graph: Option<bool>,
    pub block_height: Option<Decimal>,
    pub observed_at: Option<Timestamp>,
    pub checked_at: Timestamp,
    pub stale: bool,
    pub error_code: Option<ErrorCode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSummary {
    pub id: String,
    pub label: String,
    pub backend: Backend,
    pub network: Network,
    pub identity_pubkey: Option<String>,
    pub identity_revision: Option<String>,
    pub read_only: bool,
    pub status: NodeStatus,
    pub capabilities: Capabilities,
    pub unresolved_operation_count: Decimal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeBinding {
    pub node_id: String,
    pub network: VerifiedNetwork,
    pub identity_pubkey: String,
    pub identity_revision: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node: NodeSummary,
    pub alias: Option<String>,
    pub version: Option<String>,
    pub observed_at: Timestamp,
    pub stale: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Balances {
    pub node_id: String,
    pub network: Network,
    pub onchain_confirmed_sat: Option<Sat>,
    pub onchain_unconfirmed_sat: Option<Sat>,
    pub onchain_spendable_sat: Option<Sat>,
    pub channel_local_msat: Option<Msat>,
    pub channel_remote_msat: Option<Msat>,
    pub channel_spendable_msat: Option<Msat>,
    pub observed_at: Timestamp,
    pub stale: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invoice {
    pub payment_hash: String,
    pub amount_msat: Option<Msat>,
    pub received_msat: Option<Msat>,
    pub state: InvoiceState,
    pub backend_state: String,
    pub bolt11: Option<String>,
    pub description: Option<String>,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub paid_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payment {
    pub payment_hash: String,
    pub amount_msat: Option<Msat>,
    pub fee_msat: Option<Msat>,
    pub destination: Option<String>,
    pub state: PaymentState,
    pub backend_state: String,
    pub created_at: Timestamp,
    pub completed_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    pub pubkey: String,
    pub connected: bool,
    pub address: Option<String>,
    pub inbound: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    pub peer_pubkey: String,
    pub funding_outpoint: Option<String>,
    pub short_channel_id: Option<String>,
    pub state: ChannelState,
    pub backend_state: String,
    pub private: Option<bool>,
    pub capacity_sat: Option<Sat>,
    pub local_msat: Option<Msat>,
    pub remote_msat: Option<Msat>,
    pub spendable_msat: Option<Msat>,
    pub close_type: Option<CloseType>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionOutput {
    pub index: u32,
    pub address: Option<String>,
    pub amount_sat: Sat,
    pub is_ours: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub txid: String,
    pub direction: Direction,
    pub amount_sat: Option<Sat>,
    pub fee_sat: Option<Sat>,
    pub confirmations: Option<Decimal>,
    pub block_height: Option<Decimal>,
    pub occurred_at: Option<Timestamp>,
    pub outputs: Vec<TransactionOutput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub fee_rate_sat_vbyte: Decimal,
    pub target_blocks: Option<u32>,
    pub estimated_at: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeEstimates {
    pub node_id: String,
    pub observed_at: Option<Timestamp>,
    pub stale: bool,
    pub economy: Option<FeeEstimate>,
    pub normal: Option<FeeEstimate>,
    pub priority: Option<FeeEstimate>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecodedInvoice {
    pub payment_hash: String,
    pub network: Network,
    pub network_matches_node: Option<bool>,
    pub destination: String,
    pub amount_msat: Option<Msat>,
    pub description: Option<String>,
    pub description_hash: Option<String>,
    pub requires_description: bool,
    pub expires_at: Timestamp,
    pub expired: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInvoice {
    pub amount_msat: Msat,
    pub description: String,
    pub expiry_seconds: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayInvoice {
    pub bolt11: String,
    #[serde(deserialize_with = "required_optional")]
    pub amount_msat: Option<Msat>,
    pub max_fee_msat: Msat,
    #[serde(deserialize_with = "required_optional")]
    pub description: Option<String>,
}

fn required_optional<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectPeer {
    pub pubkey: String,
    pub host: String,
    pub port: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisconnectPeer {
    pub pubkey: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenChannel {
    pub peer_pubkey: String,
    pub amount_sat: Sat,
    pub private: bool,
    pub fee_rate_sat_vbyte: Decimal,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseChannel {
    pub channel_id: String,
    pub fee_rate_sat_vbyte: Decimal,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AddressType {
    #[serde(rename = "p2wpkh")]
    P2wpkh,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewAddress {
    pub address_type: AddressType,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendOnchain {
    pub address: String,
    pub amount_sat: Sat,
    pub fee_rate_sat_vbyte: Decimal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OperationRequest {
    CreateInvoice(CreateInvoice),
    PayInvoice(PayInvoice),
    ConnectPeer(ConnectPeer),
    DisconnectPeer(DisconnectPeer),
    OpenChannel(OpenChannel),
    CloseChannel(CloseChannel),
    NewAddress(NewAddress),
    SendOnchain(SendOnchain),
}

impl OperationRequest {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::CreateInvoice(_) => OperationKind::CreateInvoice,
            Self::PayInvoice(_) => OperationKind::PayInvoice,
            Self::ConnectPeer(_) => OperationKind::ConnectPeer,
            Self::DisconnectPeer(_) => OperationKind::DisconnectPeer,
            Self::OpenChannel(_) => OperationKind::OpenChannel,
            Self::CloseChannel(_) => OperationKind::CloseChannel,
            Self::NewAddress(_) => OperationKind::NewAddress,
            Self::SendOnchain(_) => OperationKind::SendOnchain,
        }
    }
    pub fn sensitive(&self) -> bool {
        matches!(
            self,
            Self::PayInvoice(_)
                | Self::OpenChannel(_)
                | Self::CloseChannel(_)
                | Self::SendOnchain(_)
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeReview {
    pub control: FeeControl,
    pub max_fee_msat: Option<Msat>,
    pub fee_rate_sat_vbyte: Option<Decimal>,
    pub fee_estimate_sat: Option<Sat>,
    pub estimate_only: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationReview {
    pub operation_id: Uuid,
    pub node: NodeBinding,
    pub policy_revision: String,
    pub digest: String,
    pub expires_at: Timestamp,
    pub sensitive: bool,
    pub amount_sat: Option<Sat>,
    pub amount_msat: Option<Msat>,
    pub destination: Option<String>,
    pub peer_pubkey: Option<String>,
    pub channel_id: Option<String>,
    pub payment_hash: Option<String>,
    pub fee: FeeReview,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationStatus {
    pub status: AuthorizationState,
    pub mode: ReauthMode,
    pub expires_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationResult {
    CreateInvoice {
        payment_hash: String,
        bolt11: String,
    },
    PayInvoice {
        payment_hash: String,
        amount_msat: Msat,
        fee_msat: Option<Msat>,
    },
    ConnectPeer {
        pubkey: String,
        connected: bool,
    },
    DisconnectPeer {
        pubkey: String,
        connected: bool,
    },
    OpenChannel {
        channel_id: Option<String>,
        funding_outpoint: Option<String>,
    },
    CloseChannel {
        channel_id: String,
        close_type: CloseType,
        txids: Vec<String>,
        confirmations: Option<Decimal>,
    },
    NewAddress {
        address: String,
        address_type: AddressType,
    },
    SendOnchain {
        txid: String,
        amount_sat: Sat,
        fee_sat: Option<Sat>,
        confirmations: Option<Decimal>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Operation {
    pub id: Uuid,
    pub node_id: String,
    pub request: OperationRequest,
    pub review: OperationReview,
    pub state: OperationState,
    pub stage: OperationStage,
    pub authorization: AuthorizationStatus,
    pub result: Option<OperationResult>,
    pub error: Option<ErrorDetail>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_reconciled_at: Option<Timestamp>,
}

impl Operation {
    pub fn binding_is_valid(&self) -> bool {
        self.id == self.review.operation_id
            && self.node_id == self.review.node.node_id
            && self.request.sensitive() == self.review.sensitive
            && !self.review.policy_revision.is_empty()
            && !self.review.node.identity_revision.is_empty()
    }
}

impl OperationState {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Expired)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Page<T> {
    pub node_id: Option<String>,
    pub network: Option<Network>,
    pub next_cursor: Option<String>,
    pub observed_at: Timestamp,
    pub stale: bool,
    pub truncated: bool,
    pub items: Vec<T>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use serde_json::Value;

    fn roundtrip<T: DeserializeOwned + Serialize>(fixtures: &Value, name: &str) {
        let original = &fixtures["fixtures"][name]["value"];
        let value: T = serde_json::from_value(original.clone())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            serde_json::to_value(value).unwrap(),
            *original,
            "fixture {name} changed on roundtrip"
        );
    }

    #[test]
    fn frozen_financial_fixtures_roundtrip_without_dropping_fields() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../api-server/tests/fixtures/api-examples.json"
        ))
        .unwrap();
        for name in ["node_lnd", "node_lnd_rest_readonly_offline", "node_cln"] {
            roundtrip::<NodeSummary>(&fixtures, name);
        }
        roundtrip::<NodeInfo>(&fixtures, "node_info");
        roundtrip::<NodeStatus>(&fixtures, "node_status");
        roundtrip::<FeeEstimates>(&fixtures, "fee_estimates");
        roundtrip::<DecodedInvoice>(&fixtures, "decode");
        for name in ["balances", "balances_stale"] {
            roundtrip::<Balances>(&fixtures, name);
        }
        roundtrip::<Page<NodeSummary>>(&fixtures, "nodes_page");
        roundtrip::<Page<Invoice>>(&fixtures, "invoices_page");
        roundtrip::<Page<Payment>>(&fixtures, "payments_page");
        roundtrip::<Page<Peer>>(&fixtures, "peers_page");
        roundtrip::<Page<Channel>>(&fixtures, "channels_page");
        roundtrip::<Page<Channel>>(&fixtures, "empty_channels_page");
        roundtrip::<Page<Transaction>>(&fixtures, "transactions_page");
        roundtrip::<Page<Operation>>(&fixtures, "operations_page");
        for name in [
            "operation_review",
            "operation_pending",
            "operation_unknown",
            "operation_settled",
            "operation_broadcast",
        ] {
            roundtrip::<Operation>(&fixtures, name);
        }
        for case in fixtures["operation_cases"].as_array().unwrap() {
            roundtrip::<OperationRequest>(&fixtures, case["request_fixture"].as_str().unwrap());
            roundtrip::<OperationReview>(&fixtures, case["review_fixture"].as_str().unwrap());
            roundtrip::<OperationResult>(&fixtures, case["result_fixture"].as_str().unwrap());
        }
        assert_eq!(
            serde_json::to_string(&Direction::SelfTransfer).unwrap(),
            "\"self\""
        );
        assert!(serde_json::from_str::<VerifiedNetwork>("\"unknown\"").is_err());
        assert!(VerifiedNetwork::try_from(Network::Unknown).is_err());
    }

    #[test]
    fn mutation_boundary_rejects_omitted_nullable_fields_and_extra_flags() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../api-server/tests/fixtures/api-examples.json"
        ))
        .unwrap();
        let mut request = fixtures["fixtures"]["pay_invoice_request"]["value"].clone();
        request["params"]
            .as_object_mut()
            .unwrap()
            .remove("amount_msat");
        assert!(serde_json::from_value::<OperationRequest>(request).is_err());
        let mut request = fixtures["fixtures"]["close_channel_request"]["value"].clone();
        request["params"]["force"] = Value::Bool(true);
        assert!(serde_json::from_value::<OperationRequest>(request).is_err());
        let mut request = fixtures["fixtures"]["send_onchain_request"]["value"].clone();
        request["params"]["amount_sat"] = serde_json::json!(10000);
        assert!(serde_json::from_value::<OperationRequest>(request).is_err());
    }
}
