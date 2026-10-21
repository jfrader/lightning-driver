use super::*;
use lightning_client::money::{Decimal, Msat, Sat};

#[derive(Clone, Copy, Serialize, Deserialize)]
pub(super) enum Rejection {
    InsufficientFunds,
    NoRoute,
    FeeLimit,
    PeerUnavailable,
    Refused,
}
impl Rejection {
    fn code(self) -> ErrorCode {
        match self {
            Self::InsufficientFunds => ErrorCode::InsufficientFunds,
            Self::NoRoute => ErrorCode::NoRoute,
            Self::FeeLimit => ErrorCode::FeeLimitExceeded,
            Self::PeerUnavailable => ErrorCode::PeerUnavailable,
            Self::Refused => ErrorCode::UpstreamRejected,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) enum Class {
    Rejected(Rejection),
    Positive,
    Lost,
    NotFound,
    Partial,
    Pruned,
    Conflict,
    // Exact hash evidence can exclude payment without attributing an older attempt's settlement.
    PaidElsewhere,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) enum Facts {
    Invoice {
        payment_hash: String,
        bolt11: String,
    },
    Payment {
        payment_hash: String,
        amount_msat: Msat,
        fee_msat: Option<Msat>,
        settled: bool,
    },
    Peer {
        pubkey: String,
        connected: bool,
        complete: bool,
    },
    Open {
        channel_id: Option<String>,
        funding_outpoint: Option<String>,
        active: bool,
        published: bool,
    },
    Close {
        channel: String,
        close_type: CloseType,
        txids: Vec<String>,
        confirmations: Option<Decimal>,
        closed: bool,
        published: bool,
    },
    Address {
        address: String,
    },
    Send {
        txid: String,
        amount_sat: Sat,
        fee_sat: Option<Sat>,
        confirmations: Option<Decimal>,
        published: bool,
    },
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Evidence {
    pub operation_id: Uuid,
    pub binding: NodeBinding,
    pub generation: Uuid,
    pub kind: OperationKind,
    pub claim_id: Uuid,
    pub sequence: i64,
    pub reference: RecoveryReference,
    pub class: Class,
    pub facts: Option<Facts>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Knowledge {
    pub reference: RecoveryReference,
    pub sequence: i64,
    pub facts_sequence: i64,
    pub accepted: bool,
    pub published: bool,
    pub conflict: bool,
}
impl Knowledge {
    pub fn new(intent: &ReviewedIntent) -> Self {
        Self {
            reference: RecoveryReference::planned(intent),
            sequence: 0,
            facts_sequence: 0,
            accepted: false,
            published: false,
            conflict: false,
        }
    }
}
pub(super) struct Transition {
    pub operation: Operation,
    pub knowledge: Knowledge,
    pub release: bool,
    pub paid_hash: Option<String>,
}

fn detail(operation: Uuid, code: ErrorCode, outcome: ErrorOutcome) -> ErrorDetail {
    ErrorDetail {
        code,
        message: match code {
            ErrorCode::OutcomeUnknown => "Operation outcome is unknown.",
            ErrorCode::UpstreamInvalidResponse => "Node response could not be verified.",
            ErrorCode::UnexpectedUnilateralClose => "Channel closed unilaterally.",
            _ => "Node rejected the operation.",
        }
        .into(),
        request_id: Uuid::new_v4(),
        operation_id: Some(operation),
        outcome,
    }
}
fn txid(text: &str) -> bool {
    text.parse::<bitcoin::Txid>().is_ok() && text == text.to_ascii_lowercase()
}
fn outpoint(text: &str) -> bool {
    text.parse::<bitcoin::OutPoint>().is_ok()
}

fn merge_reference(
    old: &RecoveryReference,
    new: &RecoveryReference,
    allow_new: bool,
) -> Result<RecoveryReference> {
    let mut merged = old.clone();
    for (target, incoming) in [
        (&mut merged.payment_hash, &new.payment_hash),
        (&mut merged.invoice_label, &new.invoice_label),
        (&mut merged.peer, &new.peer),
        (&mut merged.channel, &new.channel),
        (&mut merged.txid, &new.txid),
        (&mut merged.address, &new.address),
        (&mut merged.attempt, &new.attempt),
    ] {
        if let Some(value) = incoming {
            if value.is_empty()
                || value.len() > 512
                || target.as_ref().is_some_and(|previous| previous != value)
                || (target.is_none() && !allow_new)
            {
                return Err(failure(ErrorCode::UpstreamInvalidResponse));
            }
            *target = Some(value.clone());
        }
    }
    Ok(merged)
}

pub(super) struct ObservationContext {
    pub claim_id: Uuid,
    pub allocated_sequence: i64,
    pub read: bool,
    pub now: DateTime<Utc>,
}

pub(super) fn transition(
    intent: &ReviewedIntent,
    mut operation: Operation,
    mut knowledge: Knowledge,
    evidence: Evidence,
    context: ObservationContext,
) -> Result<Transition> {
    let ObservationContext {
        claim_id,
        allocated_sequence,
        read,
        now,
    } = context;
    if evidence.operation_id != operation.id
        || evidence.binding != operation.review.node
        || evidence.generation != intent.connection_generation
        || evidence.kind != operation.request.kind()
        || evidence.claim_id != claim_id
        || (read && (evidence.sequence <= 0 || evidence.sequence > allocated_sequence))
        || (!read && evidence.sequence != 0)
    {
        return Err(failure(ErrorCode::UpstreamInvalidResponse));
    }
    let preknown = matches!(
        operation.request,
        OperationRequest::CreateInvoice(_)
            | OperationRequest::ConnectPeer(_)
            | OperationRequest::DisconnectPeer(_)
            | OperationRequest::CloseChannel(_)
    );
    let r = &evidence.reference;
    let shaped = match operation.request {
        OperationRequest::CreateInvoice(_) => RecoveryReference {
            payment_hash: r.payment_hash.clone(),
            invoice_label: r.invoice_label.clone(),
            ..RecoveryReference::default()
        },
        OperationRequest::PayInvoice(_) => RecoveryReference {
            payment_hash: r.payment_hash.clone(),
            attempt: r.attempt.clone(),
            ..RecoveryReference::default()
        },
        OperationRequest::ConnectPeer(_) | OperationRequest::DisconnectPeer(_) => {
            RecoveryReference {
                peer: r.peer.clone(),
                ..RecoveryReference::default()
            }
        }
        OperationRequest::OpenChannel(_) | OperationRequest::CloseChannel(_) => RecoveryReference {
            peer: r.peer.clone(),
            channel: r.channel.clone(),
            ..RecoveryReference::default()
        },
        OperationRequest::NewAddress(_) => RecoveryReference {
            address: r.address.clone(),
            ..RecoveryReference::default()
        },
        OperationRequest::SendOnchain(_) => RecoveryReference {
            txid: r.txid.clone(),
            ..RecoveryReference::default()
        },
    };
    if shaped != evidence.reference {
        return Err(failure(ErrorCode::UpstreamInvalidResponse));
    }
    if read && matches!(evidence.class, Class::Rejected(_)) {
        let linked = match operation.request {
            OperationRequest::PayInvoice(_) => {
                knowledge.reference.payment_hash.is_some() && knowledge.reference.attempt.is_some()
            }
            OperationRequest::SendOnchain(_) => knowledge.reference.txid.is_some(),
            OperationRequest::OpenChannel(_) | OperationRequest::CloseChannel(_) => {
                knowledge.reference.channel.is_some()
            }
            OperationRequest::NewAddress(_) => knowledge.reference.address.is_some(),
            OperationRequest::CreateInvoice(_) => {
                knowledge.reference.payment_hash.is_some()
                    || knowledge.reference.invoice_label.is_some()
            }
            OperationRequest::ConnectPeer(_) | OperationRequest::DisconnectPeer(_) => {
                knowledge.reference.peer.is_some()
            }
        };
        if !linked || evidence.reference != knowledge.reference {
            return Err(failure(ErrorCode::UpstreamInvalidResponse));
        }
    }
    if read
        && matches!(evidence.class, Class::Positive)
        && matches!(operation.request, OperationRequest::PayInvoice(_))
        && (knowledge.reference.attempt.is_none()
            || evidence.reference.attempt != knowledge.reference.attempt)
    {
        return Err(failure(ErrorCode::UpstreamInvalidResponse));
    }
    let reference = merge_reference(&knowledge.reference, &evidence.reference, !read || preknown)?;
    let original = serde_json::to_value(&operation)?;
    let terminal = operation.state.terminal();
    let mut paid_hash = None;
    let mut release = false;
    // Older completion/publication may add knowledge, but never overwrite newer measurements.
    let fresh =
        evidence.sequence > knowledge.facts_sequence || (!read && knowledge.facts_sequence == 0);
    match evidence.class {
        Class::PaidElsewhere => {
            if !matches!(operation.request, OperationRequest::PayInvoice(_))
                || evidence.reference.payment_hash != operation.review.payment_hash
            {
                return Err(failure(ErrorCode::UpstreamInvalidResponse));
            }
            paid_hash = operation.review.payment_hash.clone();
        }
        Class::Positive => {
            let facts = evidence
                .facts
                .ok_or_else(|| failure(ErrorCode::UpstreamInvalidResponse))?;
            let (result, stage, success, published, unilateral) =
                positive(intent, &reference, facts)?;
            let result = merge_result(operation.result.clone(), result, fresh)?;
            if !terminal {
                operation.result = Some(result);
                operation.state = if unilateral {
                    OperationState::Failed
                } else if success {
                    OperationState::Succeeded
                } else {
                    OperationState::Pending
                };
                operation.stage = progress(operation.stage, stage, operation.request.kind());
                operation.error = if unilateral {
                    Some(detail(
                        operation.id,
                        ErrorCode::UnexpectedUnilateralClose,
                        ErrorOutcome::DefiniteFailure,
                    ))
                } else {
                    None
                };
                release = operation.state.terminal();
                if success && matches!(operation.request, OperationRequest::PayInvoice(_)) {
                    paid_hash = operation.review.payment_hash.clone();
                }
            } else if matches!(
                operation.state,
                OperationState::Succeeded | OperationState::Failed
            ) {
                // Only refresh same-identity terminal send/close facts, never outcome or close type.
                if matches!(
                    operation.result,
                    Some(
                        OperationResult::SendOnchain { .. } | OperationResult::CloseChannel { .. }
                    )
                ) {
                    operation.result = Some(result);
                    if operation.state == OperationState::Succeeded {
                        operation.stage =
                            progress(operation.stage, stage, operation.request.kind());
                    }
                }
            }
            knowledge.accepted = true;
            knowledge.published |= published;
            if fresh {
                knowledge.facts_sequence = evidence.sequence;
            }
        }
        Class::Rejected(rejection) => {
            if !terminal {
                operation.state = OperationState::Failed;
                operation.error = Some(detail(
                    operation.id,
                    rejection.code(),
                    ErrorOutcome::DefiniteFailure,
                ));
                release = true;
            } else if operation.state != OperationState::Failed {
                knowledge.conflict = true;
            }
        }
        Class::Lost | Class::NotFound | Class::Partial | Class::Pruned | Class::Conflict => {
            if matches!(evidence.class, Class::Conflict) {
                knowledge.conflict = true;
            }
            if !terminal && !knowledge.accepted {
                operation.state = OperationState::Unknown;
                operation.stage = OperationStage::Reconciling;
                let code = if matches!(evidence.class, Class::Partial | Class::Conflict) {
                    ErrorCode::UpstreamInvalidResponse
                } else {
                    ErrorCode::OutcomeUnknown
                };
                // Repeated identical inconclusive evidence does not generate a new public error UUID.
                if operation
                    .error
                    .as_ref()
                    .is_none_or(|error| error.code != code)
                {
                    operation.error = Some(detail(operation.id, code, ErrorOutcome::Unknown));
                }
            }
        }
    }
    knowledge.reference = reference;
    knowledge.sequence = knowledge.sequence.max(evidence.sequence);
    // Compare before changing timestamps; last_reconciled tracks reads, not RPC responses.
    if serde_json::to_value(&operation)? != original {
        operation.updated_at = now;
    }
    if read && evidence.sequence >= knowledge.sequence {
        operation.last_reconciled_at = Some(
            operation
                .last_reconciled_at
                .map_or(now, |previous| previous.max(now)),
        );
    }
    Ok(Transition {
        operation,
        knowledge,
        release,
        paid_hash,
    })
}

fn positive(
    intent: &ReviewedIntent,
    reference: &RecoveryReference,
    facts: Facts,
) -> Result<(OperationResult, OperationStage, bool, bool, bool)> {
    let op = &intent.operation;
    let r = &op.review;
    let invalid = || failure(ErrorCode::UpstreamInvalidResponse);
    let result = match (&op.request, facts) {
        (
            OperationRequest::CreateInvoice(p),
            Facts::Invoice {
                payment_hash,
                bolt11,
            },
        ) => {
            let decoded = lightning_client::validation::decode(
                &bolt11,
                intent::network(&r.node),
                op.created_at,
            )
            .map_err(|_| invalid())?;
            let parsed = bolt11
                .parse::<lightning_invoice::Bolt11Invoice>()
                .map_err(|_| invalid())?;
            let description_matches = match parsed.description() {
                lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(description) => {
                    description.as_inner().0 == p.description
                }
                lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(hash) => {
                    use bitcoin::hashes::Hash;
                    hash.0 == bitcoin::hashes::sha256::Hash::hash(p.description.as_bytes())
                }
            };
            if decoded.payment_hash != payment_hash
                || decoded.amount_msat != Some(p.amount_msat)
                || parsed.expiry_time().as_secs() != u64::from(p.expiry_seconds)
                || !description_matches
                || decoded.network_matches_node != Some(true)
                || reference
                    .payment_hash
                    .as_ref()
                    .is_some_and(|hash| hash != &payment_hash)
                || (reference.payment_hash.is_none()
                    && reference.invoice_label != intent.invoice_label)
            {
                return Err(invalid());
            }
            (
                OperationResult::CreateInvoice {
                    payment_hash,
                    bolt11,
                },
                OperationStage::Completed,
                true,
                false,
                false,
            )
        }
        (
            OperationRequest::PayInvoice(p),
            Facts::Payment {
                payment_hash,
                amount_msat,
                fee_msat,
                settled,
            },
        ) => {
            if Some(&payment_hash) != r.payment_hash.as_ref()
                || reference.payment_hash.as_ref() != Some(&payment_hash)
                || Some(amount_msat) != r.amount_msat
                || fee_msat.is_some_and(|fee| fee > p.max_fee_msat)
            {
                return Err(invalid());
            }
            (
                OperationResult::PayInvoice {
                    payment_hash,
                    amount_msat,
                    fee_msat,
                },
                if settled {
                    OperationStage::Settled
                } else {
                    OperationStage::Submitted
                },
                settled,
                false,
                false,
            )
        }
        (
            OperationRequest::ConnectPeer(p),
            Facts::Peer {
                pubkey,
                connected,
                complete,
            },
        ) if pubkey == p.pubkey
            && connected
            && complete
            && reference.peer.as_ref() == Some(&pubkey) =>
        {
            (
                OperationResult::ConnectPeer { pubkey, connected },
                OperationStage::Completed,
                true,
                false,
                false,
            )
        }
        (
            OperationRequest::DisconnectPeer(p),
            Facts::Peer {
                pubkey,
                connected,
                complete,
            },
        ) if pubkey == p.pubkey
            && !connected
            && complete
            && reference.peer.as_ref() == Some(&pubkey) =>
        {
            (
                OperationResult::DisconnectPeer { pubkey, connected },
                OperationStage::Completed,
                true,
                false,
                false,
            )
        }
        (
            OperationRequest::OpenChannel(_),
            Facts::Open {
                channel_id,
                funding_outpoint,
                active,
                published,
            },
        ) => {
            if funding_outpoint.as_deref().is_some_and(|s| !outpoint(s))
                || (channel_id.is_none() && funding_outpoint.is_none())
                || reference.channel.as_ref() != funding_outpoint.as_ref().or(channel_id.as_ref())
            {
                return Err(invalid());
            }
            (
                OperationResult::OpenChannel {
                    channel_id,
                    funding_outpoint,
                },
                if active {
                    OperationStage::ChannelActive
                } else if published {
                    OperationStage::Broadcast
                } else {
                    OperationStage::Submitted
                },
                active,
                published,
                false,
            )
        }
        (
            OperationRequest::CloseChannel(p),
            Facts::Close {
                channel,
                close_type,
                txids,
                confirmations,
                closed,
                published,
            },
        ) => {
            if Some(&channel) != intent.close_target.as_ref()
                || reference.channel.as_ref() != Some(&channel)
                || txids.len() > 64
                || txids.iter().any(|id| !txid(id))
            {
                return Err(invalid());
            }
            let success = closed && close_type == CloseType::Cooperative;
            let unilateral = closed && close_type == CloseType::Unilateral;
            (
                OperationResult::CloseChannel {
                    channel_id: p.channel_id.clone(),
                    close_type,
                    txids,
                    confirmations,
                },
                if closed {
                    OperationStage::ChannelClosed
                } else if published {
                    OperationStage::Broadcast
                } else {
                    OperationStage::Submitted
                },
                success,
                published,
                unilateral,
            )
        }
        (OperationRequest::NewAddress(_), Facts::Address { address }) => {
            let parsed = intent::address(&address, &r.node).map_err(|_| invalid())?;
            if parsed.address_type() != Some(bitcoin::AddressType::P2wpkh)
                || reference.address.as_ref() != Some(&address)
            {
                return Err(invalid());
            }
            (
                OperationResult::NewAddress {
                    address,
                    address_type: AddressType::P2wpkh,
                },
                OperationStage::Completed,
                true,
                false,
                false,
            )
        }
        (
            OperationRequest::SendOnchain(p),
            Facts::Send {
                txid: id,
                amount_sat,
                fee_sat,
                confirmations,
                published,
            },
        ) => {
            if !txid(&id) || reference.txid.as_ref() != Some(&id) || amount_sat != p.amount_sat {
                return Err(invalid());
            }
            (
                OperationResult::SendOnchain {
                    txid: id,
                    amount_sat,
                    fee_sat,
                    confirmations,
                },
                if published && confirmations.is_some_and(|n| n > Decimal::ZERO) {
                    OperationStage::Confirmed
                } else if published {
                    OperationStage::Broadcast
                } else {
                    OperationStage::Submitted
                },
                published,
                published,
                false,
            )
        }
        _ => return Err(invalid()),
    };
    Ok(result)
}

fn merge_result(
    old: Option<OperationResult>,
    new: OperationResult,
    fresh: bool,
) -> Result<OperationResult> {
    let Some(old) = old else {
        return Ok(new);
    };
    let invalid = || failure(ErrorCode::UpstreamInvalidResponse);
    let mut merged = old.clone();
    match (&mut merged, new) {
        (
            OperationResult::SendOnchain {
                txid,
                amount_sat,
                fee_sat,
                confirmations,
            },
            OperationResult::SendOnchain {
                txid: new_id,
                amount_sat: new_amount,
                fee_sat: new_fee,
                confirmations: new_confirmations,
            },
        ) => {
            if *txid != new_id
                || *amount_sat != new_amount
                || fee_sat.is_some() && new_fee.is_some() && *fee_sat != new_fee
            {
                return Err(invalid());
            }
            *fee_sat = fee_sat.or(new_fee);
            if fresh && new_confirmations.is_some() {
                *confirmations = new_confirmations;
            }
        }
        (
            OperationResult::CloseChannel {
                channel_id,
                close_type,
                txids,
                confirmations,
            },
            OperationResult::CloseChannel {
                channel_id: new_id,
                close_type: new_type,
                txids: new_txids,
                confirmations: new_confirmations,
            },
        ) => {
            if *channel_id != new_id
                || (*close_type != CloseType::Unknown
                    && new_type != CloseType::Unknown
                    && *close_type != new_type)
            {
                return Err(invalid());
            }
            if *close_type == CloseType::Unknown {
                *close_type = new_type;
            }
            for id in new_txids {
                if !txids.contains(&id) {
                    txids.push(id);
                }
            }
            txids.sort();
            if fresh && new_confirmations.is_some() {
                *confirmations = new_confirmations;
            }
        }
        (
            OperationResult::PayInvoice {
                payment_hash,
                amount_msat,
                fee_msat,
            },
            OperationResult::PayInvoice {
                payment_hash: new_hash,
                amount_msat: new_amount,
                fee_msat: new_fee,
            },
        ) => {
            if *payment_hash != new_hash
                || *amount_msat != new_amount
                || fee_msat.is_some() && new_fee.is_some() && *fee_msat != new_fee
            {
                return Err(invalid());
            }
            *fee_msat = fee_msat.or(new_fee);
        }
        (
            OperationResult::OpenChannel {
                channel_id,
                funding_outpoint,
            },
            OperationResult::OpenChannel {
                channel_id: new_id,
                funding_outpoint: new_point,
            },
        ) => {
            if channel_id.is_some() && new_id.is_some() && *channel_id != new_id
                || funding_outpoint.is_some()
                    && new_point.is_some()
                    && *funding_outpoint != new_point
            {
                return Err(invalid());
            }
            *channel_id = channel_id.clone().or(new_id);
            *funding_outpoint = funding_outpoint.clone().or(new_point);
        }
        (_, new) => {
            if serde_json::to_value(&old)? != serde_json::to_value(new)? {
                return Err(invalid());
            }
        }
    }
    Ok(merged)
}
fn progress(old: OperationStage, new: OperationStage, kind: OperationKind) -> OperationStage {
    use OperationStage::*;
    let path: &[OperationStage] = match kind {
        OperationKind::PayInvoice => &[Submitted, Settled],
        OperationKind::OpenChannel => &[Submitted, Broadcast, ChannelActive],
        OperationKind::CloseChannel => &[Submitted, Broadcast, ChannelClosed],
        OperationKind::SendOnchain => &[Submitted, Broadcast, Confirmed],
        _ => &[Submitted, Completed],
    };
    if path.iter().position(|stage| *stage == old) > path.iter().position(|stage| *stage == new) {
        old
    } else {
        new
    }
}
