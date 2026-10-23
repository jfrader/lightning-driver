use super::*;
use bitcoin::{address::NetworkUnchecked, secp256k1::PublicKey, Address};
use chrono::SecondsFormat;
use lightning_client::{money::Decimal, settings::MAX_INVOICE_DESCRIPTION_CHARS, validation};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::str::FromStr;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ReviewedIntent {
    pub operation: Operation,
    pub input: Value,
    pub input_digest: String,
    pub connection_generation: Uuid,
    pub close_target: Option<String>,
    pub invoice_label: Option<String>,
}

pub(super) fn hash(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

pub(super) fn network(binding: &NodeBinding) -> Network {
    match binding.network {
        VerifiedNetwork::Mainnet => Network::Mainnet,
        VerifiedNetwork::Testnet => Network::Testnet,
        VerifiedNetwork::Signet => Network::Signet,
        VerifiedNetwork::Regtest => Network::Regtest,
    }
}

pub(super) fn address(text: &str, binding: &NodeBinding) -> Result<Address> {
    let expected = match binding.network {
        VerifiedNetwork::Mainnet => bitcoin::Network::Bitcoin,
        VerifiedNetwork::Testnet => bitcoin::Network::Testnet,
        VerifiedNetwork::Signet => bitcoin::Network::Signet,
        VerifiedNetwork::Regtest => bitcoin::Network::Regtest,
    };
    Address::<NetworkUnchecked>::from_str(text)
        .map_err(|_| failure(ErrorCode::InvalidAddress))?
        .require_network(expected)
        .map_err(|_| failure(ErrorCode::NetworkMismatch))
}

fn pubkey(text: &str) -> Result<String> {
    if text.len() != 66 {
        return Err(failure(ErrorCode::InvalidPeer));
    }
    Ok(PublicKey::from_str(text)
        .map_err(|_| failure(ErrorCode::InvalidPeer))?
        .to_string())
}

pub(super) fn normalize(mut request: OperationRequest) -> Result<OperationRequest> {
    match &mut request {
        OperationRequest::CreateInvoice(p) => {
            p.amount_msat
                .0
                .positive()
                .map_err(|_| failure(ErrorCode::InvalidAmount))?;
            if p.description.chars().count() > MAX_INVOICE_DESCRIPTION_CHARS
                || p.expiry_seconds == 0
            {
                return Err(failure(ErrorCode::InvalidRequest));
            }
        }
        OperationRequest::PayInvoice(p) => {
            if p.bolt11.len() > lightning_client::settings::MAX_BOLT11_BYTES {
                return Err(failure(ErrorCode::InvalidInvoice));
            }
            p.bolt11 = p
                .bolt11
                .parse::<lightning_invoice::Bolt11Invoice>()
                .map_err(|_| failure(ErrorCode::InvalidInvoice))?
                .to_string();
        }
        OperationRequest::ConnectPeer(p) => {
            p.pubkey = pubkey(&p.pubkey)?;
            if p.port == 0 {
                return Err(failure(ErrorCode::InvalidPeer));
            }
            let host = p
                .host
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(&p.host);
            lightning_client::settings::validate_peer_host(host)
                .map_err(|_| failure(ErrorCode::InvalidPeer))?;
            p.host = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                ip.to_string()
            } else {
                url::Host::parse(host)
                    .map_err(|_| failure(ErrorCode::InvalidPeer))?
                    .to_string()
            };
        }
        OperationRequest::DisconnectPeer(p) => p.pubkey = pubkey(&p.pubkey)?,
        OperationRequest::OpenChannel(p) => {
            p.peer_pubkey = pubkey(&p.peer_pubkey)?;
            p.amount_sat
                .0
                .positive()
                .map_err(|_| failure(ErrorCode::InvalidAmount))?;
            p.fee_rate_sat_vbyte
                .positive()
                .map_err(|_| failure(ErrorCode::InvalidAmount))?;
        }
        OperationRequest::CloseChannel(p) => {
            if p.channel_id.is_empty() || p.channel_id.len() > 256 {
                return Err(failure(ErrorCode::InvalidRequest));
            }
            p.fee_rate_sat_vbyte
                .positive()
                .map_err(|_| failure(ErrorCode::InvalidAmount))?;
        }
        OperationRequest::NewAddress(_) => {}
        OperationRequest::SendOnchain(p) => {
            p.address = Address::<NetworkUnchecked>::from_str(&p.address)
                .map_err(|_| failure(ErrorCode::InvalidAddress))?
                .assume_checked()
                .to_string();
            p.amount_sat
                .0
                .positive()
                .map_err(|_| failure(ErrorCode::InvalidAmount))?;
            p.fee_rate_sat_vbyte
                .positive()
                .map_err(|_| failure(ErrorCode::InvalidAmount))?;
        }
    }
    Ok(request)
}

fn canonical(request: &OperationRequest) -> Value {
    match request {
        OperationRequest::CreateInvoice(p) => json!([
            "create_invoice",
            [p.amount_msat, p.description, p.expiry_seconds]
        ]),
        OperationRequest::PayInvoice(p) => json!([
            "pay_invoice",
            [p.bolt11, p.amount_msat, p.max_fee_msat, p.description]
        ]),
        OperationRequest::ConnectPeer(p) => json!(["connect_peer", [p.pubkey, p.host, p.port]]),
        OperationRequest::DisconnectPeer(p) => json!(["disconnect_peer", [p.pubkey]]),
        OperationRequest::OpenChannel(p) => json!([
            "open_channel",
            [p.peer_pubkey, p.amount_sat, p.private, p.fee_rate_sat_vbyte]
        ]),
        OperationRequest::CloseChannel(p) => {
            json!(["close_channel", [p.channel_id, p.fee_rate_sat_vbyte]])
        }
        OperationRequest::NewAddress(p) => json!(["new_address", [p.address_type]]),
        OperationRequest::SendOnchain(p) => json!([
            "send_onchain",
            [p.address, p.amount_sat, p.fee_rate_sat_vbyte]
        ]),
    }
}

pub(super) fn input(node: &str, request: &OperationRequest) -> Value {
    json!(["ld-input-v1", node, canonical(request)])
}

impl ReviewedIntent {
    pub fn build(
        request: OperationRequest,
        node: &NodeConfig,
        facts: &ReadFacts,
        now: DateTime<Utc>,
    ) -> Result<(Self, Option<zeroize::Zeroizing<[u8; 32]>>)> {
        let id = Uuid::new_v4();
        let expires = now
            .checked_add_signed(chrono::Duration::seconds(i64::from(node.review_seconds)))
            .filter(|expiry| *expiry > now)
            .ok_or_else(|| failure(ErrorCode::PolicyViolation))?;
        let mut review = OperationReview {
            operation_id: id,
            node: node.binding.clone(),
            policy_revision: node.policy.revision.clone(),
            digest: String::new(),
            expires_at: expires,
            sensitive: request.sensitive(),
            amount_sat: None,
            amount_msat: None,
            destination: None,
            peer_pubkey: None,
            channel_id: None,
            payment_hash: None,
            fee: FeeReview {
                control: FeeControl::None,
                max_fee_msat: None,
                fee_rate_sat_vbyte: None,
                fee_estimate_sat: None,
                estimate_only: true,
            },
        };
        let limits = &node.policy.limits;
        let mut secret = None;
        let mut label = None;
        let mut close_target = None;
        let bounds =
            |value: Decimal, bounds: &lightning_client::settings::AmountBounds| -> Result<()> {
                if value == Decimal::ZERO || !bounds.contains(value) {
                    Err(failure(ErrorCode::PolicyViolation))
                } else {
                    Ok(())
                }
            };
        match &request {
            OperationRequest::CreateInvoice(p) => {
                bounds(p.amount_msat.0, &limits.create_invoice_msat)?;
                if p.expiry_seconds < limits.invoice_expiry_seconds.min
                    || p.expiry_seconds > limits.invoice_expiry_seconds.max
                {
                    return Err(failure(ErrorCode::PolicyViolation));
                }
                review.amount_msat = Some(p.amount_msat);
                if node.backend == Backend::ClnRest {
                    label = Some(format!("ld-{id}"));
                } else {
                    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
                    OsRng.fill_bytes(bytes.as_mut());
                    review.payment_hash = Some(hex::encode(Sha256::digest(&bytes[..])));
                    secret = Some(bytes);
                }
            }
            OperationRequest::PayInvoice(p) => {
                let decoded = validation::decode(&p.bolt11, network(&node.binding), now)
                    .map_err(invoice_error)?;
                let amount =
                    validation::validate_payment(&decoded, p.amount_msat, p.description.as_deref())
                        .map_err(invoice_error)?;
                bounds(amount.0, &limits.pay_invoice_msat)?;
                if p.max_fee_msat > limits.max_routing_fee_msat {
                    return Err(failure(ErrorCode::PolicyViolation));
                }
                amount
                    .0
                    .checked_add(p.max_fee_msat.0)
                    .map_err(|_| failure(ErrorCode::InvalidAmount))?;
                review.expires_at = review.expires_at.min(decoded.expires_at);
                review.amount_msat = Some(amount);
                review.destination = Some(decoded.destination);
                review.payment_hash = Some(decoded.payment_hash);
                review.fee.control = FeeControl::AbsoluteRoutingLimit;
                review.fee.max_fee_msat = Some(p.max_fee_msat);
            }
            OperationRequest::ConnectPeer(p) => {
                if !node.peer_policy.allowed_hosts.contains(&p.host)
                    || !node.peer_policy.allowed_ports.contains(&p.port)
                {
                    return Err(failure(ErrorCode::PolicyViolation));
                }
                review.peer_pubkey = Some(p.pubkey.clone());
                review.destination = Some(if p.host.contains(':') {
                    format!("[{}]:{}", p.host, p.port)
                } else {
                    format!("{}:{}", p.host, p.port)
                });
            }
            OperationRequest::DisconnectPeer(p) => review.peer_pubkey = Some(p.pubkey.clone()),
            OperationRequest::OpenChannel(p) => {
                bounds(p.amount_sat.0, &limits.open_channel_sat)?;
                bounds(p.fee_rate_sat_vbyte, &limits.fee_rate_sat_vbyte)?;
                if !facts.peer_connected {
                    return Err(failure(ErrorCode::PeerUnavailable));
                }
                review.amount_sat = Some(p.amount_sat);
                review.peer_pubkey = Some(p.peer_pubkey.clone());
                review.destination = Some(p.peer_pubkey.clone());
                review.fee.control = FeeControl::RequestedOnchainRate;
                review.fee.fee_rate_sat_vbyte = Some(p.fee_rate_sat_vbyte);
            }
            OperationRequest::CloseChannel(p) => {
                bounds(p.fee_rate_sat_vbyte, &limits.fee_rate_sat_vbyte)?;
                close_target = Some(
                    facts
                        .close_target
                        .clone()
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| failure(ErrorCode::Unsupported))?,
                );
                review.peer_pubkey = Some(pubkey(
                    facts
                        .close_peer
                        .as_deref()
                        .ok_or_else(|| failure(ErrorCode::Unsupported))?,
                )?);
                review.channel_id = Some(p.channel_id.clone());
                review.fee.control = FeeControl::CooperativeNegotiation;
                review.fee.fee_rate_sat_vbyte = Some(p.fee_rate_sat_vbyte);
            }
            OperationRequest::NewAddress(_) => {}
            OperationRequest::SendOnchain(p) => {
                address(&p.address, &node.binding)?;
                bounds(p.amount_sat.0, &limits.send_onchain_sat)?;
                bounds(p.fee_rate_sat_vbyte, &limits.fee_rate_sat_vbyte)?;
                review.amount_sat = Some(p.amount_sat);
                review.destination = Some(p.address.clone());
                review.fee.control = FeeControl::RequestedOnchainRate;
                review.fee.fee_rate_sat_vbyte = Some(p.fee_rate_sat_vbyte);
            }
        }
        let input = input(&node.binding.node_id, &request);
        let mut intent = Self {
            input_digest: hash(&input)?,
            input,
            connection_generation: node.generation,
            close_target,
            invoice_label: label,
            operation: Operation {
                id,
                node_id: node.binding.node_id.clone(),
                request,
                review,
                state: OperationState::AwaitingConfirmation,
                stage: OperationStage::NotDispatched,
                authorization: AuthorizationStatus {
                    status: AuthorizationState::Required,
                    mode: node.reauth_mode,
                    expires_at: None,
                },
                result: None,
                error: None,
                created_at: now,
                updated_at: now,
                last_reconciled_at: None,
                reconciliation: None,
            },
        };
        if !intent.operation.review.sensitive {
            intent.operation.authorization.status = AuthorizationState::NotRequired;
        }
        intent.operation.review.digest = hash(&intent.review_encoding())?;
        Ok((intent, secret))
    }

    fn review_encoding(&self) -> Value {
        let op = &self.operation;
        let r = &op.review;
        let n = &r.node;
        let f = &r.fee;
        json!([
            "ld-review-v1",
            op.id,
            [n.node_id, n.network, n.identity_pubkey, n.identity_revision],
            r.policy_revision,
            canonical(&op.request),
            r.expires_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
            r.sensitive,
            [
                r.amount_sat,
                r.amount_msat,
                r.destination,
                r.peer_pubkey,
                r.channel_id,
                r.payment_hash,
                [
                    f.control,
                    f.max_fee_msat,
                    f.fee_rate_sat_vbyte,
                    f.fee_estimate_sat,
                    true
                ]
            ],
            [self.close_target, self.invoice_label]
        ])
    }

    pub fn validate(&self, operation: &Operation) -> Result<()> {
        let op = &self.operation;
        if !op.binding_is_valid()
            || !op.review.fee.estimate_only
            || self.input != input(&op.node_id, &op.request)
            || self.input_digest != hash(&self.input)?
            || op.review.digest != hash(&self.review_encoding())?
            || serde_json::to_value(&operation.request)? != serde_json::to_value(&op.request)?
            || serde_json::to_value(&operation.review)? != serde_json::to_value(&op.review)?
            || operation.id != op.id
            || operation.node_id != op.node_id
            || operation.created_at != op.created_at
        {
            return Err(failure(ErrorCode::ReviewMismatch));
        }
        Ok(())
    }

    pub fn resources(&self) -> Vec<Resource> {
        let mut resources = vec![Resource::Intent(self.input_digest.clone())];
        let r = &self.operation.review;
        match &self.operation.request {
            OperationRequest::PayInvoice(_) => {
                if let Some(hash) = &r.payment_hash {
                    resources.push(Resource::Payment(hash.clone()));
                }
            }
            OperationRequest::ConnectPeer(_)
            | OperationRequest::DisconnectPeer(_)
            | OperationRequest::OpenChannel(_) => {
                if let Some(peer) = &r.peer_pubkey {
                    resources.push(Resource::Peer(peer.clone()));
                }
                if matches!(self.operation.request, OperationRequest::OpenChannel(_)) {
                    resources.push(Resource::Wallet);
                }
            }
            OperationRequest::CloseChannel(_) => {
                if let Some(target) = &self.close_target {
                    resources.push(Resource::Channel(target.clone()));
                }
            }
            OperationRequest::SendOnchain(_) => resources.push(Resource::Wallet),
            _ => {}
        }
        resources.sort();
        resources
    }
}

fn invoice_error(error: validation::InvoiceError) -> EngineError {
    failure(match error {
        validation::InvoiceError::Expired => ErrorCode::InvoiceExpired,
        validation::InvoiceError::Network => ErrorCode::NetworkMismatch,
        validation::InvoiceError::Amount | validation::InvoiceError::Override => {
            ErrorCode::InvalidAmount
        }
        _ => ErrorCode::InvalidInvoice,
    })
}
