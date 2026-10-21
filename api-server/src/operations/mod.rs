#![allow(dead_code)]

mod adapter;
mod cln;
mod evidence;
pub(crate) mod http;
mod intent;
mod lnd;
mod runtime;
mod storage;
#[cfg(test)]
mod tests;

use crate::{
    auth::{AuthError, AuthManager, Context},
    journal::{Journal, JournalError, PendingSecretKey, Resource},
};
use adapter::{Collection, InfoObservation, ReadQuery, ReadResult};
use chrono::{DateTime, Utc};
use evidence::{Evidence, Knowledge};
use intent::ReviewedIntent;
use lightning_client::{
    model::*,
    settings::{NodePolicy, PeerPolicy},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

type Result<T> = std::result::Result<T, EngineError>;
type ResponseFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug)]
pub(crate) struct EngineError {
    code: ErrorCode,
    operation_id: Option<Uuid>,
    outcome: ErrorOutcome,
}
fn failure(code: ErrorCode) -> EngineError {
    EngineError {
        code,
        operation_id: None,
        outcome: ErrorOutcome::NotDispatched,
    }
}
impl EngineError {
    fn claimed(mut self, id: Uuid) -> Self {
        self.operation_id = Some(id);
        self.outcome = ErrorOutcome::Unknown;
        self
    }
}
impl From<JournalError> for EngineError {
    fn from(error: JournalError) -> Self {
        match error {
            JournalError::NotFound => failure(ErrorCode::NotFound),
            JournalError::Revoked => failure(ErrorCode::SessionRequired),
            _ => failure(ErrorCode::StorageUnavailable),
        }
    }
}
impl From<rusqlite::Error> for EngineError {
    fn from(_: rusqlite::Error) -> Self {
        failure(ErrorCode::StorageUnavailable)
    }
}
impl From<serde_json::Error> for EngineError {
    fn from(_: serde_json::Error) -> Self {
        failure(ErrorCode::StorageUnavailable)
    }
}
impl From<AuthError> for EngineError {
    fn from(error: AuthError) -> Self {
        failure(match error {
            AuthError::Session => ErrorCode::SessionRequired,
            AuthError::NotRequired => ErrorCode::AuthorizationNotRequired,
            AuthError::Authorization => ErrorCode::AuthorizationInvalid,
            AuthError::Storage => ErrorCode::StorageUnavailable,
            AuthError::Limited | AuthError::AllocationLimited(_) => ErrorCode::RateLimited,
            AuthError::Expired => ErrorCode::ChallengeExpired,
            AuthError::Challenge => ErrorCode::ChallengeInvalid,
            _ => ErrorCode::AuthenticationFailed,
        })
    }
}

trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}
struct WallClock;
impl Clock for WallClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Clone)]
struct NodeConfig {
    binding: NodeBinding,
    generation: Uuid,
    backend: Backend,
    policy: NodePolicy,
    peer_policy: PeerPolicy,
    reauth_mode: ReauthMode,
    capabilities: Capabilities,
    review_seconds: u32,
    freshness_seconds: u32,
}

#[derive(Clone)]
struct ReadFacts {
    binding: NodeBinding,
    generation: Uuid,
    observed_at: DateTime<Utc>,
    connection: NodeConnection,
    sync_usable: bool,
    permission: bool,
    peer_connected: bool,
    close_target: Option<String>,
    close_peer: Option<String>,
}

struct PinnedNode {
    config: NodeConfig,
    adapter: Arc<dyn Adapter>,
}
impl Clone for PinnedNode {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            adapter: self.adapter.clone(),
        }
    }
}
type NodeGate = Arc<Mutex<Option<PinnedNode>>>;

// There is no arbitrary RPC, continuation, cleanup or retry entry point.
trait Adapter: Send + Sync {
    fn read(&self, _query: ReadQuery) -> ResponseFuture<'_, Result<ReadResult>> {
        Box::pin(async { Err(failure(ErrorCode::Unsupported)) })
    }
    fn prepare<'a>(
        &'a self,
        request: &'a OperationRequest,
    ) -> ResponseFuture<'a, Result<ReadFacts>>;
    fn prepare_review<'a>(
        &'a self,
        operation: &'a Operation,
    ) -> ResponseFuture<'a, Result<ReadFacts>> {
        self.prepare(&operation.request)
    }
    fn execute_once(&self, permit: ClaimPermit) -> ResponseFuture<'_, Evidence>;
    fn observe_exact(&self, query: ObservationQuery) -> ResponseFuture<'_, Evidence>;
}

// Never Clone/Serialize. Only a positively acknowledged new claim constructs this value.
struct ClaimPermit {
    claim_id: Uuid,
    intent: ReviewedIntent,
    secret: Option<zeroize::Zeroizing<[u8; 32]>>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug, Default)]
struct RecoveryReference {
    payment_hash: Option<String>,
    invoice_label: Option<String>,
    peer: Option<String>,
    channel: Option<String>,
    txid: Option<String>,
    address: Option<String>,
    attempt: Option<String>,
}
impl RecoveryReference {
    fn planned(intent: &ReviewedIntent) -> Self {
        Self {
            payment_hash: intent.operation.review.payment_hash.clone(),
            invoice_label: intent.invoice_label.clone(),
            peer: intent.operation.review.peer_pubkey.clone(),
            channel: intent.close_target.clone(),
            ..Self::default()
        }
    }
}
struct ObservationQuery {
    request: OperationRequest,
    operation_id: Uuid,
    binding: NodeBinding,
    generation: Uuid,
    kind: OperationKind,
    claim_id: Uuid,
    sequence: i64,
    reference: RecoveryReference,
    close_type: Option<CloseType>,
    close_txids: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultPoint {
    BeforeCreateCommit,
    BeforeClaimTransaction,
    AfterGrantRemoval,
    BeforeClaimCommit,
    CommitAcknowledgement,
    BeforeAdapter,
    BeforeResult,
    ObservationCommit,
}
#[derive(Clone, Default)]
struct Faults {
    #[cfg(test)]
    handler: Option<Arc<dyn Fn(FaultPoint) -> bool + Send + Sync>>,
}
impl Faults {
    fn hit(&self, point: FaultPoint) -> Result<()> {
        #[cfg(test)]
        if self.handler.as_ref().is_some_and(|handler| handler(point)) {
            return Err(failure(ErrorCode::StorageUnavailable));
        }
        let _ = point;
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct Engine {
    journal: Journal,
    auth: AuthManager,
    nodes: Arc<BTreeMap<String, NodeGate>>,
    unavailable: Arc<BTreeMap<String, (bool, ErrorCode)>>,
    clock: Arc<dyn Clock>,
    key: Arc<PendingSecretKey>,
    tasks: Arc<tokio::sync::Semaphore>,
    faults: Faults,
}

impl Engine {
    pub(crate) async fn recover(&self) -> Result<()> {
        let key = self.key.clone();
        self.journal.run(move |connection| {
            let mut statement=connection.prepare("SELECT o.body,s.ciphertext FROM pending_invoice_secrets s JOIN operations o ON o.id=s.operation_id")?;
            let mut rows=statement.query([])?;
            while let Some(row)=rows.next()? {
                let operation:Operation=serde_json::from_str(&row.get::<_,String>(0)?)?;
                key.decrypt(&operation,&crate::journal::SealedInvoiceSecret(row.get(1)?))?;
            }
            Ok(())
        }).await?;
        self.journal.recover(self.clock.now()).await?;
        Ok(())
    }
    fn node(&self, id: &str) -> Result<NodeGate> {
        if let Some((read_only, code)) = self.unavailable.get(id) {
            return Err(failure(if *read_only {
                ErrorCode::ReadOnly
            } else {
                *code
            }));
        }
        self.nodes
            .get(id)
            .cloned()
            .ok_or_else(|| failure(ErrorCode::NotFound))
    }
    fn pinned(&self, id: &str) -> Result<PinnedNode> {
        self.node(id)?
            .lock()
            .map_err(|_| failure(ErrorCode::InternalError))?
            .clone()
            .ok_or_else(|| failure(ErrorCode::NotFound))
    }

    #[cfg(test)]
    async fn create_review(
        &self,
        context: &Context,
        node: &str,
        key: Uuid,
        request: OperationRequest,
    ) -> Result<Operation> {
        self.create_review_outcome(context, node, key, request)
            .await
            .map(|(operation, _)| operation)
    }

    async fn create_review_outcome(
        &self,
        context: &Context,
        node: &str,
        key: Uuid,
        request: OperationRequest,
    ) -> Result<(Operation, bool)> {
        self.live(context).await?;
        let pinned = self.pinned(node)?;
        writable(&pinned.config)?;
        if key.is_nil() {
            return Err(failure(ErrorCode::InvalidRequest));
        }
        let request = intent::normalize(request)?;
        let input = intent::hash(&intent::input(node, &request))?;
        // Replay precedes live daemon prerequisites and all random invoice material.
        if let Some(operation) = storage::replay(self, context, node, key, &input).await? {
            return Ok((operation, false));
        }
        let facts = pinned.adapter.prepare(&request).await?;
        let (intent, secret) =
            ReviewedIntent::build(request, &pinned.config, &facts, self.clock.now())?;
        let facts = pinned.adapter.prepare_review(&intent.operation).await?;
        eligible(
            &pinned.config,
            &facts,
            &intent.operation.request,
            self.clock.now(),
        )?;
        let sealed = secret
            .as_ref()
            .map(|secret| self.key.encrypt(&intent.operation, secret))
            .transpose()?;
        storage::create(self, context, intent, key, sealed, facts).await
    }

    async fn live(&self, context: &Context) -> Result<()> {
        let context = context.clone();
        let auth = self.auth.clone();
        let clock = self.clock.clone();
        self.journal
            .run(move |connection| {
                let generation = storage::generation(connection)?;
                Ok(
                    auth.with_claim_session(&context, generation, clock.now(), |_| {
                        Ok::<_, EngineError>(())
                    }),
                )
            })
            .await?
    }

    async fn reviewable(
        &self,
        context: &Context,
        node: &str,
        id: Uuid,
        digest: &str,
    ) -> Result<Operation> {
        storage::authorization_gate(self, context, node, id, digest).await
    }
    async fn start_authorization(
        &self,
        context: &Context,
        node: &str,
        id: Uuid,
        digest: &str,
    ) -> Result<crate::auth::AuthorizationStart> {
        let operation = self.reviewable(context, node, id, digest).await?;
        let response = self
            .auth
            .start_authorization(context, &operation, self.clock.now())
            .await?;
        self.reviewable(context, node, id, digest).await?;
        Ok(response)
    }
    async fn finish_authorization(
        &self,
        context: &Context,
        node: &str,
        id: Uuid,
        digest: &str,
        finish: crate::auth::AuthenticationFinish,
    ) -> Result<crate::auth::OperationAuthorization> {
        let operation = self.reviewable(context, node, id, digest).await?;
        let response = self
            .auth
            .finish_authorization(context, &operation, finish, self.clock.now())
            .await?;
        self.reviewable(context, node, id, digest).await?;
        Ok(response)
    }

    async fn confirm_once(
        &self,
        context: &Context,
        node: &str,
        id: Uuid,
        digest: &str,
        authorization: Option<Uuid>,
    ) -> Result<Operation> {
        self.confirm_once_outcome(context, node, id, digest, authorization)
            .await
            .map(|(operation, _)| operation)
    }

    async fn confirm_once_outcome(
        &self,
        context: &Context,
        node: &str,
        id: Uuid,
        digest: &str,
        authorization: Option<Uuid>,
    ) -> Result<(Operation, bool)> {
        let slot = self
            .tasks
            .clone()
            .try_acquire_owned()
            .map_err(|_| failure(ErrorCode::StorageUnavailable))?;
        let cancelled = Arc::new(Mutex::new(false));
        let _guard = Cancellation(cancelled.clone());
        let engine = self.clone();
        let context = context.clone();
        let node = node.to_string();
        let digest = digest.to_string();
        tokio::spawn(async move {
            let _slot = slot;
            engine
                .confirm_task(context, node, id, digest, authorization, cancelled)
                .await
        })
        .await
        .map_err(|_| failure(ErrorCode::InternalError).claimed(id))?
    }

    async fn confirm_task(
        &self,
        context: Context,
        node: String,
        id: Uuid,
        digest: String,
        authorization: Option<Uuid>,
        cancelled: Arc<Mutex<bool>>,
    ) -> Result<(Operation, bool)> {
        // First gate handles duplicates/removal without a probe or a reusable permit.
        if let Some(existing) = storage::duplicate(self, &context, &node, id, &digest).await? {
            return Ok((existing, false));
        }
        let pinned = self.pinned(&node)?;
        let operation = storage::load_local(self, id).await?;
        let facts = match pinned.adapter.prepare_review(&operation).await {
            Ok(facts) => facts,
            Err(error) => {
                return match storage::duplicate(self, &context, &node, id, &digest).await? {
                    Some(operation) => Ok((operation, false)),
                    None => Err(error),
                }
            }
        };
        let claim = storage::claim(
            self,
            &context,
            storage::ClaimRequest {
                node,
                id,
                digest,
                authorization,
                cancelled,
            },
            &pinned.config,
            facts,
        )
        .await;
        let claim = match claim {
            Ok(claim) => claim,
            Err(error) if error.outcome == ErrorOutcome::Unknown => {
                return storage::uncertain(self, id, ErrorCode::OutcomeUnknown)
                    .await
                    .map(|operation| (operation, true))
                    .map_err(|e| e.claimed(id))
            }
            Err(error) => return Err(error),
        };
        let permit = match claim {
            Claim::Existing(operation) => return Ok((*operation, false)),
            Claim::New(permit) => *permit,
        };
        self.faults
            .hit(FaultPoint::BeforeAdapter)
            .map_err(|e| e.claimed(id))?;
        let evidence = pinned.adapter.execute_once(permit).await;
        self.faults
            .hit(FaultPoint::BeforeResult)
            .map_err(|e| e.claimed(id))?;
        match storage::apply(self, id, evidence, false).await {
            Ok(operation) => Ok((operation, true)),
            Err(error) if error.code == ErrorCode::StorageUnavailable => {
                storage::uncertain(self, id, ErrorCode::OutcomeUnknown)
                    .await
                    .map(|operation| (operation, true))
                    .map_err(|e| e.claimed(id))
            }
            Err(error) if error.code == ErrorCode::UpstreamInvalidResponse => {
                storage::uncertain(self, id, ErrorCode::UpstreamInvalidResponse)
                    .await
                    .map(|operation| (operation, true))
                    .map_err(|e| e.claimed(id))
            }
            Err(error) => Err(error.claimed(id)),
        }
    }

    pub(crate) async fn observe(
        &self,
        context: &Context,
        node: &str,
        id: Uuid,
    ) -> Result<Operation> {
        let operation = storage::status(self, context, node, id).await?;
        let Ok(pinned) = self.pinned(node) else {
            return Ok(operation);
        };
        if pinned.config.binding != operation.review.node {
            return Ok(operation);
        }
        let Some(query) = storage::observation_query(self, id, &pinned.config).await? else {
            return Ok(operation);
        };
        let evidence = pinned.adapter.observe_exact(query).await;
        storage::apply(self, id, evidence, true)
            .await
            .map_err(|e| e.claimed(id))
    }
}

enum Claim {
    Existing(Box<Operation>),
    New(Box<ClaimPermit>),
}
struct Cancellation(Arc<Mutex<bool>>);
impl Drop for Cancellation {
    fn drop(&mut self) {
        if let Ok(mut cancelled) = self.0.lock() {
            *cancelled = true;
        }
    }
}

fn writable(config: &NodeConfig) -> Result<()> {
    if config.policy.read_only {
        Err(failure(ErrorCode::ReadOnly))
    } else {
        Ok(())
    }
}
fn capability<'a>(config: &'a NodeConfig, request: &OperationRequest) -> &'a Capability {
    let c = &config.capabilities;
    match request {
        OperationRequest::CreateInvoice(_) => &c.create_invoice,
        OperationRequest::PayInvoice(_) => &c.pay_invoice,
        OperationRequest::ConnectPeer(_) => &c.connect_peer,
        OperationRequest::DisconnectPeer(_) => &c.disconnect_peer,
        OperationRequest::OpenChannel(_) => &c.open_channel,
        OperationRequest::CloseChannel(_) => &c.close_channel,
        OperationRequest::NewAddress(_) => &c.new_address,
        OperationRequest::SendOnchain(_) => &c.send_onchain,
    }
}
fn eligible(
    config: &NodeConfig,
    facts: &ReadFacts,
    request: &OperationRequest,
    now: DateTime<Utc>,
) -> Result<()> {
    writable(config)?;
    if facts.binding != config.binding || facts.generation != config.generation {
        return Err(failure(ErrorCode::IdentityChanged));
    }
    match facts.connection {
        NodeConnection::Online => {}
        NodeConnection::AuthError => return Err(failure(ErrorCode::NodeAuthError)),
        NodeConnection::IdentityMismatch => return Err(failure(ErrorCode::NodeUnverified)),
        _ => return Err(failure(ErrorCode::NodeOffline)),
    }
    if !capability(config, request).enabled {
        return Err(failure(ErrorCode::Unsupported));
    }
    if !facts.permission {
        return Err(failure(ErrorCode::NodeAuthError));
    }
    if !facts.sync_usable {
        return Err(failure(ErrorCode::NodeSyncing));
    }
    if facts.observed_at > now
        || now.signed_duration_since(facts.observed_at)
            >= chrono::Duration::seconds(i64::from(config.freshness_seconds))
    {
        return Err(failure(ErrorCode::NodeOffline));
    }
    if config.binding.identity_revision.is_empty()
        || config
            .binding
            .identity_pubkey
            .parse::<bitcoin::secp256k1::PublicKey>()
            .is_err()
    {
        return Err(failure(ErrorCode::NodeUnverified));
    }
    if config.policy.revision.is_empty() || config.policy.node_id != config.binding.node_id {
        return Err(failure(ErrorCode::NotConfigured));
    }
    Ok(())
}
