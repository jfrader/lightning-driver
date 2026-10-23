use super::*;
use crate::journal::SealedInvoiceSecret;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

async fn job<T: Send + 'static>(
    engine: &Engine,
    action: impl FnOnce(&mut Connection) -> Result<T> + Send + 'static,
) -> Result<T> {
    engine
        .journal
        .run(move |connection| Ok(action(connection)))
        .await?
}
pub(super) fn generation(connection: &Connection) -> std::result::Result<i64, JournalError> {
    Ok(connection.query_row(
        "SELECT generation FROM auth_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?)
}
fn load(connection: &Connection, id: Uuid) -> Result<Operation> {
    let body: Option<String> = connection
        .query_row(
            "SELECT body FROM operations WHERE id=?1",
            [id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(serde_json::from_str(
        &body.ok_or_else(|| failure(ErrorCode::NotFound))?,
    )?)
}
fn save(connection: &Connection, operation: &Operation) -> Result<()> {
    connection.execute(
        "UPDATE operations SET body=?1 WHERE id=?2",
        params![serde_json::to_string(operation)?, operation.id.to_string()],
    )?;
    Ok(())
}
fn dispatched(connection: &Connection, id: Uuid) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT dispatched FROM operations WHERE id=?1",
        [id.to_string()],
        |row| row.get(0),
    )?)
}
fn stored_intent(connection: &Connection, id: Uuid) -> Result<ReviewedIntent> {
    let intent: Option<String> = connection
        .query_row(
            "SELECT intent FROM operation_intents WHERE operation_id=?1 AND encoding_version=1",
            [id.to_string()],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    Ok(serde_json::from_str(&intent.ok_or_else(|| {
        failure(ErrorCode::OperationNotReviewable)
    })?)?)
}
fn binding(operation: &Operation, node: &str, digest: &str) -> Result<()> {
    if operation.node_id != node {
        return Err(failure(ErrorCode::NotFound));
    }
    if operation.review.digest != digest {
        return Err(failure(ErrorCode::ReviewMismatch));
    }
    Ok(())
}
fn check(
    intent: &ReviewedIntent,
    operation: &Operation,
    config: &NodeConfig,
    facts: Option<&ReadFacts>,
    now: DateTime<Utc>,
) -> Result<()> {
    writable(config)?;
    intent.validate(operation)?;
    if operation.state != OperationState::AwaitingConfirmation {
        return Err(failure(ErrorCode::OperationNotReviewable));
    }
    if operation.review.expires_at <= now {
        return Err(failure(ErrorCode::ReviewExpired));
    }
    if config.binding != operation.review.node || config.generation != intent.connection_generation
    {
        return Err(failure(ErrorCode::IdentityChanged));
    }
    if config.policy.revision != operation.review.policy_revision {
        return Err(failure(ErrorCode::PolicyChanged));
    }
    if !capability(config, &operation.request).enabled {
        return Err(failure(ErrorCode::Unsupported));
    }
    if let Some(facts) = facts {
        eligible(config, facts, &operation.request, now)?;
        if matches!(operation.request, OperationRequest::OpenChannel(_)) && !facts.peer_connected {
            return Err(failure(ErrorCode::PeerUnavailable));
        }
        if matches!(operation.request, OperationRequest::CloseChannel(_))
            && (facts.close_target != intent.close_target
                || facts.close_peer != operation.review.peer_pubkey)
        {
            return Err(failure(ErrorCode::IdentityChanged));
        }
    }
    if let OperationRequest::PayInvoice(p) = &operation.request {
        let decoded =
            lightning_client::validation::decode(&p.bolt11, intent::network(&config.binding), now)
                .map_err(|_| failure(ErrorCode::InvalidInvoice))?;
        lightning_client::validation::validate_payment(
            &decoded,
            p.amount_msat,
            p.description.as_deref(),
        )
        .map_err(|_| failure(ErrorCode::InvoiceExpired))?;
    }
    Ok(())
}
fn resources(connection: &Connection, intent: &ReviewedIntent) -> Result<()> {
    let wrong_scope: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM resource_claims WHERE operation_id=?1 AND node_id<>?2)",
        params![intent.operation.id.to_string(), intent.operation.node_id],
        |row| row.get(0),
    )?;
    if wrong_scope {
        return Err(failure(ErrorCode::ReviewMismatch));
    }
    let mut statement = connection
        .prepare("SELECT resource FROM resource_claims WHERE operation_id=?1 ORDER BY resource")?;
    let stored = statement
        .query_map([intent.operation.id.to_string()], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut expected: Vec<_> = intent.resources().iter().map(Resource::key).collect();
    expected.sort();
    if stored != expected {
        return Err(failure(ErrorCode::ReviewMismatch));
    }
    paid(connection, intent)?;
    Ok(())
}
fn paid(connection: &Connection, intent: &ReviewedIntent) -> Result<()> {
    if matches!(intent.operation.request, OperationRequest::PayInvoice(_)) {
        if let Some(hash) = &intent.operation.review.payment_hash {
            if let Some(id) = connection
                .query_row(
                    "SELECT operation_id FROM paid_hashes WHERE node_id=?1 AND payment_hash=?2",
                    params![intent.operation.node_id, hash],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                let mut error = failure(ErrorCode::AlreadyPaid);
                error.operation_id = Uuid::parse_str(&id).ok();
                return Err(error);
            }
        }
    }
    Ok(())
}
fn replay_in(
    connection: &Connection,
    node: &str,
    key: Uuid,
    input: &str,
) -> Result<Option<Operation>> {
    let row: Option<(String, Vec<u8>)> = connection
        .query_row(
            "SELECT body,request_digest FROM operations WHERE node_id=?1 AND request_key=?2",
            params![node, key.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some((body, digest)) => {
            let operation: Operation = serde_json::from_str(&body)?;
            if digest != input.as_bytes() {
                let mut error = failure(ErrorCode::IdempotencyConflict);
                error.operation_id = Some(operation.id);
                return Err(error);
            }
            Ok(Some(operation))
        }
    }
}
pub(super) async fn load_local(engine: &Engine, id: Uuid) -> Result<Operation> {
    job(engine, move |connection| load(connection, id)).await
}

pub(super) async fn status(
    engine: &Engine,
    context: &Context,
    node: &str,
    id: Uuid,
) -> Result<Operation> {
    let e = engine.clone();
    let context = context.clone();
    let node = node.to_string();
    job(engine, move |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expired = crate::journal::expire_reviews(&tx, e.clock.now())?;
        let generation = generation(&tx)?;
        e.auth
            .with_claim_session(&context, generation, e.clock.now(), |session| {
                let mut operation = load(&tx, id)?;
                if operation.node_id != node {
                    return Err(failure(ErrorCode::NotFound));
                }
                session.project(&mut operation);
                tx.commit()?;
                crate::journal::log_expired(expired);
                Ok(operation)
            })
    })
    .await
}

pub(super) async fn uncertain(engine: &Engine, id: Uuid, code: ErrorCode) -> Result<Operation> {
    let e = engine.clone();
    job(engine, move |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut operation = load(&tx, id)?;
        let from = operation.state;
        let stage = operation.stage;
        if !operation.state.terminal() && dispatched(&tx, id)? {
            let knowledge: String = tx.query_row(
                "SELECT evidence FROM operation_intents WHERE operation_id=?1",
                [id.to_string()],
                |row| row.get(0),
            )?;
            let knowledge: Knowledge = serde_json::from_str(&knowledge)?;
            if !knowledge.accepted {
                operation.state = OperationState::Unknown;
                operation.stage = OperationStage::Reconciling;
                operation.error = Some(ErrorDetail {
                    code,
                    message: if code == ErrorCode::UpstreamInvalidResponse {
                        "Node response could not be verified."
                    } else {
                        "Operation outcome is unknown."
                    }
                    .into(),
                    request_id: Uuid::new_v4(),
                    operation_id: Some(id),
                    outcome: ErrorOutcome::Unknown,
                });
                operation.updated_at = e.clock.now();
                save(&tx, &operation)?;
            }
        }
        tx.commit()?;
        if from != operation.state || stage != operation.stage {
            crate::observability::Event::transition(Some(from), &operation).emit();
        }
        Ok(operation)
    })
    .await
}

pub(super) async fn replay(
    engine: &Engine,
    context: &Context,
    node: &str,
    key: Uuid,
    input: &str,
) -> Result<Option<Operation>> {
    let e = engine.clone();
    let context = context.clone();
    let node = node.to_string();
    let input = input.to_string();
    job(engine, move |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expired = crate::journal::expire_reviews(&tx, e.clock.now())?;
        let gate = e.node(&node)?;
        let pinned = gate.lock().map_err(|_| failure(ErrorCode::InternalError))?;
        let generation = generation(&tx)?;
        e.auth
            .with_claim_session(&context, generation, e.clock.now(), |session| {
                let pinned = pinned
                    .as_ref()
                    .ok_or_else(|| failure(ErrorCode::NotFound))?;
                writable(&pinned.config)?;
                let mut operation = replay_in(&tx, &node, key, &input)?;
                if let Some(operation) = &mut operation {
                    session.project(operation);
                }
                tx.commit()?;
                crate::journal::log_expired(expired);
                Ok(operation)
            })
    })
    .await
}

pub(super) async fn create(
    engine: &Engine,
    context: &Context,
    intent: ReviewedIntent,
    key: Uuid,
    secret: Option<SealedInvoiceSecret>,
    facts: ReadFacts,
) -> Result<(Operation, bool)> {
    let e = engine.clone();
    let context = context.clone();
    job(engine,move |connection| {
        let tx=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expired = crate::journal::expire_reviews(&tx,e.clock.now())?;
        let gate=e.node(&intent.operation.node_id)?;let pinned=gate.lock().map_err(|_|failure(ErrorCode::InternalError))?;
        let generation=generation(&tx)?;
        e.auth.with_claim_session(&context,generation,e.clock.now(),|session| {
            let now=e.clock.now();let config=&pinned.as_ref().ok_or_else(||failure(ErrorCode::NotFound))?.config;
                writable(config)?;
            if let Some(mut existing)=replay_in(&tx,&intent.operation.node_id,key,&intent.input_digest)? {
                session.project(&mut existing);tx.commit()?;crate::journal::log_expired(expired);return Ok((existing, false));
            }
            check(&intent,&intent.operation,config,Some(&facts),now)?;
            paid(&tx,&intent)?;
            for resource in intent.resources() {
                if let Some(id)=tx.query_row("SELECT operation_id FROM resource_claims WHERE node_id=?1 AND resource=?2",params![intent.operation.node_id,resource.key()],|row| row.get::<_,String>(0)).optional()? {
                    let mut error=failure(ErrorCode::ResourceBusy);error.operation_id=Uuid::parse_str(&id).ok();return Err(error);
                }
            }
            let operation=&intent.operation;
            tx.execute("INSERT INTO operations(id,node_id,request_key,request_digest,body) VALUES(?1,?2,?3,?4,?5)",params![operation.id.to_string(),operation.node_id,key.to_string(),intent.input_digest.as_bytes(),serde_json::to_string(operation)?])?;
            tx.execute("INSERT INTO operation_intents(operation_id,encoding_version,intent,evidence) VALUES(?1,1,?2,?3)",params![operation.id.to_string(),serde_json::to_string(&intent)?,serde_json::to_string(&Knowledge::new(&intent))?])?;
            for resource in intent.resources() {tx.execute("INSERT INTO resource_claims VALUES(?1,?2,?3)",params![operation.node_id,resource.key(),operation.id.to_string()])?;}
            if let Some(secret)=secret {tx.execute("INSERT INTO pending_invoice_secrets VALUES(?1,?2)",params![operation.id.to_string(),secret.0])?;}
            e.faults.hit(FaultPoint::BeforeCreateCommit)?;
            tx.commit()?;
            crate::journal::log_expired(expired);
            crate::observability::Event::transition(None, operation).emit();
            Ok((operation.clone(), true))
        })
    }).await
}

pub(super) async fn duplicate(
    engine: &Engine,
    context: &Context,
    node: &str,
    id: Uuid,
    digest: &str,
) -> Result<Option<Operation>> {
    let e = engine.clone();
    let context = context.clone();
    let node = node.to_string();
    let digest = digest.to_string();
    job(engine, move |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let gate = e.nodes.get(&node).cloned();
        let pinned = gate
            .as_ref()
            .map(|gate| gate.lock().map_err(|_| failure(ErrorCode::InternalError)))
            .transpose()?;
        let generation = generation(&tx)?;
        e.auth
            .with_claim_session(&context, generation, e.clock.now(), |_| {
                let operation = load(&tx, id)?;
                binding(&operation, &node, &digest)?;
                if e.unavailable
                    .get(&node)
                    .is_some_and(|(read_only, _)| *read_only)
                {
                    return Err(failure(ErrorCode::ReadOnly));
                }
                if let Some(Some(pinned)) = pinned.as_deref() {
                    writable(&pinned.config)?;
                }
                if dispatched(&tx, id)? {
                    tx.commit()?;
                    Ok(Some(operation))
                } else {
                    Ok(None)
                }
            })
    })
    .await
}

pub(super) struct ClaimRequest {
    pub node: String,
    pub id: Uuid,
    pub digest: String,
    pub authorization: Option<Uuid>,
    pub cancelled: Arc<Mutex<bool>>,
}

pub(super) async fn claim(
    engine: &Engine,
    context: &Context,
    request: ClaimRequest,
    prepared: &NodeConfig,
    facts: ReadFacts,
) -> Result<Claim> {
    let e = engine.clone();
    let context = context.clone();
    let ClaimRequest {
        node,
        id,
        digest,
        authorization,
        cancelled,
    } = request;
    let prepared = prepared.clone();
    job(engine, move |connection| {
        e.faults.hit(FaultPoint::BeforeClaimTransaction)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cancelled = cancelled
            .lock()
            .map_err(|_| failure(ErrorCode::InternalError))?;
        if *cancelled {
            return Err(failure(ErrorCode::OperationNotReviewable));
        }
        let gate = e.node(&node)?;
        let pinned = gate.lock().map_err(|_| failure(ErrorCode::InternalError))?;
        let generation = generation(&tx)?;
        e.auth
            .with_claim_session(&context, generation, e.clock.now(), |session| {
                let now = e.clock.now();
                let mut operation = load(&tx, id)?;
                binding(&operation, &node, &digest)?;
                if let Some(pinned) = pinned.as_ref() {
                    writable(&pinned.config)?;
                }
                if dispatched(&tx, id)? {
                    tx.commit()?;
                    return Ok(Claim::Existing(Box::new(operation)));
                }
                let config = &pinned
                    .as_ref()
                    .ok_or_else(|| failure(ErrorCode::NotFound))?
                    .config;
                if prepared.generation != config.generation {
                    return Err(failure(ErrorCode::IdentityChanged));
                }
                let intent = stored_intent(&tx, id)?;
                check(&intent, &operation, config, Some(&facts), now)?;
                resources(&tx, &intent)?;
                let secret = if matches!(operation.request, OperationRequest::CreateInvoice(_))
                    && config.backend != Backend::ClnRest
                {
                    let ciphertext: Vec<u8> = tx.query_row(
                        "SELECT ciphertext FROM pending_invoice_secrets WHERE operation_id=?1",
                        [id.to_string()],
                        |row| row.get(0),
                    )?;
                    let secret = e
                        .key
                        .decrypt(&operation, &SealedInvoiceSecret(ciphertext))?;
                    use sha2::Digest;
                    if Some(hex::encode(sha2::Sha256::digest(&secret[..])))
                        != operation.review.payment_hash
                    {
                        return Err(failure(ErrorCode::StorageUnavailable));
                    }
                    Some(secret)
                } else {
                    None
                };
                if operation.review.sensitive && authorization.is_none() {
                    return Err(failure(ErrorCode::ReauthRequired));
                }
                session.consume(&operation, authorization)?;
                e.faults.hit(FaultPoint::AfterGrantRemoval)?;
                let from = operation.state;
                operation.state = OperationState::Dispatching;
                operation.stage = OperationStage::Submitted;
                operation.authorization.status = if operation.review.sensitive {
                    AuthorizationState::Consumed
                } else {
                    AuthorizationState::NotRequired
                };
                operation.authorization.expires_at = None;
                operation.updated_at = now;
                let claim_id = Uuid::new_v4();
                if tx.execute(
                    "UPDATE operations SET dispatched=1,body=?1 WHERE id=?2 AND dispatched=0",
                    params![serde_json::to_string(&operation)?, id.to_string()],
                )? != 1
                {
                    return Err(failure(ErrorCode::InternalError));
                }
                tx.execute(
                    "UPDATE operation_intents SET claim_id=?1 WHERE operation_id=?2",
                    params![claim_id.to_string(), id.to_string()],
                )?;
                e.faults.hit(FaultPoint::BeforeClaimCommit)?;
                tx.commit()
                    .map_err(|error| EngineError::from(error).claimed(id))?;
                crate::observability::Event::transition(Some(from), &operation).emit();
                e.faults
                    .hit(FaultPoint::CommitAcknowledgement)
                    .map_err(|error| error.claimed(id))?;
                Ok(Claim::New(Box::new(ClaimPermit {
                    claim_id,
                    intent,
                    secret,
                })))
            })
    })
    .await
}

pub(super) async fn authorization_gate(
    engine: &Engine,
    context: &Context,
    node: &str,
    id: Uuid,
    digest: &str,
) -> Result<Operation> {
    // Preparation stays outside all locks; final gate checks the pinned generation again.
    engine.live(context).await?;
    let pinned = engine.pinned(node)?;
    writable(&pinned.config)?;
    let operation = load_local(engine, id).await?;
    binding(&operation, node, digest)?;
    let facts = pinned.adapter.prepare_review(&operation).await?;
    let e = engine.clone();
    let context = context.clone();
    let node = node.to_string();
    let digest = digest.to_string();
    job(engine, move |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let gate = e.node(&node)?;
        let pinned = gate.lock().map_err(|_| failure(ErrorCode::InternalError))?;
        let generation = generation(&tx)?;
        e.auth
            .with_claim_session(&context, generation, e.clock.now(), |session| {
                let mut operation = load(&tx, id)?;
                binding(&operation, &node, &digest)?;
                let config = &pinned
                    .as_ref()
                    .ok_or_else(|| failure(ErrorCode::NotFound))?
                    .config;
                let intent = stored_intent(&tx, id)?;
                check(&intent, &operation, config, Some(&facts), e.clock.now())?;
                resources(&tx, &intent)?;
                session.project(&mut operation);
                tx.commit()?;
                Ok(operation)
            })
    })
    .await
}

pub(super) async fn observation_query(
    engine: &Engine,
    id: Uuid,
    config: &NodeConfig,
) -> Result<Option<ObservationQuery>> {
    let config = config.clone();
    let now = engine.clock.now();
    job(engine,move |connection| {
        let tx=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !dispatched(&tx,id)? {return Ok(None);}
        let operation=load(&tx,id)?;
        let row:Option<(Option<String>,Option<String>,i64)>=tx.query_row("SELECT intent,claim_id,next_sequence FROM operation_intents WHERE operation_id=?1 AND encoding_version=1",[id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
        let Some((Some(intent),Some(claim),sequence))=row else {return Ok(None);};
        let intent:ReviewedIntent=serde_json::from_str(&intent)?;
        if config.binding!=operation.review.node || config.generation!=intent.connection_generation {return Ok(None);}
        let knowledge:String=tx.query_row("SELECT evidence FROM operation_intents WHERE operation_id=?1",[id.to_string()],|row|row.get(0))?;
        let mut knowledge:Knowledge=serde_json::from_str(&knowledge)?;
        if knowledge.reconciliation.attempts >= RECONCILIATION_LIFETIME_ATTEMPTS
            || knowledge.reconciliation.next_attempt_at.is_some_and(|next| now < next) {
            return Ok(None);
        }
        knowledge.reconciliation.attempts += 1;
        knowledge.reconciliation.last_attempt_at = Some(now);
        knowledge.reconciliation.last_outcome = Some(ReconciliationOutcome::InFlight);
        knowledge.reconciliation.exhausted = knowledge.reconciliation.attempts >= RECONCILIATION_LIFETIME_ATTEMPTS;
        knowledge.reconciliation.next_attempt_at = if knowledge.reconciliation.exhausted {
            None
        } else {
            Some(now.checked_add_signed(chrono::Duration::seconds(reconciliation_interval_seconds(knowledge.reconciliation.attempts)))
                .ok_or_else(|| failure(ErrorCode::InternalError))?)
        };
        let mut projected = operation.clone();
        projected.reconciliation = Some(knowledge.reconciliation.clone());
        save(&tx, &projected)?;
        let sequence=sequence.checked_add(1).ok_or_else(||failure(ErrorCode::InternalError))?;
        tx.execute("UPDATE operation_intents SET next_sequence=?1 WHERE operation_id=?2",params![sequence,id.to_string()])?;
        tx.execute("UPDATE operation_intents SET evidence=?1 WHERE operation_id=?2",params![serde_json::to_string(&knowledge)?,id.to_string()])?;
        tx.commit()?;
        crate::observability::Event::Reconciliation {
            operation_id: id,
            attempt: knowledge.reconciliation.attempts,
            next_delay_seconds: knowledge.reconciliation.next_attempt_at.map(|next| next.signed_duration_since(now).num_seconds()),
            exhausted: knowledge.reconciliation.exhausted,
        }.emit();
        let (close_type,close_txids)=match operation.result {Some(OperationResult::CloseChannel{close_type,txids,..})=>(Some(close_type),txids),_=>(None,vec![])};
        Ok(Some(ObservationQuery{request:operation.request.clone(),operation_id:id,binding:operation.review.node,generation:config.generation,kind:operation.request.kind(),claim_id:Uuid::parse_str(&claim).map_err(|_|failure(ErrorCode::StorageUnavailable))?,sequence,reference:knowledge.reference,close_type,close_txids}))
    }).await
}

pub(super) async fn observation_candidates(
    engine: &Engine,
    config: &NodeConfig,
) -> Result<Vec<Uuid>> {
    let config = config.clone();
    let now = engine.clock.now();
    job(engine, move |connection| {
        crate::history::register_time_functions(connection)?;
        let mut statement = connection.prepare(
            "SELECT o.id FROM operations o
             JOIN operation_intents i ON i.operation_id=o.id
             WHERE o.node_id=?1 AND o.dispatched=1 AND o.terminal=0
               AND COALESCE(json_extract(i.evidence,'$.reconciliation.attempts'),0) < ?2
               AND (json_extract(i.evidence,'$.reconciliation.next_attempt_at') IS NULL
                    OR creation_seconds(json_extract(i.evidence,'$.reconciliation.next_attempt_at')) < ?3
                    OR (creation_seconds(json_extract(i.evidence,'$.reconciliation.next_attempt_at')) = ?3
                        AND creation_nanos(json_extract(i.evidence,'$.reconciliation.next_attempt_at')) <= ?4))
               AND json_extract(o.body,'$.review.node')=json(?5)
               AND json_extract(i.intent,'$.connection_generation')=?6
             ORDER BY json_extract(i.evidence,'$.reconciliation.last_attempt_at') ASC,o.id ASC
             LIMIT ?7"
        )?;
        let mut rows = statement.query(params![
            config.binding.node_id,
            RECONCILIATION_LIFETIME_ATTEMPTS,
            now.timestamp(),
            now.timestamp_subsec_nanos(),
            serde_json::to_string(&config.binding)?,
            config.generation.to_string(),
            i64::try_from(LIST_RECONCILIATION_CAP).map_err(|_| failure(ErrorCode::InternalError))?,
        ])?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            ids.push(Uuid::parse_str(&id).map_err(|_| failure(ErrorCode::StorageUnavailable))?);
        }
        Ok(ids)
    }).await
}

pub(super) async fn apply(
    engine: &Engine,
    id: Uuid,
    evidence: Evidence,
    read: bool,
) -> Result<Operation> {
    let e = engine.clone();
    job(engine, move |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = load(&tx, id)?;
        if !dispatched(&tx, id)? {
            return Err(failure(ErrorCode::OperationNotReviewable));
        }
        let intent = stored_intent(&tx, id)?;
        intent.validate(&operation)?;
        let (claim, sequence, knowledge): (String, i64, String) = tx.query_row(
            "SELECT claim_id,next_sequence,evidence FROM operation_intents WHERE operation_id=?1",
            [id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let claim = Uuid::parse_str(&claim).map_err(|_| failure(ErrorCode::StorageUnavailable))?;
        let from = operation.state;
        let stage = operation.stage;
        let transition = evidence::transition(
            &intent,
            operation,
            serde_json::from_str(&knowledge)?,
            evidence,
            evidence::ObservationContext {
                claim_id: claim,
                allocated_sequence: sequence,
                read,
                now: e.clock.now(),
            },
        )?;
        save(&tx, &transition.operation)?;
        tx.execute(
            "UPDATE operation_intents SET evidence=?1 WHERE operation_id=?2",
            params![
                serde_json::to_string(&transition.knowledge)?,
                id.to_string()
            ],
        )?;
        if let Some(hash) = transition.paid_hash {
            tx.execute(
                "INSERT OR IGNORE INTO paid_hashes VALUES(?1,?2,?3)",
                params![transition.operation.node_id, hash, id.to_string()],
            )?;
        }
        if transition.release {
            tx.execute(
                "DELETE FROM resource_claims WHERE operation_id=?1",
                [id.to_string()],
            )?;
            tx.execute(
                "DELETE FROM pending_invoice_secrets WHERE operation_id=?1",
                [id.to_string()],
            )?;
        }
        e.faults.hit(FaultPoint::ObservationCommit)?;
        tx.commit()?;
        if from != transition.operation.state || stage != transition.operation.stage {
            crate::observability::Event::transition(Some(from), &transition.operation).emit();
        }
        Ok(transition.operation)
    })
    .await
}
