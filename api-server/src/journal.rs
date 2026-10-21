use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use chrono::{DateTime, Utc};
use lightning_client::model::{
    AuthorizationState, ErrorCode, ErrorDetail, ErrorOutcome, Operation, OperationResult,
    OperationStage, OperationState,
};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const SQLITE_BUSY_SECONDS: u64 = 3;
const SQLITE_WORKERS: usize = 4;
const PAYMENT_RESOURCE_PREFIX: &str = "payment:";

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("Operation not found")]
    NotFound,
    #[error("Idempotency key belongs to another request")]
    IdempotencyConflict(Uuid),
    #[error("Resource is reserved by an unresolved operation")]
    ResourceBusy(Uuid),
    #[error("Payment is already settled")]
    AlreadyPaid(Uuid),
    #[error("Review cannot be dispatched")]
    NotReviewable,
    #[error("Review expired")]
    ReviewExpired,
    #[error("Authentication was revoked")]
    Revoked,
    #[error("Protected storage unavailable")]
    Storage,
    #[error("Pending invoice secret cannot be authenticated")]
    Secret,
    #[error("Response exceeds the configured byte limit")]
    ResponseTooLarge,
}

impl From<rusqlite::Error> for JournalError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
impl From<serde_json::Error> for JournalError {
    fn from(_: serde_json::Error) -> Self {
        Self::Storage
    }
}

#[derive(Clone)]
pub struct Journal {
    path: Arc<PathBuf>,
    workers: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone, Debug)]
pub enum Created {
    New(Box<Operation>),
    Existing(Box<Operation>),
}

#[derive(Clone, Debug)]
pub enum Claimed {
    New(Box<Operation>),
    Existing(Box<Operation>),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Resource {
    Intent(String),
    Payment(String),
    Wallet,
    Peer(String),
    Channel(String),
}

impl Resource {
    pub(crate) fn key(&self) -> String {
        match self {
            Self::Intent(hash) => format!("intent:{hash}"),
            Self::Payment(hash) => format!("{PAYMENT_RESOURCE_PREFIX}{hash}"),
            Self::Wallet => "wallet".into(),
            Self::Peer(key) => format!("peer:{key}"),
            Self::Channel(id) => format!("channel:{id}"),
        }
    }
}

#[derive(Clone)]
pub struct SealedInvoiceSecret(pub(crate) Vec<u8>);

pub struct PendingSecretKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl PendingSecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn encrypt(
        &self,
        operation: &Operation,
        secret: &[u8; 32],
    ) -> Result<SealedInvoiceSecret, JournalError> {
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let context = serde_json::to_vec(&(
            operation.id,
            &operation.review.node,
            &operation.review.digest,
        ))?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.bytes.as_ref())
            .map_err(|_| JournalError::Secret)?;
        let encrypted = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: secret,
                    aad: &context,
                },
            )
            .map_err(|_| JournalError::Secret)?;
        let mut sealed = nonce.to_vec();
        sealed.extend(encrypted);
        Ok(SealedInvoiceSecret(sealed))
    }

    pub fn decrypt(
        &self,
        operation: &Operation,
        sealed: &SealedInvoiceSecret,
    ) -> Result<Zeroizing<[u8; 32]>, JournalError> {
        let sealed = &sealed.0;
        if sealed.len() != 24 + 32 + 16 {
            return Err(JournalError::Secret);
        }
        let context = serde_json::to_vec(&(
            operation.id,
            &operation.review.node,
            &operation.review.digest,
        ))?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.bytes.as_ref())
            .map_err(|_| JournalError::Secret)?;
        let nonce: [u8; 24] = sealed[..24].try_into().map_err(|_| JournalError::Secret)?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &sealed[24..],
                        aad: &context,
                    },
                )
                .map_err(|_| JournalError::Secret)?,
        );
        let bytes: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| JournalError::Secret)?;
        Ok(Zeroizing::new(bytes))
    }
}

impl Journal {
    #[cfg(test)]
    pub(crate) fn with_test_capacity(mut self, workers: usize) -> Self {
        self.workers = Arc::new(tokio::sync::Semaphore::new(workers));
        self
    }
    pub async fn open(path: PathBuf) -> Result<Self, JournalError> {
        let journal = Self {
            path: Arc::new(path),
            workers: Arc::new(tokio::sync::Semaphore::new(SQLITE_WORKERS)),
        };
        journal.run(|connection| {
            crate::migrations::migrate(connection)?;
            connection.execute_batch("PRAGMA journal_mode=WAL;")?;
            connection.execute("INSERT OR IGNORE INTO auth_meta(singleton,operator_id,generation) VALUES(1,?1,0)",[Uuid::new_v4().to_string()])?;
            Ok(())
        }).await?;
        Ok(journal)
    }

    pub async fn run<T: Send + 'static>(
        &self,
        action: impl FnOnce(&mut Connection) -> Result<T, JournalError> + Send + 'static,
    ) -> Result<T, JournalError> {
        let path = self.path.clone();
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| JournalError::Storage)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            ensure_protected(&path)?;
            let mut connection = Connection::open(path.as_path())?;
            connection.busy_timeout(Duration::from_secs(SQLITE_BUSY_SECONDS))?;
            connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
            crate::migrations::register_functions(&connection)?;
            action(&mut connection)
        })
        .await
        .map_err(|_| JournalError::Storage)?
    }

    pub async fn authentication(&self) -> Result<(Uuid, i64), JournalError> {
        self.run(|connection| {
            let (id, generation): (String, i64) = connection.query_row(
                "SELECT operator_id,generation FROM auth_meta WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            Ok((
                Uuid::parse_str(&id).map_err(|_| JournalError::Storage)?,
                generation,
            ))
        })
        .await
    }

    pub async fn issue_enrollment(
        &self,
        now: DateTime<Utc>,
        ttl: Duration,
        recover: bool,
    ) -> Result<Zeroizing<String>, JournalError> {
        let mut random = [0u8; 32];
        OsRng.fill_bytes(&mut random);
        let token = Zeroizing::new(hex::encode(random));
        let token_hash = Sha256::digest(token.as_bytes()).to_vec();
        let expiry = now
            .timestamp()
            .checked_add(i64::try_from(ttl.as_secs()).map_err(|_| JournalError::Storage)?)
            .ok_or(JournalError::Storage)?;
        self.run(move |connection| {
            let tx=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if recover {
                tx.execute("UPDATE auth_meta SET generation=generation+1 WHERE singleton=1",[])?;
                tx.execute("DELETE FROM credentials",[])?;
                tx.execute("DELETE FROM enrollment",[])?;
            }
            tx.execute("DELETE FROM enrollment WHERE expires_at<=?1",[now.timestamp()])?;
            tx.execute("INSERT INTO enrollment(token_hash,generation,expires_at) SELECT ?1,generation,?2 FROM auth_meta WHERE singleton=1",params![token_hash,expiry])?;
            tx.commit()?;Ok(())
        }).await?;
        Ok(token)
    }

    pub async fn claim_enrollment(
        &self,
        token: Zeroizing<String>,
        now: DateTime<Utc>,
    ) -> Result<i64, JournalError> {
        let token_hash = Sha256::digest(token.as_bytes()).to_vec();
        self.run(move |connection| {
            let tx=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let generation:Option<i64>=tx.query_row("SELECT e.generation FROM enrollment e JOIN auth_meta a ON a.singleton=1 AND a.generation=e.generation WHERE token_hash=?1 AND expires_at>?2",params![token_hash,now.timestamp()],|row|row.get(0)).optional()?;
            tx.execute("DELETE FROM enrollment WHERE token_hash=?1",[token_hash])?;
            tx.commit()?;
            generation.ok_or(JournalError::Revoked)
        }).await
    }

    pub async fn enrollment_available(&self, now: DateTime<Utc>) -> Result<bool, JournalError> {
        self.run(move |connection| Ok(connection.query_row("SELECT EXISTS(SELECT 1 FROM enrollment e JOIN auth_meta a ON a.singleton=1 AND a.generation=e.generation WHERE expires_at>?1)",[now.timestamp()],|row|row.get(0))?)).await
    }

    pub async fn create(
        &self,
        operation: Operation,
        request_key: Uuid,
        resources: Vec<Resource>,
        secret: Option<SealedInvoiceSecret>,
    ) -> Result<Created, JournalError> {
        let resources: std::collections::BTreeSet<Resource> = resources.into_iter().collect();
        if !operation.binding_is_valid()
            || operation.state != OperationState::AwaitingConfirmation
            || operation.stage != OperationStage::NotDispatched
        {
            return Err(JournalError::NotReviewable);
        }
        if secret.is_some()
            && !matches!(
                operation.request,
                lightning_client::model::OperationRequest::CreateInvoice(_)
            )
        {
            return Err(JournalError::NotReviewable);
        }
        let digest = Sha256::digest(serde_json::to_vec(&operation.request)?).to_vec();
        self.run(move |connection| {
            let tx=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if let Some((existing,digest_before))=tx.query_row("SELECT body,request_digest FROM operations WHERE node_id=?1 AND request_key=?2",params![operation.node_id,request_key.to_string()],|row|Ok((row.get::<_,String>(0)?,row.get::<_,Vec<u8>>(1)?))).optional()? {
                let existing:Operation=serde_json::from_str(&existing)?;
                if digest!=digest_before { return Err(JournalError::IdempotencyConflict(existing.id)); }
                return Ok(Created::Existing(Box::new(existing)));
            }
            expire_reviews(&tx,Utc::now())?;
            for resource in &resources {
                if let Some(blocker)=tx.query_row("SELECT operation_id FROM resource_claims WHERE node_id=?1 AND resource=?2",params![operation.node_id,resource.key()],|row|row.get::<_,String>(0)).optional()? {
                    let id=Uuid::parse_str(&blocker).map_err(|_|JournalError::Storage)?;
                    let previous=load(&tx,id)?;
                    if previous.state==OperationState::Succeeded && matches!(resource,Resource::Payment(_)) { return Err(JournalError::AlreadyPaid(id)); }
                    return Err(JournalError::ResourceBusy(id));
                }
            }
            tx.execute("INSERT INTO operations(id,node_id,request_key,request_digest,body) VALUES(?1,?2,?3,?4,?5)",params![operation.id.to_string(),operation.node_id,request_key.to_string(),digest,serde_json::to_string(&operation)?])?;
            for resource in resources { tx.execute("INSERT INTO resource_claims(node_id,resource,operation_id) VALUES(?1,?2,?3)",params![operation.node_id,resource.key(),operation.id.to_string()])?; }
            if let Some(ciphertext)=secret { tx.execute("INSERT INTO pending_invoice_secrets(operation_id,ciphertext) VALUES(?1,?2)",params![operation.id.to_string(),ciphertext.0])?; }
            tx.commit()?;
            Ok(Created::New(Box::new(operation)))
        }).await
    }

    pub async fn get(&self, id: Uuid) -> Result<Operation, JournalError> {
        self.run(move |connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            expire_reviews(&tx, Utc::now())?;
            let operation = load(&tx, id)?;
            tx.commit()?;
            Ok(operation)
        })
        .await
    }

    pub async fn list(
        &self,
        node_id: String,
        max_items: usize,
    ) -> Result<(Vec<Operation>, bool), JournalError> {
        self.history(node_id, None, None, max_items).await
    }

    pub async fn claim(
        &self,
        id: Uuid,
        node_id: String,
        review_digest: String,
        policy_revision: String,
        generation: i64,
        now: DateTime<Utc>,
    ) -> Result<Claimed, JournalError> {
        self.run(move |connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            check_generation(&tx, generation)?;
            if engine_owned(&tx, id)? {
                return Err(JournalError::NotReviewable);
            }
            let mut operation = load(&tx, id)?;
            if operation.node_id != node_id {
                return Err(JournalError::NotFound);
            }
            let dispatched: bool = tx.query_row(
                "SELECT dispatched FROM operations WHERE id=?1",
                [id.to_string()],
                |row| row.get(0),
            )?;
            if dispatched {
                return Ok(Claimed::Existing(Box::new(operation)));
            }
            if operation.state != OperationState::AwaitingConfirmation
                || operation.review.digest != review_digest
                || operation.review.policy_revision != policy_revision
            {
                return Err(JournalError::NotReviewable);
            }
            if operation.review.expires_at <= now {
                return Err(JournalError::ReviewExpired);
            }
            operation.state = OperationState::Dispatching;
            operation.stage = OperationStage::Submitted;
            operation.authorization.status = if operation.review.sensitive {
                AuthorizationState::Consumed
            } else {
                AuthorizationState::NotRequired
            };
            operation.updated_at = now;
            tx.execute(
                "UPDATE operations SET dispatched=1,body=?1 WHERE id=?2 AND dispatched=0",
                params![serde_json::to_string(&operation)?, id.to_string()],
            )?;
            tx.commit()?;
            Ok(Claimed::New(Box::new(operation)))
        })
        .await
    }

    pub async fn record(
        &self,
        id: Uuid,
        state: OperationState,
        stage: OperationStage,
        result: Option<OperationResult>,
        error: Option<ErrorDetail>,
        now: DateTime<Utc>,
    ) -> Result<Operation, JournalError> {
        self.run(move |connection| {
            let tx=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if engine_owned(&tx,id)? {return Err(JournalError::NotReviewable);}
            let mut operation=load(&tx,id)?;
            if operation.state.terminal() { return Ok(operation); }
            let dispatched:bool=tx.query_row("SELECT dispatched FROM operations WHERE id=?1",[id.to_string()],|row|row.get(0))?;
            if !dispatched { return Err(JournalError::NotReviewable); }
            if matches!(state,OperationState::AwaitingConfirmation|OperationState::Dispatching|OperationState::Expired) {return Err(JournalError::NotReviewable);}
            operation.state=state;operation.stage=stage;operation.result=result.or(operation.result);
            operation.error=error;operation.updated_at=now;operation.last_reconciled_at=Some(now);
            save(&tx,&operation)?;
            if state.terminal() {
                if state==OperationState::Succeeded && matches!(operation.request,lightning_client::model::OperationRequest::PayInvoice(_)) {
                    tx.execute("DELETE FROM resource_claims WHERE operation_id=?1 AND resource NOT LIKE ?2",params![id.to_string(),format!("{PAYMENT_RESOURCE_PREFIX}%")])?;
                } else { tx.execute("DELETE FROM resource_claims WHERE operation_id=?1",[id.to_string()])?; }
                tx.execute("DELETE FROM pending_invoice_secrets WHERE operation_id=?1",[id.to_string()])?;
            }
            tx.commit()?;Ok(operation)
        }).await
    }

    pub async fn pending_secret(
        &self,
        id: Uuid,
    ) -> Result<Option<SealedInvoiceSecret>, JournalError> {
        self.run(move |connection| {
            Ok(connection
                .query_row(
                    "SELECT ciphertext FROM pending_invoice_secrets WHERE operation_id=?1",
                    [id.to_string()],
                    |row| row.get(0),
                )
                .optional()?
                .map(SealedInvoiceSecret))
        })
        .await
    }

    pub async fn recover(&self, now: DateTime<Utc>) -> Result<(), JournalError> {
        self.run(move |connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut statement =
                tx.prepare("SELECT body FROM operations WHERE dispatched=1 AND terminal=0")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            let mut recovering = Vec::new();
            for row in rows {
                let mut operation: Operation = serde_json::from_str(&row?)?;
                if !operation.state.terminal() {
                    operation.state = OperationState::Unknown;
                    operation.stage = OperationStage::Reconciling;
                    operation.updated_at = now;
                    operation.error = Some(ErrorDetail {
                        code: ErrorCode::OutcomeUnknown,
                        message: "Operation outcome is unknown. Check its status.".into(),
                        request_id: Uuid::new_v4(),
                        operation_id: Some(operation.id),
                        outcome: ErrorOutcome::Unknown,
                    });
                    recovering.push(operation);
                }
            }
            drop(statement);
            for operation in recovering {
                save(&tx, &operation)?;
            }
            // Restart expires every undispatched review, including future-dated ones.
            // The cutoff is MAX_UTC; the transition timestamp is the captured startup now.
            expire_reviews_before(&tx, DateTime::<Utc>::MAX_UTC, now)?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
}

fn check_generation(connection: &Connection, generation: i64) -> Result<(), JournalError> {
    let current: i64 = connection.query_row(
        "SELECT generation FROM auth_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if current != generation {
        return Err(JournalError::Revoked);
    }
    Ok(())
}

fn engine_owned(connection: &Connection, id: Uuid) -> Result<bool, JournalError> {
    Ok(connection.query_row("SELECT EXISTS(SELECT 1 FROM operation_intents WHERE operation_id=?1 AND encoding_version=1)", [id.to_string()], |row| row.get(0))?)
}

fn load(connection: &Connection, id: Uuid) -> Result<Operation, JournalError> {
    let body: Option<String> = connection
        .query_row(
            "SELECT body FROM operations WHERE id=?1",
            [id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(serde_json::from_str(&body.ok_or(JournalError::NotFound)?)?)
}

fn save(connection: &Connection, operation: &Operation) -> Result<(), JournalError> {
    connection.execute(
        "UPDATE operations SET body=?1 WHERE id=?2",
        params![serde_json::to_string(operation)?, operation.id.to_string()],
    )?;
    Ok(())
}

pub(crate) fn expire_reviews(
    connection: &Connection,
    now: DateTime<Utc>,
) -> Result<(), JournalError> {
    expire_reviews_before(connection, now, now)
}

fn expire_reviews_before(
    connection: &Connection,
    cutoff: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), JournalError> {
    crate::history::register_time_functions(connection)?;
    connection.execute(
        "UPDATE operations
         SET body=json_set(body,'$.state','expired','$.updated_at',?1)
         WHERE dispatched=0
           AND state='awaiting_confirmation'
           AND (
             creation_seconds(json_extract(body,'$.review.expires_at'))<?2
             OR (
               creation_seconds(json_extract(body,'$.review.expires_at'))=?2
               AND creation_nanos(json_extract(body,'$.review.expires_at'))<=?3
             )
           )",
        params![
            now.to_rfc3339(),
            cutoff.timestamp(),
            i64::from(cutoff.timestamp_subsec_nanos()),
        ],
    )?;
    for table in ["resource_claims", "pending_invoice_secrets"] {
        let statement = format!(
            "DELETE FROM {table}
             WHERE operation_id IN (
               SELECT id FROM operations
               WHERE dispatched=0 AND state='expired'
             )"
        );
        connection.execute(&statement, [])?;
    }
    Ok(())
}

fn ensure_protected(path: &Path) -> Result<(), JournalError> {
    validate_state_directory(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| JournalError::Storage)?;
    let metadata = file.metadata().map_err(|_| JournalError::Storage)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
    {
        return Err(JournalError::Storage);
    }
    Ok(())
}

pub(crate) fn validate_state_directory(database: &Path) -> Result<(), JournalError> {
    let parent = database
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = std::fs::symlink_metadata(parent).map_err(|_| JournalError::Storage)?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(JournalError::Storage);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightning_client::{
        model::{OperationRequest, ReauthMode},
        money::{Decimal, Msat},
    };

    fn operation() -> Operation {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/api-examples.json")).unwrap();
        let mut operation: Operation =
            serde_json::from_value(fixtures["fixtures"]["operation_review"]["value"].clone())
                .unwrap();
        operation.id = Uuid::new_v4();
        operation.review.operation_id = operation.id;
        operation.created_at = Utc::now();
        operation.updated_at = operation.created_at;
        operation.review.expires_at = operation.created_at + chrono::Duration::minutes(5);
        operation.authorization.mode = ReauthMode::EveryOperation;
        operation
    }

    async fn store() -> (tempfile::TempDir, Journal) {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let journal = Journal::open(directory.path().join("journal.sqlite"))
            .await
            .unwrap();
        (directory, journal)
    }

    async fn claim(journal: &Journal, operation: &Operation) -> Result<Claimed, JournalError> {
        journal
            .claim(
                operation.id,
                operation.node_id.clone(),
                operation.review.digest.clone(),
                operation.review.policy_revision.clone(),
                journal.authentication().await.unwrap().1,
                Utc::now(),
            )
            .await
    }

    #[tokio::test]
    async fn idempotency_semantic_claims_and_concurrent_confirm_are_durable() {
        let (directory, journal) = store().await;
        let original = operation();
        let key = Uuid::new_v4();
        let resources = vec![Resource::Payment("synthetic".into()), Resource::Wallet];
        assert!(matches!(
            journal
                .create(original.clone(), key, resources.clone(), None)
                .await
                .unwrap(),
            Created::New(_)
        ));
        assert!(matches!(
            journal
                .create(original.clone(), key, resources.clone(), None)
                .await
                .unwrap(),
            Created::Existing(_)
        ));
        let mut changed = original.clone();
        if let OperationRequest::PayInvoice(ref mut params) = changed.request {
            params.max_fee_msat = Msat(Decimal::new(5).unwrap());
        }
        assert!(
            matches!(journal.create(changed,key,resources.clone(),None).await,Err(JournalError::IdempotencyConflict(id)) if id==original.id)
        );
        let different = operation();
        assert!(
            matches!(journal.create(different,Uuid::new_v4(),resources.clone(),None).await,Err(JournalError::ResourceBusy(id)) if id==original.id)
        );
        let (a, b) = tokio::join!(claim(&journal, &original), claim(&journal, &original));
        let claims = [a.unwrap(), b.unwrap()];
        assert_eq!(
            claims
                .iter()
                .filter(|claim| matches!(claim, Claimed::New(_)))
                .count(),
            1
        );
        let reopened = Journal::open(directory.path().join("journal.sqlite"))
            .await
            .unwrap();
        reopened.recover(Utc::now()).await.unwrap();
        let recovered = reopened.get(original.id).await.unwrap();
        assert_eq!(recovered.state, OperationState::Unknown);
        assert!(matches!(
            claim(&reopened, &original).await.unwrap(),
            Claimed::Existing(_)
        ));
        assert!(matches!(
            reopened
                .create(operation(), Uuid::new_v4(), vec![Resource::Wallet], None)
                .await,
            Err(JournalError::ResourceBusy(_))
        ));
        reopened
            .record(
                original.id,
                OperationState::Succeeded,
                OperationStage::Settled,
                None,
                None,
                Utc::now(),
            )
            .await
            .unwrap();
        assert!(matches!(
            reopened
                .create(operation(), Uuid::new_v4(), resources, None)
                .await,
            Err(JournalError::AlreadyPaid(_))
        ));
    }

    #[tokio::test]
    async fn expired_reviews_release_claims_but_recovery_never_replays() {
        let (_directory, journal) = store().await;
        let mut expired = operation();
        expired.review.expires_at = Utc::now() - chrono::Duration::seconds(1);
        journal
            .create(
                expired.clone(),
                Uuid::new_v4(),
                vec![Resource::Wallet],
                None,
            )
            .await
            .unwrap();
        assert!(matches!(
            claim(&journal, &expired).await,
            Err(JournalError::ReviewExpired)
        ));
        assert_eq!(
            journal.get(expired.id).await.unwrap().state,
            OperationState::Expired
        );
        let current = operation();
        journal
            .create(
                current.clone(),
                Uuid::new_v4(),
                vec![Resource::Wallet],
                None,
            )
            .await
            .unwrap();
        journal.recover(Utc::now()).await.unwrap();
        assert_eq!(
            journal.get(current.id).await.unwrap().state,
            OperationState::Expired
        );
        assert!(matches!(
            claim(&journal, &current).await,
            Err(JournalError::NotReviewable)
        ));
    }

    #[tokio::test]
    async fn enrollment_is_one_use_and_host_recovery_revokes_existing_generation() {
        let (_directory, journal) = store().await;
        let generation = journal.authentication().await.unwrap().1;
        let token = journal
            .issue_enrollment(Utc::now(), Duration::from_secs(60), false)
            .await
            .unwrap();
        assert!(journal.enrollment_available(Utc::now()).await.unwrap());
        assert_eq!(
            journal
                .claim_enrollment(token.clone(), Utc::now())
                .await
                .unwrap(),
            generation
        );
        assert!(matches!(
            journal.claim_enrollment(token, Utc::now()).await,
            Err(JournalError::Revoked)
        ));
        let original = operation();
        journal
            .create(original.clone(), Uuid::new_v4(), vec![], None)
            .await
            .unwrap();
        journal
            .issue_enrollment(Utc::now(), Duration::from_secs(60), true)
            .await
            .unwrap();
        assert!(matches!(
            journal
                .claim(
                    original.id,
                    original.node_id.clone(),
                    original.review.digest.clone(),
                    original.review.policy_revision.clone(),
                    generation,
                    Utc::now()
                )
                .await,
            Err(JournalError::Revoked)
        ));
        assert_eq!(journal.authentication().await.unwrap().1, generation + 1);
    }

    #[tokio::test]
    async fn invalid_identity_or_sensitivity_binding_is_not_journalled() {
        let (_directory, journal) = store().await;
        let mut invalid = operation();
        invalid.review.operation_id = Uuid::new_v4();
        assert!(matches!(
            journal.create(invalid, Uuid::new_v4(), vec![], None).await,
            Err(JournalError::NotReviewable)
        ));
        let mut invalid = operation();
        invalid.review.node.node_id = "different-node".into();
        assert!(matches!(
            journal.create(invalid, Uuid::new_v4(), vec![], None).await,
            Err(JournalError::NotReviewable)
        ));
        let mut invalid = operation();
        invalid.review.sensitive = false;
        assert!(matches!(
            journal.create(invalid, Uuid::new_v4(), vec![], None).await,
            Err(JournalError::NotReviewable)
        ));
        let (operations, truncated) = journal.list("lnd-lab".into(), 1).await.unwrap();
        assert!(operations.is_empty());
        assert!(!truncated);
    }

    #[tokio::test]
    async fn duplicate_resources_are_one_atomic_claim() {
        let (_directory, journal) = store().await;
        let original = operation();
        journal
            .create(
                original.clone(),
                Uuid::new_v4(),
                vec![
                    Resource::Wallet,
                    Resource::Wallet,
                    Resource::Payment("synthetic".into()),
                    Resource::Payment("synthetic".into()),
                ],
                None,
            )
            .await
            .unwrap();
        assert!(matches!(
            claim(&journal, &original).await.unwrap(),
            Claimed::New(_)
        ));
        assert!(
            matches!(journal.create(operation(),Uuid::new_v4(),vec![Resource::Wallet],None).await,Err(JournalError::ResourceBusy(id)) if id==original.id)
        );
    }

    #[tokio::test]
    async fn transitions_keep_metadata_atomic_and_startup_cutoff_separate_from_timestamp() {
        let (_directory, journal) = store().await;
        let original = operation();
        let undispatched = operation();
        for operation in [&original, &undispatched] {
            journal
                .create(operation.clone(), Uuid::new_v4(), vec![], None)
                .await
                .unwrap();
        }
        let now = Utc::now();
        journal
            .claim(
                original.id,
                original.node_id.clone(),
                original.review.digest.clone(),
                original.review.policy_revision.clone(),
                journal.authentication().await.unwrap().1,
                now,
            )
            .await
            .unwrap();
        journal.recover(now).await.unwrap();
        assert_eq!(journal.get(original.id).await.unwrap().updated_at, now);
        let expired = journal.get(undispatched.id).await.unwrap();
        assert_eq!(expired.state, OperationState::Expired);
        assert_eq!(expired.updated_at, now);
        journal
            .record(
                original.id,
                OperationState::Succeeded,
                OperationStage::Settled,
                None,
                None,
                now,
            )
            .await
            .unwrap();
        journal.run(|connection| {
            let mismatches: i64 = connection.query_row("SELECT count(*) FROM operations WHERE created_at_ns!=timestamp_ns(json_extract(body,'$.created_at')) OR updated_at_ns!=timestamp_ns(json_extract(body,'$.updated_at')) OR state!=json_extract(body,'$.state') OR kind!=json_extract(body,'$.request.kind') OR terminal!=(state IN ('succeeded','failed','expired')) OR sensitivity!=json_extract(body,'$.review.sensitive')", [], |row| row.get(0))?;
            assert_eq!(mismatches, 0);
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("UPDATE operations SET body=json_set(body,'$.state','pending')", [])?;
            assert_eq!(tx.query_row("SELECT count(*) FROM operations WHERE terminal=0 AND state='pending'", [], |row| row.get::<_, i64>(0))?, 2);
            tx.rollback()?;
            assert_eq!(connection.query_row("SELECT count(*) FROM operations WHERE terminal=1", [], |row| row.get::<_, i64>(0))?, 2);
            Ok(())
        }).await.unwrap();
    }

    #[test]
    fn invoice_preimage_aead_binds_operation_identity_and_review() {
        let key = PendingSecretKey::new([7; 32]);
        let original = operation();
        let secret = [8; 32];
        let sealed = key.encrypt(&original, &secret).unwrap();
        assert!(!sealed.0.windows(32).any(|bytes| bytes == secret));
        assert_eq!(*key.decrypt(&original, &sealed).unwrap(), secret);
        let mut retargeted = original.clone();
        retargeted.review.node.identity_revision.push_str("changed");
        assert!(matches!(
            key.decrypt(&retargeted, &sealed),
            Err(JournalError::Secret)
        ));
        let mut tampered = sealed.clone();
        tampered.0[25] ^= 1;
        assert!(matches!(
            key.decrypt(&original, &tampered),
            Err(JournalError::Secret)
        ));
        assert!(!serde_json::to_string(&original)
            .unwrap()
            .contains(&hex::encode(secret)));
    }
}
