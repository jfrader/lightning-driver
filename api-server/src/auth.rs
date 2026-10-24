use crate::journal::{Journal, JournalError};
use chrono::{DateTime, Duration, Utc};
use lightning_client::{
    model::{NodeBinding, Operation, OperationState, ReauthMode},
    settings::{ApiSettings, Limits, ReauthPolicy},
};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use zeroize::Zeroizing;

mod nostr_auth;
mod session_store;
pub use nostr_auth::{
    NostrAuthorizationStart, NostrChallenge, NostrFinish, NostrIdentity, NostrOutcome, NostrStart,
};
use session_store::SessionStore;

const MAX_AUTHENTICATORS: usize = 16;
const MAX_RATE_BUCKETS: usize = 256;
const VERIFICATION_WORKERS: usize = 2;
const RATE_WINDOW_SECONDS: i64 = 60;
const ANONYMOUS_IDENTITY_SHARES: usize = 4;
const AUTHENTICATED_CHALLENGE_RESERVE_DIVISOR: usize = 4;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ClientIdentity {
    Socket(IpAddr),
    Forwarded(IpAddr),
}

#[derive(Clone)]
struct AdmissionLimits {
    anonymous: usize,
    anonymous_per_identity: usize,
    starts_per_minute: usize,
    rate_buckets: usize,
}

impl From<&Limits> for AdmissionLimits {
    fn from(limits: &Limits) -> Self {
        Self {
            anonymous: limits.max_sessions,
            anonymous_per_identity: (limits.max_sessions / ANONYMOUS_IDENTITY_SHARES).max(1),
            starts_per_minute: limits.login_attempts_per_minute,
            rate_buckets: MAX_RATE_BUCKETS,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Resource not found")]
    NotFound,
    #[error("Keep at least one sign-in method")]
    LastCredential,
    #[error("Enrollment unavailable")]
    EnrollmentUnavailable,
    #[error("Invalid request")]
    InvalidRequest,
    #[error("Sign in required")]
    Session,
    #[error("Reload the session")]
    Csrf,
    #[error("Authentication failed")]
    Authentication,
    #[error("Authentication challenge invalid or consumed")]
    Challenge,
    #[error("Authentication challenge expired")]
    Expired,
    #[error("Authentication capacity exceeded")]
    Limited,
    #[error("Authentication capacity exceeded")]
    AllocationLimited(u64),
    #[error("Operation authorization invalid")]
    Authorization,
    #[error("Operation does not require reauthentication")]
    NotRequired,
    #[error("Sign in again before changing sign-in methods")]
    ReauthRequired,
    #[error("Protected authentication storage unavailable")]
    Storage,
}

impl From<JournalError> for AuthError {
    fn from(error: JournalError) -> Self {
        if matches!(error, JournalError::Revoked) {
            Self::Session
        } else {
            Self::Storage
        }
    }
}

#[derive(Clone)]
pub struct AuthManager {
    public_origin: url::Url,
    webauthn: Arc<Webauthn>,
    journal: Journal,
    sessions: SessionStore,
    session_gate: Arc<Mutex<()>>,
    limits: Limits,
    admission: AdmissionLimits,
    policy: ReauthPolicy,
    memory: Arc<Mutex<Memory>>,
    workers: Arc<Semaphore>,
}

#[derive(Default)]
struct Memory {
    nostr_pending: HashMap<Uuid, (Uuid, DateTime<Utc>)>,
    nostr_failures: HashMap<Uuid, VecDeque<DateTime<Utc>>>,
    contexts: HashMap<[u8; 32], Context>,
    ceremonies: HashMap<Uuid, Ceremony>,
    grants: HashMap<Uuid, Grant>,
    rates: HashMap<ClientIdentity, VecDeque<DateTime<Utc>>>,
    verifying: HashMap<Uuid, usize>,
}

pub(crate) struct ClaimSession<'a> {
    memory: &'a mut Memory,
    context: Context,
    now: DateTime<Utc>,
}

impl ClaimSession<'_> {
    pub(crate) fn consume(
        &mut self,
        operation: &Operation,
        authorization: Option<Uuid>,
    ) -> Result<(), AuthError> {
        if !operation.request.sensitive() {
            return if authorization.is_none() {
                Ok(())
            } else {
                Err(AuthError::Authorization)
            };
        }
        let id = authorization.ok_or(AuthError::Authorization)?;
        let grant = self
            .memory
            .grants
            .get(&id)
            .ok_or(AuthError::Authorization)?;
        if grant.owner != self.context.id
            || grant.generation != self.context.generation
            || grant.expires <= self.now
            || grant.binding != GrantBinding::from_operation(operation)
        {
            return Err(AuthError::Authorization);
        }
        self.memory.grants.remove(&id);
        Ok(())
    }

    pub(crate) fn project(&self, operation: &mut Operation) {
        if operation.state != OperationState::AwaitingConfirmation || !operation.request.sensitive()
        {
            return;
        }
        let grant = self.memory.grants.values().find(|grant| {
            grant.owner == self.context.id
                && grant.generation == self.context.generation
                && grant.expires > self.now
                && grant.binding == GrantBinding::from_operation(operation)
        });
        operation.authorization.status = if grant.is_some() {
            lightning_client::model::AuthorizationState::Authorized
        } else {
            lightning_client::model::AuthorizationState::Required
        };
        operation.authorization.expires_at = grant.map(|grant| grant.expires);
    }
}

struct VerificationGuard {
    memory: Arc<Mutex<Memory>>,
    owner: Uuid,
}

impl Drop for VerificationGuard {
    fn drop(&mut self) {
        if let Ok(mut memory) = self.memory.lock() {
            if let Some(count) = memory.verifying.get_mut(&self.owner) {
                *count -= 1;
                if *count == 0 {
                    memory.verifying.remove(&self.owner);
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Context {
    pub nostr_pubkey: Option<String>,
    key: [u8; 32],
    id: Uuid,
    csrf: Zeroizing<String>,
    generation: i64,
    identity: ClientIdentity,
    created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub last_authenticated_at: Option<DateTime<Utc>>,
}

impl Context {
    pub(crate) fn snapshot_owner(&self) -> Uuid {
        self.id
    }
}

pub struct NewContext {
    pub context: Context,
    pub cookie: Zeroizing<String>,
}

#[derive(Clone, Serialize)]
pub struct SessionView {
    pub auth_method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey: Option<String>,
    pub authenticated: bool,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub last_authenticated_at: DateTime<Utc>,
    pub reauth: ReauthPolicy,
}

#[derive(Serialize)]
pub struct ActiveSession {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub last_authenticated_at: DateTime<Utc>,
    pub method: &'static str,
    pub nostr_pubkey: Option<String>,
    pub current: bool,
}

#[derive(Serialize)]
pub struct AuthenticationChallenge {
    pub challenge_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub options: RequestChallengeResponse,
}

#[derive(Serialize)]
pub struct RegistrationChallenge {
    pub challenge_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub options: CreationChallengeResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationFinish {
    pub challenge_id: Uuid,
    pub credential: PublicKeyCredential,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationFinish {
    pub challenge_id: Uuid,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Clone, Serialize)]
pub struct OperationAuthorization {
    pub authorization_id: Uuid,
    pub operation_id: Uuid,
    pub node_id: String,
    pub review_digest: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuthorizationStart {
    ChallengeRequired {
        challenge: AuthenticationChallenge,
    },
    Authorized {
        authorization: OperationAuthorization,
    },
}

struct Ceremony {
    owner: Uuid,
    generation: i64,
    expires: DateTime<Utc>,
    purpose: Purpose,
}
enum Purpose {
    Login(PasskeyAuthentication),
    Enrollment(PasskeyRegistration),
    Operation {
        state: PasskeyAuthentication,
        binding: GrantBinding,
    },
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
struct GrantBinding {
    operation_id: Uuid,
    node: NodeBinding,
    digest: String,
    policy_revision: String,
}
struct Grant {
    owner: Uuid,
    generation: i64,
    expires: DateTime<Utc>,
    binding: GrantBinding,
}

impl GrantBinding {
    fn from_operation(operation: &Operation) -> Self {
        Self {
            operation_id: operation.id,
            node: operation.review.node.clone(),
            digest: operation.review.digest.clone(),
            policy_revision: operation.review.policy_revision.clone(),
        }
    }
}

impl AuthManager {
    // Called only after SQLite's immediate transaction and the engine's local gates.
    // The callback must be synchronous; retaining this guard through commit linearizes logout.
    pub(crate) fn with_claim_session<T, E: From<AuthError>>(
        &self,
        context: &Context,
        generation: i64,
        now: DateTime<Utc>,
        action: impl FnOnce(&mut ClaimSession<'_>) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        let live = memory
            .contexts
            .get(&context.key)
            .ok_or(AuthError::Session)?;
        if live.id != context.id
            || live.generation != generation
            || live.generation != context.generation
            || live.last_authenticated_at.is_none()
            || live.expires_at <= now
            || live.idle_expires_at <= now
        {
            return Err(AuthError::Session.into());
        }
        let context = live.clone();
        action(&mut ClaimSession {
            memory: &mut memory,
            context,
            now,
        })
    }

    pub fn new(settings: &ApiSettings, journal: Journal) -> Result<Self, AuthError> {
        let webauthn = WebauthnBuilder::new(&settings.rp_id, &settings.public_origin)
            .map_err(|_| AuthError::Authentication)?
            .rp_name("Lightning node manager")
            .build()
            .map_err(|_| AuthError::Authentication)?;
        Ok(Self {
            public_origin: settings.public_origin.clone(),
            webauthn: Arc::new(webauthn),
            sessions: SessionStore::new(journal.path()),
            session_gate: Arc::new(Mutex::new(())),
            journal,
            limits: settings.limits.clone(),
            admission: AdmissionLimits::from(&settings.limits),
            policy: settings.reauth.clone(),
            memory: Arc::new(Mutex::new(Memory::default())),
            workers: Arc::new(Semaphore::new(VERIFICATION_WORKERS)),
        })
    }

    pub fn admit_start(
        &self,
        identity: ClientIdentity,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        memory.rates.retain(|_, queue| {
            while queue
                .front()
                .is_some_and(|time| *time + Duration::seconds(RATE_WINDOW_SECONDS) <= now)
            {
                queue.pop_front();
            }
            !queue.is_empty()
        });
        if !memory.rates.contains_key(&identity)
            && memory.rates.len() >= self.admission.rate_buckets
        {
            return Err(AuthError::Limited);
        }
        let queue = memory.rates.entry(identity).or_default();
        if queue.len() >= self.admission.starts_per_minute {
            return Err(AuthError::Limited);
        }
        queue.push_back(now);
        Ok(())
    }

    pub async fn anonymous(
        &self,
        identity: ClientIdentity,
        now: DateTime<Utc>,
    ) -> Result<NewContext, AuthError> {
        let generation = self.journal.authentication().await?.1;
        self.create_context(now, generation, false, identity)
    }

    fn create_context(
        &self,
        now: DateTime<Utc>,
        generation: i64,
        authenticated: bool,
        identity: ClientIdentity,
    ) -> Result<NewContext, AuthError> {
        let new = self.build_context(now, generation, authenticated, identity);
        let _gate = self.session_gate.lock().map_err(|_| AuthError::Storage)?;
        {
            let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
            if memory
                .contexts
                .values()
                .any(|context| context.generation > generation)
            {
                return Err(AuthError::Session);
            }
            memory
                .contexts
                .retain(|_, context| context.generation >= generation);
            memory.prune(now);
            if !authenticated {
                memory.make_anonymous_room(identity, &self.admission, now)?;
            }
        }
        let live_keys = self.live_session_keys(now)?;
        if authenticated {
            self.sessions
                .create(&new.context, self.limits.max_sessions, now, &live_keys)?;
        } else {
            self.sessions.maintain(generation, now, &live_keys)?;
        }
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        memory.contexts.insert(new.context.key, new.context.clone());
        Ok(new)
    }

    fn live_session_keys(&self, now: DateTime<Utc>) -> Result<Vec<[u8; 32]>, AuthError> {
        Ok(self
            .memory
            .lock()
            .map_err(|_| AuthError::Storage)?
            .live_session_keys(now))
    }

    fn build_context(
        &self,
        now: DateTime<Utc>,
        generation: i64,
        authenticated: bool,
        identity: ClientIdentity,
    ) -> NewContext {
        let cookie = random_token();
        let csrf = random_token();
        let key = token_hash(cookie.as_bytes());
        let expires_at = now
            + Duration::seconds(i64::from(if authenticated {
                self.limits.session_absolute_seconds
            } else {
                self.limits.preauth_seconds
            }));
        let context = Context {
            nostr_pubkey: None,
            key,
            id: Uuid::new_v4(),
            csrf,
            generation,
            identity,
            created_at: now,
            expires_at,
            idle_expires_at: if authenticated {
                (now + Duration::seconds(i64::from(self.limits.session_idle_seconds)))
                    .min(expires_at)
            } else {
                expires_at
            },
            last_authenticated_at: authenticated.then_some(now),
        };
        NewContext { context, cookie }
    }

    pub async fn context(
        &self,
        cookie: &str,
        authenticated: bool,
        now: DateTime<Utc>,
    ) -> Result<Context, AuthError> {
        if cookie.len() != 64 {
            return Err(AuthError::Session);
        }
        let key = token_hash(cookie.as_bytes());
        let generation = self.journal.authentication().await?.1;
        let _gate = self.session_gate.lock().map_err(|_| AuthError::Storage)?;
        self.sessions
            .maintain(generation, now, &self.live_session_keys(now)?)?;
        let cached = {
            let memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
            memory.contexts.get(&key).cloned()
        };
        let mut context = match cached {
            Some(context) => context,
            None if authenticated => self.sessions.load(&key)?.ok_or(AuthError::Session)?,
            None => return Err(AuthError::Session),
        };
        if context.last_authenticated_at.is_some() != authenticated
            || context.generation > generation
        {
            return Err(AuthError::Session);
        }
        if context.generation != generation
            || context.expires_at <= now
            || context.idle_expires_at <= now
        {
            if context.last_authenticated_at.is_some() {
                self.sessions.delete(&key)?;
            }
            let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
            memory.contexts.remove(&key);
            memory
                .contexts
                .retain(|_, context| context.generation >= generation);
            memory.prune(now);
            return Err(AuthError::Session);
        }
        if authenticated {
            context.idle_expires_at = (now
                + Duration::seconds(i64::from(self.limits.session_idle_seconds)))
            .min(context.expires_at);
            self.sessions.slide(&context)?;
        }
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        memory
            .contexts
            .retain(|_, context| context.generation >= generation);
        memory.prune(now);
        memory.contexts.insert(key, context.clone());
        Ok(context)
    }

    pub fn verify_csrf(context: &Context, header: &str) -> Result<(), AuthError> {
        if context.csrf.as_bytes().ct_eq(header.as_bytes()).into() {
            Ok(())
        } else {
            Err(AuthError::Csrf)
        }
    }

    pub fn csrf(context: &Context) -> &str {
        context.csrf.as_str()
    }

    pub fn session(&self, context: &Context) -> Result<SessionView, AuthError> {
        Ok(SessionView {
            auth_method: if context.nostr_pubkey.is_some() {
                "nostr"
            } else {
                "passkey"
            },
            nostr_pubkey: context.nostr_pubkey.clone(),
            authenticated: true,
            csrf_token: context.csrf.to_string(),
            expires_at: context.expires_at,
            idle_expires_at: context.idle_expires_at,
            last_authenticated_at: context.last_authenticated_at.ok_or(AuthError::Session)?,
            reauth: self.policy.clone(),
        })
    }

    pub fn active_sessions(
        &self,
        context: &Context,
        now: DateTime<Utc>,
    ) -> Result<Vec<ActiveSession>, AuthError> {
        let _gate = self.session_gate.lock().map_err(|_| AuthError::Storage)?;
        let cached = self.live_idle(context.generation)?;
        self.sessions
            .list(context.generation, context.id, now, &cached)
    }

    /// Idle deadlines of the live contexts, so listing never holds the memory lock across SQLite.
    fn live_idle(&self, generation: i64) -> Result<HashMap<Uuid, DateTime<Utc>>, AuthError> {
        Ok(self
            .memory
            .lock()
            .map_err(|_| AuthError::Storage)?
            .contexts
            .values()
            .filter(|context| context.generation == generation)
            .map(|context| (context.id, context.idle_expires_at))
            .collect())
    }

    pub fn revoke_session(
        &self,
        context: &Context,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let _gate = self.session_gate.lock().map_err(|_| AuthError::Storage)?;
        let cached = self.live_idle(context.generation)?;
        if !self
            .sessions
            .list(context.generation, context.id, now, &cached)?
            .iter()
            .any(|session| session.id == id)
        {
            return Err(AuthError::NotFound);
        }
        self.sessions.delete_by_id(id, context.generation)?;
        self.memory
            .lock()
            .map_err(|_| AuthError::Storage)?
            .remove_context(id);
        Ok(())
    }

    pub fn revoke(&self, context: &Context) -> Result<(), AuthError> {
        let mut attempt = crate::observability::AuthAttempt::new(
            if context.nostr_pubkey.is_some() {
                crate::observability::Method::Nostr
            } else {
                crate::observability::Method::Passkey
            },
            crate::observability::AuthAction::SignOut,
        );
        let result = self.revoke_context(context);
        if result.is_ok() {
            attempt.success();
        }
        result
    }

    fn revoke_context(&self, context: &Context) -> Result<(), AuthError> {
        let _gate = self.session_gate.lock().map_err(|_| AuthError::Storage)?;
        if context.last_authenticated_at.is_some() {
            self.sessions.delete(&context.key)?;
        }
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        memory.remove_context(context.id);
        Ok(())
    }

    pub async fn login_available(&self) -> Result<bool, AuthError> {
        Ok(self.passkey_login_available().await? || self.nostr_login_available().await?)
    }

    pub async fn passkey_login_available(&self) -> Result<bool, AuthError> {
        Ok(!self.passkeys().await?.is_empty())
    }

    pub async fn start_login(
        &self,
        context: &Context,
        now: DateTime<Utc>,
    ) -> Result<AuthenticationChallenge, AuthError> {
        if context.last_authenticated_at.is_some() {
            return Err(AuthError::Session);
        }
        let passkeys = self.passkeys().await?;
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|_| AuthError::Authentication)?;
        let (challenge_id, expires_at) =
            self.insert_ceremony(context, Purpose::Login(state), now)?;
        Ok(AuthenticationChallenge {
            challenge_id,
            expires_at,
            options,
        })
    }

    pub async fn finish_login(
        &self,
        context: &Context,
        finish: AuthenticationFinish,
        now: DateTime<Utc>,
    ) -> Result<NewContext, AuthError> {
        let mut attempt = crate::observability::AuthAttempt::new(
            crate::observability::Method::Passkey,
            crate::observability::AuthAction::SignIn,
        );
        let result = async {
            let (ceremony, _verification) =
                self.take_ceremony(context, finish.challenge_id, now)?;
            let Purpose::Login(state) = ceremony.purpose else {
                return Err(AuthError::Challenge);
            };
            self.verify_authentication(finish.credential, state, ceremony.generation)
                .await?;
            self.revoke_context(context)?;
            self.create_context(now, ceremony.generation, true, context.identity)
        }
        .await;
        if result.is_ok() {
            attempt.success();
        }
        result
    }

    pub async fn start_enrollment(
        &self,
        context: &Context,
        token: Zeroizing<String>,
        now: DateTime<Utc>,
    ) -> Result<RegistrationChallenge, AuthError> {
        let result = async {
            if context.last_authenticated_at.is_some() {
                return Err(AuthError::Session);
            }
            if token.len() != 64 {
                return Err(AuthError::Authentication);
            }
            let generation = self
                .journal
                .claim_enrollment(token, now)
                .await
                .map_err(|_| AuthError::Authentication)?;
            if generation != context.generation {
                return Err(AuthError::Session);
            }
            let passkeys = self.passkeys().await?;
            if passkeys.len() >= MAX_AUTHENTICATORS {
                return Err(AuthError::Limited);
            }
            let exclude = passkeys
                .iter()
                .map(|passkey| passkey.cred_id().clone())
                .collect();
            let operator = self.journal.authentication().await?.0;
            let (options, state) = self
                .webauthn
                .start_passkey_registration(operator, "operator", "Operator", Some(exclude))
                .map_err(|_| AuthError::Authentication)?;
            let (challenge_id, expires_at) =
                self.insert_ceremony(context, Purpose::Enrollment(state), now)?;
            Ok(RegistrationChallenge {
                challenge_id,
                expires_at,
                options,
            })
        }
        .await;
        if result.is_err() {
            crate::observability::Event::Auth {
                method: crate::observability::Method::Passkey,
                action: crate::observability::AuthAction::Enroll,
                outcome: "failure",
            }
            .emit();
        }
        result
    }

    pub async fn finish_enrollment(
        &self,
        context: &Context,
        finish: RegistrationFinish,
        now: DateTime<Utc>,
    ) -> Result<NewContext, AuthError> {
        let mut attempt = crate::observability::AuthAttempt::new(
            crate::observability::Method::Passkey,
            crate::observability::AuthAction::Enroll,
        );
        let result = async {
            let (ceremony, _verification) =
                self.take_ceremony(context, finish.challenge_id, now)?;
            let Purpose::Enrollment(state) = ceremony.purpose else {
                return Err(AuthError::Challenge);
            };
            let permit = self
                .workers
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| AuthError::Storage)?;
            let webauthn = self.webauthn.clone();
            let (passkey, _permit) = tokio::task::spawn_blocking(move || {
                let result = webauthn
                    .finish_passkey_registration(&finish.credential, &state)
                    .map_err(|_| AuthError::Authentication);
                result.map(|passkey| (passkey, permit))
            })
            .await
            .map_err(|_| AuthError::Authentication)??;
            self.register_passkey(passkey, ceremony.generation).await?;
            self.revoke_context(context)?;
            self.create_context(now, ceremony.generation, true, context.identity)
        }
        .await;
        if result.is_ok() {
            attempt.success();
        }
        result
    }

    pub async fn start_authorization(
        &self,
        context: &Context,
        operation: &Operation,
        now: DateTime<Utc>,
    ) -> Result<AuthorizationStart, AuthError> {
        if context.nostr_pubkey.is_some() {
            return Err(AuthError::Authentication);
        }
        if !operation.binding_is_valid() {
            return Err(AuthError::Authorization);
        }
        if !operation.request.sensitive() {
            return Err(AuthError::NotRequired);
        }
        if operation.state != OperationState::AwaitingConfirmation
            || operation.review.expires_at <= now
        {
            return Err(AuthError::Authorization);
        }
        let recent = self.policy.mode == ReauthMode::Recent
            && context.last_authenticated_at.is_some_and(|last| {
                self.policy
                    .recent_auth_seconds
                    .is_some_and(|seconds| now < last + Duration::seconds(i64::from(seconds)))
            });
        if recent {
            return Ok(AuthorizationStart::Authorized {
                authorization: self.issue_grant(context, operation, now)?,
            });
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&self.passkeys().await?)
            .map_err(|_| AuthError::Authentication)?;
        let (challenge_id, expires_at) = self.insert_ceremony(
            context,
            Purpose::Operation {
                state,
                binding: GrantBinding::from_operation(operation),
            },
            now,
        )?;
        Ok(AuthorizationStart::ChallengeRequired {
            challenge: AuthenticationChallenge {
                challenge_id,
                expires_at,
                options,
            },
        })
    }

    pub async fn finish_authorization(
        &self,
        context: &Context,
        operation: &Operation,
        finish: AuthenticationFinish,
        now: DateTime<Utc>,
    ) -> Result<OperationAuthorization, AuthError> {
        if context.nostr_pubkey.is_some() {
            return Err(AuthError::Authentication);
        }
        let (ceremony, _verification) = self.take_ceremony(context, finish.challenge_id, now)?;
        let Purpose::Operation { state, binding } = ceremony.purpose else {
            return Err(AuthError::Challenge);
        };
        if !operation.binding_is_valid()
            || binding != GrantBinding::from_operation(operation)
            || operation.state != OperationState::AwaitingConfirmation
            || operation.review.expires_at <= now
        {
            return Err(AuthError::Authorization);
        }
        self.verify_authentication(finish.credential, state, ceremony.generation)
            .await?;
        let refreshed = self.refresh_authentication(context, now)?;
        self.issue_grant(&refreshed, operation, now)
    }

    fn refresh_authentication(
        &self,
        context: &Context,
        now: DateTime<Utc>,
    ) -> Result<Context, AuthError> {
        let _gate = self.session_gate.lock().map_err(|_| AuthError::Storage)?;
        let mut refreshed = self
            .memory
            .lock()
            .map_err(|_| AuthError::Storage)?
            .contexts
            .get(&context.key)
            .cloned()
            .ok_or(AuthError::Session)?;
        refreshed.last_authenticated_at = Some(now);
        self.sessions.refresh(&refreshed)?;
        self.memory
            .lock()
            .map_err(|_| AuthError::Storage)?
            .contexts
            .insert(context.key, refreshed.clone());
        Ok(refreshed)
    }

    pub fn consume_grant(
        &self,
        context: &Context,
        operation: &Operation,
        authorization_id: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        if !operation.binding_is_valid() {
            return Err(AuthError::Authorization);
        }
        if !operation.request.sensitive() {
            return if authorization_id.is_none() {
                Ok(())
            } else {
                Err(AuthError::Authorization)
            };
        }
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        let grant = memory
            .grants
            .remove(&authorization_id.ok_or(AuthError::Authorization)?)
            .ok_or(AuthError::Authorization)?;
        if grant.owner != context.id
            || grant.generation != context.generation
            || grant.expires <= now
            || grant.binding != GrantBinding::from_operation(operation)
        {
            return Err(AuthError::Authorization);
        }
        if !memory.contexts.contains_key(&context.key) {
            return Err(AuthError::Session);
        }
        Ok(())
    }

    fn issue_grant(
        &self,
        context: &Context,
        operation: &Operation,
        now: DateTime<Utc>,
    ) -> Result<OperationAuthorization, AuthError> {
        let mut expires = (now + Duration::seconds(i64::from(self.limits.authorization_seconds)))
            .min(operation.review.expires_at)
            .min(context.expires_at)
            .min(context.idle_expires_at);
        if self.policy.mode == ReauthMode::Recent {
            expires = expires.min(
                context.last_authenticated_at.ok_or(AuthError::Session)?
                    + Duration::seconds(i64::from(
                        self.policy
                            .recent_auth_seconds
                            .ok_or(AuthError::Authorization)?,
                    )),
            );
        }
        if expires <= now {
            return Err(AuthError::Expired);
        }
        let id = Uuid::new_v4();
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        memory.prune(now);
        if !memory.contexts.contains_key(&context.key) {
            return Err(AuthError::Session);
        }
        if memory.grants.len() >= self.limits.max_challenges {
            return Err(AuthError::Limited);
        }
        memory.grants.insert(
            id,
            Grant {
                owner: context.id,
                generation: context.generation,
                expires,
                binding: GrantBinding::from_operation(operation),
            },
        );
        Ok(OperationAuthorization {
            authorization_id: id,
            operation_id: operation.id,
            node_id: operation.node_id.clone(),
            review_digest: operation.review.digest.clone(),
            expires_at: expires,
        })
    }

    fn insert_ceremony(
        &self,
        context: &Context,
        purpose: Purpose,
        now: DateTime<Utc>,
    ) -> Result<(Uuid, DateTime<Utc>), AuthError> {
        let expires = (now + Duration::seconds(i64::from(self.limits.challenge_seconds)))
            .min(context.expires_at)
            .min(context.idle_expires_at);
        let _gate = self.session_gate.lock().map_err(|_| AuthError::Storage)?;
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        memory.prune(now);
        if !memory.contexts.contains_key(&context.key) {
            return Err(AuthError::Session);
        }
        if memory.verifying.contains_key(&context.id) {
            return Err(AuthError::Limited);
        }
        memory.ceremonies.retain(|_, ceremony| {
            ceremony.owner != context.id
                || std::mem::discriminant(&ceremony.purpose) != std::mem::discriminant(&purpose)
        });
        memory.admit_challenge(context, self.limits.max_challenges)?;
        let id = Uuid::new_v4();
        memory.ceremonies.insert(
            id,
            Ceremony {
                owner: context.id,
                generation: context.generation,
                expires,
                purpose,
            },
        );
        Ok((id, expires))
    }

    fn take_ceremony(
        &self,
        context: &Context,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(Ceremony, VerificationGuard), AuthError> {
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        let ceremony = memory.ceremonies.remove(&id).ok_or(AuthError::Challenge)?;
        let current = memory
            .contexts
            .get(&context.key)
            .ok_or(AuthError::Session)?;
        if current.id != ceremony.owner
            || ceremony.owner != context.id
            || current.generation != ceremony.generation
        {
            return Err(AuthError::Challenge);
        }
        if ceremony.expires <= now || current.expires_at <= now || current.idle_expires_at <= now {
            return Err(AuthError::Expired);
        }
        *memory.verifying.entry(context.id).or_default() += 1;
        Ok((
            ceremony,
            VerificationGuard {
                memory: self.memory.clone(),
                owner: context.id,
            },
        ))
    }

    async fn passkeys(&self) -> Result<Vec<Passkey>, AuthError> {
        self.journal
            .run(|connection| {
                let mut statement = connection
                    .prepare("SELECT passkey FROM credentials ORDER BY credential_id LIMIT ?1")?;
                let records = statement.query_map(
                    [i64::try_from(MAX_AUTHENTICATORS + 1).map_err(|_| JournalError::Storage)?],
                    |row| row.get::<_, String>(0),
                )?;
                let mut passkeys = Vec::new();
                for record in records {
                    passkeys.push(serde_json::from_str(&record?)?);
                }
                if passkeys.len() > MAX_AUTHENTICATORS {
                    return Err(JournalError::Storage);
                }
                Ok(passkeys)
            })
            .await
            .map_err(Into::into)
    }

    async fn register_passkey(&self, passkey: Passkey, generation: i64) -> Result<(), AuthError> {
        self.journal
            .run(move |connection| {
                let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let current: i64 = tx.query_row(
                    "SELECT generation FROM auth_meta WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )?;
                if current != generation {
                    return Err(JournalError::Revoked);
                }
                let id = hex::encode(passkey.cred_id());
                let existing: Option<String> = tx
                    .query_row(
                        "SELECT credential_id FROM credentials WHERE credential_id=?1",
                        [&id],
                        |row| row.get(0),
                    )
                    .optional()?;
                if existing.is_some() {
                    return Ok(Err(AuthError::Authentication));
                }
                let count: i64 =
                    tx.query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))?;
                if count >= i64::try_from(MAX_AUTHENTICATORS).map_err(|_| JournalError::Storage)? {
                    return Ok(Err(AuthError::Limited));
                }
                tx.execute(
                    "INSERT INTO credentials(credential_id,passkey) VALUES(?1,?2)",
                    params![id, serde_json::to_string(&passkey)?],
                )?;
                tx.commit()?;
                Ok(Ok(()))
            })
            .await
            .map_err(AuthError::from)?
    }

    async fn update_passkey(
        &self,
        result: AuthenticationResult,
        generation: i64,
    ) -> Result<(), AuthError> {
        self.journal
            .run(move |connection| {
                let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let current: i64 = tx.query_row(
                    "SELECT generation FROM auth_meta WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )?;
                if current != generation {
                    return Err(JournalError::Revoked);
                }
                let id = hex::encode(result.cred_id());
                let stored: Option<String> = tx
                    .query_row(
                        "SELECT passkey FROM credentials WHERE credential_id=?1",
                        [&id],
                        |row| row.get(0),
                    )
                    .optional()?;
                let Some(stored) = stored else {
                    return Ok(Err(AuthError::Authentication));
                };
                let mut passkey: Passkey = serde_json::from_str(&stored)?;
                match passkey.update_credential(&result) {
                    Some(true) => {
                        tx.execute(
                            "UPDATE credentials SET passkey=?2 WHERE credential_id=?1",
                            params![id, serde_json::to_string(&passkey)?],
                        )?;
                    }
                    Some(false) => {}
                    None => return Ok(Err(AuthError::Authentication)),
                }
                tx.commit()?;
                Ok(Ok(()))
            })
            .await
            .map_err(AuthError::from)?
    }

    async fn verify_authentication(
        &self,
        credential: PublicKeyCredential,
        state: PasskeyAuthentication,
        generation: i64,
    ) -> Result<(), AuthError> {
        let permit = self
            .workers
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| AuthError::Storage)?;
        let webauthn = self.webauthn.clone();
        let (result, _permit) = tokio::task::spawn_blocking(move || {
            let result = webauthn
                .finish_passkey_authentication(&credential, &state)
                .map_err(|_| AuthError::Authentication);
            result.map(|result| (result, permit))
        })
        .await
        .map_err(|_| AuthError::Authentication)??;
        self.update_passkey(result, generation).await
    }
}

impl Memory {
    fn remove_context(&mut self, id: Uuid) {
        self.contexts.retain(|_, context| context.id != id);
        self.nostr_pending.retain(|_, (owner, _)| *owner != id);
        self.ceremonies.retain(|_, ceremony| ceremony.owner != id);
        self.grants.retain(|_, grant| grant.owner != id);
    }

    fn live_session_keys(&self, now: DateTime<Utc>) -> Vec<[u8; 32]> {
        self.contexts
            .values()
            .filter(|context| {
                context.last_authenticated_at.is_some()
                    && context.expires_at > now
                    && context.idle_expires_at > now
            })
            .map(|context| context.key)
            .collect()
    }

    fn admit_challenge(&self, context: &Context, maximum: usize) -> Result<(), AuthError> {
        let capacity = if context.last_authenticated_at.is_none() {
            maximum - maximum / AUTHENTICATED_CHALLENGE_RESERVE_DIVISOR
        } else {
            maximum
        };
        let allocated = self.ceremonies.len()
            + self.nostr_pending.len()
            + self.verifying.values().sum::<usize>();
        if allocated >= capacity {
            Err(AuthError::Limited)
        } else {
            Ok(())
        }
    }

    fn make_anonymous_room(
        &mut self,
        identity: ClientIdentity,
        limits: &AdmissionLimits,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        loop {
            let anonymous: Vec<_> = self
                .contexts
                .values()
                .filter(|context| context.last_authenticated_at.is_none())
                .collect();
            let identity_full = anonymous
                .iter()
                .filter(|context| context.identity == identity)
                .count()
                >= limits.anonymous_per_identity;
            if !identity_full && anonymous.len() < limits.anonymous {
                return Ok(());
            }
            let victim = anonymous
                .into_iter()
                .filter(|context| {
                    (!identity_full || context.identity == identity)
                        && !self
                            .ceremonies
                            .values()
                            .any(|ceremony| ceremony.owner == context.id)
                        && !self.verifying.contains_key(&context.id)
                        && !self
                            .nostr_pending
                            .values()
                            .any(|(owner, expires)| *owner == context.id && *expires > now)
                })
                .min_by_key(|context| (context.created_at, context.id))
                .map(|context| context.key);
            let Some(victim) = victim else {
                let horizon = self
                    .contexts
                    .values()
                    .filter(|context| {
                        context.last_authenticated_at.is_none()
                            && (!identity_full || context.identity == identity)
                    })
                    .map(|context| {
                        self.ceremonies
                            .values()
                            .filter(|ceremony| ceremony.owner == context.id)
                            .map(|ceremony| ceremony.expires)
                            .max()
                            .unwrap_or(context.expires_at)
                            .min(context.expires_at)
                    })
                    .min()
                    .unwrap_or(now + Duration::seconds(RATE_WINDOW_SECONDS));
                let seconds = ((horizon - now).num_milliseconds().max(1) + 999) / 1000;
                return Err(AuthError::AllocationLimited(
                    u64::try_from(seconds).unwrap_or(1),
                ));
            };
            self.contexts.remove(&victim);
        }
    }
    fn prune(&mut self, now: DateTime<Utc>) {
        self.contexts
            .retain(|_, context| context.expires_at > now && context.idle_expires_at > now);
        let owners: std::collections::HashSet<_> =
            self.contexts.values().map(|context| context.id).collect();
        self.nostr_pending
            .retain(|_, (owner, expires)| *expires > now && owners.contains(owner));
        self.ceremonies
            .retain(|_, ceremony| ceremony.expires > now && owners.contains(&ceremony.owner));
        self.grants
            .retain(|_, grant| grant.expires > now && owners.contains(&grant.owner));
    }
}

fn random_token() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(hex::encode(&bytes[..]))
}
fn token_hash(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightning_client::settings::Limits;
    use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};

    fn identity() -> ClientIdentity {
        ClientIdentity::Socket("192.0.2.1".parse().unwrap())
    }

    fn fixed_now() -> DateTime<Utc> {
        "2026-10-21T12:00:00Z".parse().unwrap()
    }

    #[tokio::test]
    async fn active_sessions_use_live_idle_expiry_and_exclude_expired_and_other_generations() {
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let caller = manager.create_context(now, 0, true, identity()).unwrap();
        let idle = manager.create_context(now, 0, true, identity()).unwrap();
        let absolute = manager.create_context(now, 0, true, identity()).unwrap();
        let previous = manager.create_context(now, 0, true, identity()).unwrap();
        let absolute_id = absolute.context.id.to_string();
        let previous_id = previous.context.id.to_string();
        manager
            .journal
            .run(move |connection| {
                connection.execute(
                    "UPDATE sessions SET expires_at=?1 WHERE context_id=?2",
                    params![now.timestamp(), absolute_id],
                )?;
                connection.execute(
                    "UPDATE sessions SET generation=1 WHERE context_id=?1",
                    [previous_id],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        // Keep a session alive in memory beyond the coalesced disk idle deadline.
        let just_before_idle = idle.context.idle_expires_at - Duration::seconds(1);
        let mut cached = caller.context.clone();
        cached.idle_expires_at = idle.context.idle_expires_at + Duration::seconds(10);
        cached.nostr_pubkey = Some("ab".repeat(32));
        manager.sessions.refresh(&cached).unwrap();
        manager
            .memory
            .lock()
            .unwrap()
            .contexts
            .insert(cached.key, cached.clone());
        let rows = manager
            .active_sessions(&cached, just_before_idle + Duration::seconds(1))
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, caller.context.id);
        assert_eq!(rows[0].idle_expires_at, cached.idle_expires_at);
        assert_eq!(rows[0].method, "nostr");
        assert_eq!(rows[0].nostr_pubkey, cached.nostr_pubkey);
        assert!(matches!(
            manager.revoke_session(&cached, idle.context.id, idle.context.idle_expires_at),
            Err(AuthError::NotFound)
        ));
        assert!(matches!(
            manager.revoke_session(&cached, absolute.context.id, now),
            Err(AuthError::NotFound)
        ));
        assert!(matches!(
            manager.revoke_session(&cached, previous.context.id, now),
            Err(AuthError::NotFound)
        ));
        manager
            .revoke_session(&cached, caller.context.id, idle.context.idle_expires_at)
            .unwrap();
        assert!(!manager
            .memory
            .lock()
            .unwrap()
            .contexts
            .contains_key(&cached.key));
        let restarted = AuthManager::new(&settings, manager.journal.clone()).unwrap();
        assert!(restarted
            .active_sessions(&cached, idle.context.idle_expires_at)
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn active_sessions_list_and_revoke_uncached_persisted_sessions() {
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let caller = manager.create_context(now, 0, true, identity()).unwrap();
        let other = manager
            .create_context(now + Duration::seconds(1), 0, true, identity())
            .unwrap();
        let restarted = AuthManager::new(&settings, manager.journal.clone()).unwrap();
        assert!(restarted.memory.lock().unwrap().contexts.is_empty());
        let rows = restarted
            .active_sessions(&caller.context, now + Duration::seconds(2))
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, other.context.id);
        restarted
            .revoke_session(
                &caller.context,
                other.context.id,
                now + Duration::seconds(2),
            )
            .unwrap();
        assert!(restarted
            .context(&other.cookie, true, now + Duration::seconds(2))
            .await
            .is_err());
        assert!(restarted
            .context(&caller.cookie, true, now + Duration::seconds(2))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn signed_in_session_and_csrf_survive_restart() {
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        enroll(&manager, &settings, &mut authenticator, now).await;
        let anonymous = manager.anonymous(identity(), now).await.unwrap();
        let challenge = manager.start_login(&anonymous.context, now).await.unwrap();
        let credential = authenticator
            .do_authentication(settings.public_origin.clone(), challenge.options)
            .unwrap();
        let signed_in = manager
            .finish_login(
                &anonymous.context,
                AuthenticationFinish {
                    challenge_id: challenge.challenge_id,
                    credential,
                },
                now,
            )
            .await
            .unwrap();
        let csrf = AuthManager::csrf(&signed_in.context).to_owned();
        drop(manager);
        let journal = Journal::open(settings.database.clone()).await.unwrap();
        let restarted = AuthManager::new(&settings, journal).unwrap();
        let restored = restarted
            .context(&signed_in.cookie, true, now + Duration::seconds(1))
            .await
            .unwrap();
        assert_eq!(restored.id, signed_in.context.id);
        assert_eq!(restored.identity, signed_in.context.identity);
        assert_eq!(restored.last_authenticated_at, Some(now));
        assert_eq!(AuthManager::csrf(&restored), csrf);
        AuthManager::verify_csrf(&restored, &csrf).unwrap();
        assert!(matches!(
            restarted.context(&signed_in.cookie, false, now).await,
            Err(AuthError::Session)
        ));
        assert!(restarted
            .context(&signed_in.cookie, true, now)
            .await
            .is_ok());
        assert!(restarted
            .sessions
            .load(&signed_in.context.key)
            .unwrap()
            .is_some());
        assert!(matches!(
            restarted.context(&anonymous.cookie, false, now).await,
            Err(AuthError::Session)
        ));
    }

    #[tokio::test]
    async fn revoked_and_expired_sessions_stay_rejected_after_restart() {
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let revoked = manager.create_context(now, 0, true, identity()).unwrap();
        let idle = manager.create_context(now, 0, true, identity()).unwrap();
        let absolute = manager.create_context(now, 0, true, identity()).unwrap();
        manager.revoke(&revoked.context).unwrap();
        drop(manager);
        let journal = Journal::open(settings.database.clone()).await.unwrap();
        let restarted = AuthManager::new(&settings, journal).unwrap();
        for (session, at) in [
            (&revoked, now),
            (&idle, idle.context.idle_expires_at),
            (&absolute, absolute.context.expires_at),
        ] {
            assert!(matches!(
                restarted.context(&session.cookie, true, at).await,
                Err(AuthError::Session)
            ));
            assert!(restarted
                .sessions
                .load(&session.context.key)
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    async fn older_generation_sessions_are_deleted_after_restart() {
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let session = manager.create_context(now, 0, true, identity()).unwrap();
        // Simulate a generation change made by an already-running journal owner.
        manager
            .journal
            .run(|connection| {
                connection.execute(
                    "UPDATE auth_meta SET generation=generation+1 WHERE singleton=1",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        drop(manager);
        let journal = Journal::open(settings.database.clone()).await.unwrap();
        let restarted = AuthManager::new(&settings, journal).unwrap();
        assert!(matches!(
            restarted.context(&session.cookie, true, now).await,
            Err(AuthError::Session)
        ));
        assert!(restarted
            .sessions
            .load(&session.context.key)
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn authenticated_session_cap_counts_persisted_sessions_after_restart() {
        let (_directory, manager, mut settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let session = manager.create_context(now, 0, true, identity()).unwrap();
        drop(manager);
        settings.limits.max_sessions = 1;
        let journal = Journal::open(settings.database.clone()).await.unwrap();
        let restarted = AuthManager::new(&settings, journal).unwrap();
        assert!(restarted.memory.lock().unwrap().contexts.is_empty());
        assert!(matches!(
            restarted.create_context(now, 0, true, identity()),
            Err(AuthError::Limited)
        ));
        restarted.revoke(&session.context).unwrap();
        restarted.create_context(now, 0, true, identity()).unwrap();
    }

    #[tokio::test]
    async fn sliding_idle_expiry_is_persisted_only_after_thirty_seconds() {
        let (_directory, manager, _settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let session = manager.create_context(now, 0, true, identity()).unwrap();
        manager.journal.run(|connection| {
            connection.execute_batch("CREATE TRIGGER reject_session_update BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, 'unexpected session write'); END;")?;
            Ok(())
        }).await.unwrap();
        for seconds in [1, 15, 29] {
            let live = manager
                .context(&session.cookie, true, now + Duration::seconds(seconds))
                .await
                .unwrap();
            assert_eq!(
                live.idle_expires_at,
                session.context.idle_expires_at + Duration::seconds(seconds)
            );
            assert_eq!(
                manager
                    .sessions
                    .load(&session.context.key)
                    .unwrap()
                    .unwrap()
                    .idle_expires_at,
                session.context.idle_expires_at
            );
        }
        assert!(matches!(
            manager
                .context(&session.cookie, true, now + Duration::seconds(30))
                .await,
            Err(AuthError::Storage)
        ));
        manager
            .journal
            .run(|connection| {
                connection.execute_batch("DROP TRIGGER reject_session_update;")?;
                Ok(())
            })
            .await
            .unwrap();
        manager
            .context(&session.cookie, true, now + Duration::seconds(30))
            .await
            .unwrap();
        assert_eq!(
            manager
                .sessions
                .load(&session.context.key)
                .unwrap()
                .unwrap()
                .idle_expires_at,
            session.context.idle_expires_at + Duration::seconds(30)
        );
    }

    #[tokio::test]
    async fn coalesced_idle_writes_do_not_expire_a_live_cached_session() {
        let (_directory, mut manager, _settings) = manager(ReauthMode::EveryOperation).await;
        manager.limits.max_sessions = 1;
        let now = fixed_now();
        let session = manager.create_context(now, 0, true, identity()).unwrap();
        manager
            .context(&session.cookie, true, now + Duration::seconds(29))
            .await
            .unwrap();
        let later = session.context.idle_expires_at + Duration::seconds(1);
        // Pruning another request must not discard the unflushed, live idle extension.
        manager.anonymous(identity(), later).await.unwrap();
        assert!(matches!(
            manager.create_context(later, 0, true, identity()),
            Err(AuthError::Limited)
        ));
        assert!(manager.context(&session.cookie, true, later).await.is_ok());
    }

    #[tokio::test]
    async fn failed_session_writes_never_publish_authentication_or_revocation() {
        let (_directory, manager, _settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let session = manager.create_context(now, 0, true, identity()).unwrap();
        manager.journal.run(|connection| {
            connection.execute_batch("CREATE TRIGGER reject_session_update BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, 'unexpected session write'); END;
                CREATE TRIGGER reject_session_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'unexpected session delete'); END;
                CREATE TRIGGER reject_session_insert BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'unexpected session insert'); END;")?;
            Ok(())
        }).await.unwrap();
        assert!(matches!(
            manager.refresh_authentication(&session.context, now + Duration::seconds(1)),
            Err(AuthError::Storage)
        ));
        assert_eq!(
            manager.memory.lock().unwrap().contexts[&session.context.key].last_authenticated_at,
            Some(now)
        );
        assert!(matches!(
            manager.revoke(&session.context),
            Err(AuthError::Storage)
        ));
        assert!(manager.context(&session.cookie, true, now).await.is_ok());
        assert!(matches!(
            manager.create_context(now, 0, true, identity()),
            Err(AuthError::Storage)
        ));
        assert_eq!(manager.memory.lock().unwrap().contexts.len(), 1);
    }

    #[tokio::test]
    async fn malformed_stored_session_is_rejected_without_panicking() {
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let session = manager
            .create_context(
                now,
                0,
                true,
                ClientIdentity::Forwarded("2001:db8::1".parse().unwrap()),
            )
            .unwrap();
        let restarted = AuthManager::new(&settings, manager.journal.clone()).unwrap();
        assert_eq!(
            restarted
                .context(&session.cookie, true, now)
                .await
                .unwrap()
                .identity,
            session.context.identity
        );
        let key = session.context.key;
        manager
            .journal
            .run(move |connection| {
                connection.execute(
                    "UPDATE sessions SET identity_ip='invalid' WHERE key=?1",
                    [key.as_slice()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let restarted = AuthManager::new(&settings, manager.journal.clone()).unwrap();
        assert!(matches!(
            restarted.context(&session.cookie, true, now).await,
            Err(AuthError::Session)
        ));
    }

    async fn verified_assertion(
        manager: &AuthManager,
        settings: &ApiSettings,
        authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
        now: DateTime<Utc>,
    ) -> (AuthenticationResult, i64) {
        let anonymous = manager.anonymous(identity(), now).await.unwrap();
        let challenge = manager.start_login(&anonymous.context, now).await.unwrap();
        let credential = authenticator
            .do_authentication(settings.public_origin.clone(), challenge.options)
            .unwrap();
        let (ceremony, _guard) = manager
            .take_ceremony(&anonymous.context, challenge.challenge_id, now)
            .unwrap();
        let Purpose::Login(state) = ceremony.purpose else {
            panic!("login state required")
        };
        let result = manager
            .webauthn
            .finish_passkey_authentication(&credential, &state)
            .unwrap();
        manager.revoke(&anonymous.context).unwrap();
        (result, ceremony.generation)
    }

    #[tokio::test]
    async fn admitted_finish_survives_start_exhaustion_and_waits_for_verification_capacity() {
        use std::{future::Future, task::Poll};
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        enroll(&manager, &settings, &mut authenticator, now).await;
        let anonymous = manager.anonymous(identity(), now).await.unwrap();
        manager.admit_start(identity(), now).unwrap();
        let old = manager.start_login(&anonymous.context, now).await.unwrap();
        let challenge = manager.start_login(&anonymous.context, now).await.unwrap();
        assert!(!manager
            .memory
            .lock()
            .unwrap()
            .ceremonies
            .contains_key(&old.challenge_id));
        assert_eq!(manager.memory.lock().unwrap().ceremonies.len(), 1);
        for _ in 1..manager.admission.starts_per_minute {
            manager.admit_start(identity(), now).unwrap();
        }
        assert!(matches!(
            manager.admit_start(identity(), now),
            Err(AuthError::Limited)
        ));
        let credential = authenticator
            .do_authentication(settings.public_origin.clone(), challenge.options)
            .unwrap();
        let workers = manager
            .workers
            .clone()
            .acquire_many_owned(VERIFICATION_WORKERS as u32)
            .await
            .unwrap();
        let mut finish = std::pin::pin!(manager.finish_login(
            &anonymous.context,
            AuthenticationFinish {
                challenge_id: challenge.challenge_id,
                credential
            },
            now
        ));
        std::future::poll_fn(|cx| {
            assert!(matches!(finish.as_mut().poll(cx), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        assert!(manager
            .memory
            .lock()
            .unwrap()
            .verifying
            .contains_key(&anonymous.context.id));
        // Even allocation pressure while verification waits cannot evict admitted work.
        for _ in 0..manager.admission.anonymous * 2 {
            manager.anonymous(identity(), now).await.unwrap();
        }
        assert!(manager.context(&anonymous.cookie, false, now).await.is_ok());
        drop(workers);
        let session = finish.await.unwrap();
        assert!(manager.context(&session.cookie, true, now).await.is_ok());
        assert!(manager.memory.lock().unwrap().verifying.is_empty());
        assert!(manager
            .admit_start(identity(), now + Duration::seconds(60))
            .is_ok());
    }

    #[tokio::test]
    async fn anonymous_eviction_is_oldest_abandoned_first_and_never_live_work() {
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let session = enroll(&manager, &settings, &mut authenticator, now).await;
        let pinned = manager.anonymous(identity(), now).await.unwrap();
        let challenge = manager.start_login(&pinned.context, now).await.unwrap();
        let mut abandoned = Vec::new();
        for index in 1..manager.admission.anonymous {
            let source =
                ClientIdentity::Socket(IpAddr::from([198, 51, 100, u8::try_from(index).unwrap()]));
            abandoned.push(
                manager
                    .anonymous(
                        source,
                        now + Duration::milliseconds(i64::try_from(index).unwrap()),
                    )
                    .await
                    .unwrap(),
            );
        }
        let newest = manager
            .anonymous(
                ClientIdentity::Socket("203.0.113.1".parse().unwrap()),
                now + Duration::seconds(1),
            )
            .await
            .unwrap();
        assert!(manager
            .context(&abandoned[0].cookie, false, now + Duration::seconds(1))
            .await
            .is_err());
        assert!(manager
            .context(&abandoned[1].cookie, false, now + Duration::seconds(1))
            .await
            .is_ok());
        assert!(manager
            .context(&pinned.cookie, false, now + Duration::seconds(1))
            .await
            .is_ok());
        assert!(manager
            .context(&session.cookie, true, now + Duration::seconds(1))
            .await
            .is_ok());
        assert!(manager
            .context(&newest.cookie, false, now + Duration::seconds(1))
            .await
            .is_ok());
        assert!(manager
            .memory
            .lock()
            .unwrap()
            .ceremonies
            .contains_key(&challenge.challenge_id));
        // Fill one identity's share with live ceremonies; unrelated sources still allocate.
        for _ in 1..manager.admission.anonymous_per_identity {
            let context = manager
                .anonymous(identity(), now + Duration::seconds(2))
                .await
                .unwrap();
            manager
                .start_login(&context.context, now + Duration::seconds(2))
                .await
                .unwrap();
        }
        assert!(matches!(
            manager
                .anonymous(identity(), now + Duration::seconds(2))
                .await,
            Err(AuthError::AllocationLimited(58))
        ));
        assert!(manager
            .anonymous(
                ClientIdentity::Socket("203.0.113.2".parse().unwrap()),
                now + Duration::seconds(2)
            )
            .await
            .is_ok());
        assert!(manager
            .anonymous(identity(), now + Duration::seconds(63))
            .await
            .is_ok());
        {
            let memory = manager.memory.lock().unwrap();
            assert!(memory.ceremonies.is_empty());
            assert!(memory.contexts.contains_key(&session.context.key));
            assert!(
                memory
                    .contexts
                    .values()
                    .filter(|context| context.last_authenticated_at.is_none())
                    .count()
                    <= manager.admission.anonymous
            );
        }
        manager
            .anonymous(identity(), now + Duration::seconds(364))
            .await
            .unwrap();
        let memory = manager.memory.lock().unwrap();
        assert_eq!(
            memory
                .contexts
                .values()
                .filter(|context| context.last_authenticated_at.is_none())
                .count(),
            1
        );
        assert!(memory.contexts.contains_key(&session.context.key));
    }

    #[tokio::test]
    async fn overlapping_assertions_merge_against_current_storage_and_recovery_rejects_stale_results(
    ) {
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        enroll(&manager, &settings, &mut authenticator, now).await;
        let (low, generation) =
            verified_assertion(&manager, &settings, &mut authenticator, now).await;
        let (high, _) = verified_assertion(&manager, &settings, &mut authenticator, now).await;
        assert!(high.counter() > low.counter());
        let unchanged = low.clone();
        let mut expected = manager.passkeys().await.unwrap().remove(0);
        expected.update_credential(&high).unwrap();
        expected.update_credential(&low).unwrap();
        let (persisted, wait) = tokio::sync::oneshot::channel();
        let high_manager = manager.clone();
        let high_task = tokio::spawn(async move {
            high_manager.update_passkey(high, generation).await.unwrap();
            persisted.send(()).unwrap();
        });
        let low_manager = manager.clone();
        let low_task = tokio::spawn(async move {
            wait.await.unwrap();
            low_manager.update_passkey(low, generation).await.unwrap();
        });
        high_task.await.unwrap();
        low_task.await.unwrap();
        let current = manager.passkeys().await.unwrap().remove(0);
        assert_eq!(
            serde_json::to_value(&current).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        manager.journal.run(|connection| {
            connection.execute_batch("CREATE TRIGGER reject_credential_update BEFORE UPDATE ON credentials BEGIN SELECT RAISE(ABORT, 'unexpected credential write'); END;")?;
            Ok(())
        }).await.unwrap();
        manager.update_passkey(unchanged, generation).await.unwrap();
        manager
            .journal
            .run(|connection| {
                connection.execute_batch("DROP TRIGGER reject_credential_update;")?;
                Ok(())
            })
            .await
            .unwrap();
        // Exercise the library's independent backup flags, without pretending this is a signed software-authenticator claim.
        let (result, _) = verified_assertion(&manager, &settings, &mut authenticator, now).await;
        let mut flags = serde_json::to_value(&result).unwrap();
        flags["backup_eligible"] = serde_json::json!(true);
        flags["backup_state"] = serde_json::json!(true);
        let eligible: AuthenticationResult = serde_json::from_value(flags).unwrap();
        expected.update_credential(&eligible).unwrap();
        expected.update_credential(&result).unwrap();
        manager.update_passkey(eligible, generation).await.unwrap();
        manager
            .update_passkey(result.clone(), generation)
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(&manager.passkeys().await.unwrap()[0]).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        let (recovered, wait) = tokio::sync::oneshot::channel();
        let absent = result.clone();
        let stale_manager = manager.clone();
        let stale = tokio::spawn(async move {
            wait.await.unwrap();
            stale_manager.update_passkey(result, generation).await
        });
        manager
            .journal
            .issue_enrollment(now, std::time::Duration::from_secs(60), true)
            .await
            .unwrap();
        let mut replacement = WebauthnAuthenticator::new(SoftPasskey::new(true));
        enroll(&manager, &settings, &mut replacement, now).await;
        let before = serde_json::to_value(manager.passkeys().await.unwrap()).unwrap();
        recovered.send(()).unwrap();
        assert!(matches!(stale.await.unwrap(), Err(AuthError::Session)));
        let current_generation = manager.journal.authentication().await.unwrap().1;
        assert!(matches!(
            manager.update_passkey(absent, current_generation).await,
            Err(AuthError::Authentication)
        ));
        assert_eq!(
            before,
            serde_json::to_value(manager.passkeys().await.unwrap()).unwrap()
        );
    }

    #[tokio::test]
    async fn registration_is_insert_only_and_capacity_is_checked_in_transaction() {
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = fixed_now();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let session = enroll(&manager, &settings, &mut authenticator, now).await;
        let existing = manager.passkeys().await.unwrap().remove(0);
        assert!(matches!(
            manager
                .register_passkey(existing.clone(), session.context.generation)
                .await,
            Err(AuthError::Authentication)
        ));
        assert_eq!(manager.passkeys().await.unwrap().len(), 1);
        assert_eq!(
            serde_json::to_value(&manager.passkeys().await.unwrap()[0]).unwrap(),
            serde_json::to_value(&existing).unwrap()
        );
        for _ in 1..MAX_AUTHENTICATORS {
            let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
            enroll(&manager, &settings, &mut authenticator, now).await;
        }
        // Verify an independently registered credential, then exercise the persistence cap directly.
        let operator = manager.journal.authentication().await.unwrap().0;
        let (options, state) = manager
            .webauthn
            .start_passkey_registration(operator, "operator", "Operator", None)
            .unwrap();
        let mut extra = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let response = extra
            .do_registration(settings.public_origin.clone(), options)
            .unwrap();
        let passkey = manager
            .webauthn
            .finish_passkey_registration(&response, &state)
            .unwrap();
        let before = serde_json::to_value(manager.passkeys().await.unwrap()).unwrap();
        assert!(matches!(
            manager
                .register_passkey(passkey, session.context.generation)
                .await,
            Err(AuthError::Limited)
        ));
        assert_eq!(
            before,
            serde_json::to_value(manager.passkeys().await.unwrap()).unwrap()
        );
        assert!(matches!(
            manager
                .register_passkey(existing, session.context.generation)
                .await,
            Err(AuthError::Authentication)
        ));
    }

    async fn manager(mode: ReauthMode) -> (tempfile::TempDir, AuthManager, ApiSettings) {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let settings = ApiSettings {
            bind: "127.0.0.1:8080".parse().unwrap(),
            public_origin: "https://manager.example.invalid".parse().unwrap(),
            rp_id: "manager.example.invalid".into(),
            database: directory.path().join("auth.sqlite"),
            invoice_key_file: directory.path().join("unused.key"),
            allow_insecure_loopback: false,
            client_identity: Default::default(),
            reauth: ReauthPolicy {
                mode,
                recent_auth_seconds: if mode == ReauthMode::Recent {
                    Some(120)
                } else {
                    None
                },
            },
            limits: Limits::default(),
        };
        let journal = Journal::open(settings.database.clone()).await.unwrap();
        let manager = AuthManager::new(&settings, journal).unwrap();
        (directory, manager, settings)
    }

    async fn enroll(
        manager: &AuthManager,
        settings: &ApiSettings,
        authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
        now: DateTime<Utc>,
    ) -> NewContext {
        let anonymous = manager.anonymous(identity(), now).await.unwrap();
        let token = manager
            .journal
            .issue_enrollment(now, std::time::Duration::from_secs(60), false)
            .await
            .unwrap();
        let challenge = manager
            .start_enrollment(&anonymous.context, token, now)
            .await
            .unwrap();
        let json = serde_json::to_value(&challenge).unwrap();
        assert_eq!(
            json["options"]["publicKey"]["authenticatorSelection"]["userVerification"],
            "required"
        );
        assert!(json["options"]["publicKey"]["challenge"].is_string());
        let credential = authenticator
            .do_registration(settings.public_origin.clone(), challenge.options)
            .unwrap();
        manager
            .finish_enrollment(
                &anonymous.context,
                RegistrationFinish {
                    challenge_id: challenge.challenge_id,
                    credential,
                },
                now,
            )
            .await
            .unwrap()
    }

    fn operation() -> Operation {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/api-examples.json")).unwrap();
        let mut operation: Operation =
            serde_json::from_value(fixtures["fixtures"]["operation_review"]["value"].clone())
                .unwrap();
        operation.id = Uuid::new_v4();
        operation.review.operation_id = operation.id;
        operation.review.expires_at = Utc::now() + Duration::minutes(5);
        operation
    }

    #[tokio::test]
    async fn real_passkey_ceremonies_rotate_session_and_consume_login_challenges() {
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = Utc::now();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let enrolled = enroll(&manager, &settings, &mut authenticator, now).await;
        assert!(manager.login_available().await.unwrap());
        assert!(manager.context(&enrolled.cookie, true, now).await.is_ok());
        assert!(AuthManager::verify_csrf(&enrolled.context, "wrong").is_err());
        assert!(
            AuthManager::verify_csrf(&enrolled.context, AuthManager::csrf(&enrolled.context))
                .is_ok()
        );
        let anonymous = manager.anonymous(identity(), now).await.unwrap();
        let challenge = manager.start_login(&anonymous.context, now).await.unwrap();
        let credential = authenticator
            .do_authentication(settings.public_origin.clone(), challenge.options)
            .unwrap();
        let mut browser_json = serde_json::to_value(&credential).unwrap();
        let object = browser_json.as_object_mut().unwrap();
        if let Some(extensions) = object.remove("extensions") {
            object.insert("clientExtensionResults".into(), extensions);
        }
        let credential: PublicKeyCredential = serde_json::from_value(browser_json).unwrap();
        let replay = credential.clone();
        let logged = manager
            .finish_login(
                &anonymous.context,
                AuthenticationFinish {
                    challenge_id: challenge.challenge_id,
                    credential,
                },
                now,
            )
            .await
            .unwrap();
        assert_ne!(logged.cookie.as_str(), anonymous.cookie.as_str());
        assert!(manager
            .context(&anonymous.cookie, false, now)
            .await
            .is_err());
        assert!(matches!(
            manager
                .finish_login(
                    &anonymous.context,
                    AuthenticationFinish {
                        challenge_id: challenge.challenge_id,
                        credential: replay
                    },
                    now
                )
                .await,
            Err(AuthError::Challenge)
        ));
        manager.revoke(&logged.context).unwrap();
        assert!(manager.context(&logged.cookie, true, now).await.is_err());
    }

    #[tokio::test]
    async fn strict_authorization_requires_fresh_bound_user_verified_passkey_and_one_use() {
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = Utc::now();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let session = enroll(&manager, &settings, &mut authenticator, now).await;
        let operation = operation();
        let mut inconsistent = operation.clone();
        inconsistent.review.sensitive = false;
        assert!(matches!(
            manager
                .start_authorization(&session.context, &inconsistent, now)
                .await,
            Err(AuthError::Authorization)
        ));
        assert!(manager
            .consume_grant(&session.context, &inconsistent, None, now)
            .is_err());
        assert!(manager
            .consume_grant(&session.context, &operation, None, now)
            .is_err());
        let AuthorizationStart::ChallengeRequired { challenge } = manager
            .start_authorization(&session.context, &operation, now)
            .await
            .unwrap()
        else {
            panic!("fresh login bypassed strict mode")
        };
        let credential = authenticator
            .do_authentication(settings.public_origin.clone(), challenge.options)
            .unwrap();
        let grant = manager
            .finish_authorization(
                &session.context,
                &operation,
                AuthenticationFinish {
                    challenge_id: challenge.challenge_id,
                    credential,
                },
                now,
            )
            .await
            .unwrap();
        assert_eq!(grant.operation_id, operation.id);
        assert_eq!(grant.review_digest, operation.review.digest);
        manager
            .consume_grant(
                &session.context,
                &operation,
                Some(grant.authorization_id),
                now,
            )
            .unwrap();
        assert!(manager
            .consume_grant(
                &session.context,
                &operation,
                Some(grant.authorization_id),
                now
            )
            .is_err());
        let AuthorizationStart::ChallengeRequired { challenge } = manager
            .start_authorization(&session.context, &operation, now)
            .await
            .unwrap()
        else {
            panic!("prior verification bypassed strict mode")
        };
        let credential = authenticator
            .do_authentication(settings.public_origin.clone(), challenge.options)
            .unwrap();
        let grant = manager
            .finish_authorization(
                &session.context,
                &operation,
                AuthenticationFinish {
                    challenge_id: challenge.challenge_id,
                    credential,
                },
                now,
            )
            .await
            .unwrap();
        let mut changed = operation.clone();
        changed.review.node.identity_revision.push_str("changed");
        assert!(manager
            .consume_grant(
                &session.context,
                &changed,
                Some(grant.authorization_id),
                now
            )
            .is_err());
        assert!(manager
            .consume_grant(
                &session.context,
                &operation,
                Some(grant.authorization_id),
                now
            )
            .is_err());
    }

    #[tokio::test]
    async fn recent_policy_has_server_duration_and_recovery_invalidates_live_sessions() {
        let (_directory, manager, settings) = manager(ReauthMode::Recent).await;
        let now = Utc::now();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let session = enroll(&manager, &settings, &mut authenticator, now).await;
        let operation = operation();
        let AuthorizationStart::Authorized { authorization } = manager
            .start_authorization(&session.context, &operation, now)
            .await
            .unwrap()
        else {
            panic!("recent policy not applied")
        };
        let stranger = manager.anonymous(identity(), now).await.unwrap();
        assert!(manager
            .consume_grant(
                &stranger.context,
                &operation,
                Some(authorization.authorization_id),
                now
            )
            .is_err());
        let AuthorizationStart::ChallengeRequired { challenge: _ } = manager
            .start_authorization(&session.context, &operation, now + Duration::seconds(120))
            .await
            .unwrap()
        else {
            panic!("recent window extended by client")
        };
        manager
            .journal
            .issue_enrollment(now, std::time::Duration::from_secs(60), true)
            .await
            .unwrap();
        assert!(manager.context(&session.cookie, true, now).await.is_err());
        assert!(!manager.login_available().await.unwrap());
        let fresh = manager.anonymous(identity(), now).await.unwrap();
        assert!(manager
            .memory
            .lock()
            .unwrap()
            .contexts
            .values()
            .all(|context| context.generation == fresh.context.generation));
    }

    #[tokio::test]
    async fn failed_or_expired_verification_cannot_replay_and_authenticators_without_uv_fail() {
        let (_directory, manager, settings) = manager(ReauthMode::EveryOperation).await;
        let now = Utc::now();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(false));
        let anonymous = manager.anonymous(identity(), now).await.unwrap();
        let token = manager
            .journal
            .issue_enrollment(now, std::time::Duration::from_secs(60), false)
            .await
            .unwrap();
        let mut challenge = manager
            .start_enrollment(&anonymous.context, token, now)
            .await
            .unwrap();
        let mut options = serde_json::to_value(&challenge.options).unwrap();
        options["publicKey"]["authenticatorSelection"]["userVerification"] =
            serde_json::json!("discouraged");
        challenge.options = serde_json::from_value(options).unwrap();
        let credential = authenticator
            .do_registration(settings.public_origin.clone(), challenge.options)
            .unwrap();
        let replay = credential.clone();
        assert!(matches!(
            manager
                .finish_enrollment(
                    &anonymous.context,
                    RegistrationFinish {
                        challenge_id: challenge.challenge_id,
                        credential
                    },
                    now
                )
                .await,
            Err(AuthError::Authentication)
        ));
        assert!(matches!(
            manager
                .finish_enrollment(
                    &anonymous.context,
                    RegistrationFinish {
                        challenge_id: challenge.challenge_id,
                        credential: replay
                    },
                    now
                )
                .await,
            Err(AuthError::Challenge)
        ));
        let mut good = WebauthnAuthenticator::new(SoftPasskey::new(true));
        enroll(&manager, &settings, &mut good, now).await;
        let foreign = manager.start_login(&anonymous.context, now).await.unwrap();
        let wrong_origin = good
            .do_authentication(
                "https://evil.manager.example.invalid".parse().unwrap(),
                foreign.options,
            )
            .unwrap();
        let replay = wrong_origin.clone();
        assert!(matches!(
            manager
                .finish_login(
                    &anonymous.context,
                    AuthenticationFinish {
                        challenge_id: foreign.challenge_id,
                        credential: wrong_origin
                    },
                    now
                )
                .await,
            Err(AuthError::Authentication)
        ));
        assert!(matches!(
            manager
                .finish_login(
                    &anonymous.context,
                    AuthenticationFinish {
                        challenge_id: foreign.challenge_id,
                        credential: replay
                    },
                    now
                )
                .await,
            Err(AuthError::Challenge)
        ));
        let challenge = manager.start_login(&anonymous.context, now).await.unwrap();
        let credential = good
            .do_authentication(settings.public_origin.clone(), challenge.options)
            .unwrap();
        assert!(matches!(
            manager
                .finish_login(
                    &anonymous.context,
                    AuthenticationFinish {
                        challenge_id: challenge.challenge_id,
                        credential
                    },
                    now + Duration::seconds(61)
                )
                .await,
            Err(AuthError::Expired)
        ));
    }
}
