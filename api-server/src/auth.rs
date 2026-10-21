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
    time::Instant,
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use zeroize::Zeroizing;

const MAX_AUTHENTICATORS: usize = 16;
const MAX_RATE_BUCKETS: usize = 256;
const VERIFICATION_WORKERS: usize = 2;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
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
    #[error("Operation authorization invalid")]
    Authorization,
    #[error("Operation does not require reauthentication")]
    NotRequired,
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
    webauthn: Arc<Webauthn>,
    journal: Journal,
    limits: Limits,
    policy: ReauthPolicy,
    memory: Arc<Mutex<Memory>>,
    workers: Arc<Semaphore>,
}

#[derive(Default)]
struct Memory {
    contexts: HashMap<[u8; 32], Context>,
    ceremonies: HashMap<Uuid, Ceremony>,
    grants: HashMap<Uuid, Grant>,
    rates: HashMap<IpAddr, VecDeque<Instant>>,
}

#[derive(Clone)]
pub struct Context {
    key: [u8; 32],
    id: Uuid,
    csrf: Zeroizing<String>,
    generation: i64,
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
    pub authenticated: bool,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub last_authenticated_at: DateTime<Utc>,
    pub reauth: ReauthPolicy,
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

#[derive(Clone, PartialEq)]
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
    pub fn new(settings: &ApiSettings, journal: Journal) -> Result<Self, AuthError> {
        let webauthn = WebauthnBuilder::new(&settings.rp_id, &settings.public_origin)
            .map_err(|_| AuthError::Authentication)?
            .rp_name("Lightning node manager")
            .build()
            .map_err(|_| AuthError::Authentication)?;
        Ok(Self {
            webauthn: Arc::new(webauthn),
            journal,
            limits: settings.limits.clone(),
            policy: settings.reauth.clone(),
            memory: Arc::new(Mutex::new(Memory::default())),
            workers: Arc::new(Semaphore::new(VERIFICATION_WORKERS)),
        })
    }

    pub fn admit(&self, address: IpAddr) -> Result<(), AuthError> {
        let now = Instant::now();
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        memory.rates.retain(|_, queue| {
            while queue
                .front()
                .is_some_and(|time| now.duration_since(*time).as_secs() >= 60)
            {
                queue.pop_front();
            }
            !queue.is_empty()
        });
        if !memory.rates.contains_key(&address) && memory.rates.len() >= MAX_RATE_BUCKETS {
            return Err(AuthError::Limited);
        }
        let queue = memory.rates.entry(address).or_default();
        if queue.len() >= self.limits.login_attempts_per_minute {
            return Err(AuthError::Limited);
        }
        queue.push_back(now);
        Ok(())
    }

    pub async fn anonymous(&self, now: DateTime<Utc>) -> Result<NewContext, AuthError> {
        let generation = self.journal.authentication().await?.1;
        self.create_context(now, generation, false)
    }

    fn create_context(
        &self,
        now: DateTime<Utc>,
        generation: i64,
        authenticated: bool,
    ) -> Result<NewContext, AuthError> {
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
            key,
            id: Uuid::new_v4(),
            csrf,
            generation,
            expires_at,
            idle_expires_at: if authenticated {
                (now + Duration::seconds(i64::from(self.limits.session_idle_seconds)))
                    .min(expires_at)
            } else {
                expires_at
            },
            last_authenticated_at: authenticated.then_some(now),
        };
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
        if memory
            .contexts
            .values()
            .filter(|context| context.last_authenticated_at.is_some() == authenticated)
            .count()
            >= self.limits.max_sessions
        {
            return Err(AuthError::Limited);
        }
        memory.contexts.insert(key, context.clone());
        Ok(NewContext { context, cookie })
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
        {
            let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
            memory.prune(now);
            let context = memory.contexts.get(&key).ok_or(AuthError::Session)?;
            if context.last_authenticated_at.is_some() != authenticated {
                return Err(AuthError::Session);
            }
        }
        let generation = self.journal.authentication().await?.1;
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        memory
            .contexts
            .retain(|_, context| context.generation >= generation);
        memory.prune(now);
        let context = memory.contexts.get_mut(&key).ok_or(AuthError::Session)?;
        if context.generation != generation
            || context.last_authenticated_at.is_some() != authenticated
        {
            return Err(AuthError::Session);
        }
        if authenticated {
            context.idle_expires_at = (now
                + Duration::seconds(i64::from(self.limits.session_idle_seconds)))
            .min(context.expires_at);
        }
        Ok(context.clone())
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
            authenticated: true,
            csrf_token: context.csrf.to_string(),
            expires_at: context.expires_at,
            idle_expires_at: context.idle_expires_at,
            last_authenticated_at: context.last_authenticated_at.ok_or(AuthError::Session)?,
            reauth: self.policy.clone(),
        })
    }

    pub fn revoke(&self, context: &Context) -> Result<(), AuthError> {
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        memory.contexts.remove(&context.key);
        memory
            .ceremonies
            .retain(|_, ceremony| ceremony.owner != context.id);
        memory.grants.retain(|_, grant| grant.owner != context.id);
        Ok(())
    }

    pub async fn login_available(&self) -> Result<bool, AuthError> {
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
        let ceremony = self.take_ceremony(context, finish.challenge_id, now)?;
        let Purpose::Login(state) = ceremony.purpose else {
            return Err(AuthError::Challenge);
        };
        self.verify_authentication(finish.credential, state, ceremony.generation)
            .await?;
        self.revoke(context)?;
        self.create_context(now, ceremony.generation, true)
    }

    pub async fn start_enrollment(
        &self,
        context: &Context,
        token: Zeroizing<String>,
        now: DateTime<Utc>,
    ) -> Result<RegistrationChallenge, AuthError> {
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

    pub async fn finish_enrollment(
        &self,
        context: &Context,
        finish: RegistrationFinish,
        now: DateTime<Utc>,
    ) -> Result<NewContext, AuthError> {
        let ceremony = self.take_ceremony(context, finish.challenge_id, now)?;
        let Purpose::Enrollment(state) = ceremony.purpose else {
            return Err(AuthError::Challenge);
        };
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthError::Limited)?;
        let webauthn = self.webauthn.clone();
        let passkey = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            webauthn
                .finish_passkey_registration(&finish.credential, &state)
                .map_err(|_| AuthError::Authentication)
        })
        .await
        .map_err(|_| AuthError::Authentication)??;
        self.persist_passkeys(vec![passkey], ceremony.generation)
            .await?;
        self.revoke(context)?;
        self.create_context(now, ceremony.generation, true)
    }

    pub async fn start_authorization(
        &self,
        context: &Context,
        operation: &Operation,
        now: DateTime<Utc>,
    ) -> Result<AuthorizationStart, AuthError> {
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
        let ceremony = self.take_ceremony(context, finish.challenge_id, now)?;
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
        let refreshed = {
            let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
            let refreshed = memory
                .contexts
                .get_mut(&context.key)
                .ok_or(AuthError::Session)?;
            refreshed.last_authenticated_at = Some(now);
            refreshed.clone()
        };
        self.issue_grant(&refreshed, operation, now)
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
        let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
        memory.prune(now);
        if !memory.contexts.contains_key(&context.key) {
            return Err(AuthError::Session);
        }
        if memory.ceremonies.len() >= self.limits.max_challenges {
            return Err(AuthError::Limited);
        }
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
    ) -> Result<Ceremony, AuthError> {
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
        Ok(ceremony)
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

    async fn persist_passkeys(
        &self,
        passkeys: Vec<Passkey>,
        generation: i64,
    ) -> Result<(), AuthError> {
        self.journal.run(move |connection| {
            let tx=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current:i64=tx.query_row("SELECT generation FROM auth_meta WHERE singleton=1",[],|row|row.get(0))?;
            if current!=generation {return Err(JournalError::Revoked);}
            for passkey in passkeys {
                let id=hex::encode(passkey.cred_id());
                let existing:Option<String>=tx.query_row("SELECT credential_id FROM credentials WHERE credential_id=?1",[&id],|row|row.get(0)).optional()?;
                let count:i64=tx.query_row("SELECT COUNT(*) FROM credentials",[],|row|row.get(0))?;
                if existing.is_none() && count>=i64::try_from(MAX_AUTHENTICATORS).map_err(|_|JournalError::Storage)? {return Err(JournalError::Storage);}
                tx.execute("INSERT INTO credentials(credential_id,passkey) VALUES(?1,?2) ON CONFLICT(credential_id) DO UPDATE SET passkey=excluded.passkey",params![id,serde_json::to_string(&passkey)?])?;
            }
            tx.commit()?;Ok(())
        }).await.map_err(Into::into)
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
            .try_acquire_owned()
            .map_err(|_| AuthError::Limited)?;
        let webauthn = self.webauthn.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            webauthn
                .finish_passkey_authentication(&credential, &state)
                .map_err(|_| AuthError::Authentication)
        })
        .await
        .map_err(|_| AuthError::Authentication)??;
        let mut passkeys = self.passkeys().await?;
        let passkey = passkeys
            .iter_mut()
            .find(|key| key.cred_id() == result.cred_id())
            .ok_or(AuthError::Authentication)?;
        passkey
            .update_credential(&result)
            .ok_or(AuthError::Authentication)?;
        self.persist_passkeys(vec![passkey.clone()], generation)
            .await
    }
}

impl Memory {
    fn prune(&mut self, now: DateTime<Utc>) {
        self.contexts
            .retain(|_, context| context.expires_at > now && context.idle_expires_at > now);
        let owners: std::collections::HashSet<_> =
            self.contexts.values().map(|context| context.id).collect();
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

    async fn manager(mode: ReauthMode) -> (tempfile::TempDir, AuthManager, ApiSettings) {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp/opencode")
            .unwrap();
        let settings = ApiSettings {
            bind: "127.0.0.1:8080".parse().unwrap(),
            public_origin: "https://manager.example.invalid".parse().unwrap(),
            rp_id: "manager.example.invalid".into(),
            database: directory.path().join("auth.sqlite"),
            invoice_key_file: directory.path().join("unused.key"),
            allow_insecure_loopback: false,
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
        let anonymous = manager.anonymous(now).await.unwrap();
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
        let anonymous = manager.anonymous(now).await.unwrap();
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
        let stranger = manager.anonymous(now).await.unwrap();
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
        let fresh = manager.anonymous(now).await.unwrap();
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
        let anonymous = manager.anonymous(now).await.unwrap();
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
