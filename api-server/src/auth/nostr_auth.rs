use super::*;
use crate::nostr::{normalize_pubkey, Event, MAX_ATTEMPTS, MAX_IDENTITIES, TTL_SECONDS};

const CONSUMED_ATTEMPTS: i64 = -1;

#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
pub struct NostrIdentity {
    pub pubkey: String,
    pub npub: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NostrStart {
    pub purpose: String,
    pub token: Option<String>,
    pub pubkey: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NostrFinish {
    pub challenge_id: Uuid,
    pub event: Event,
}

#[derive(Serialize)]
pub struct NostrChallenge {
    pub challenge_id: Uuid,
    pub nonce: String,
    pub expires_at: DateTime<Utc>,
    pub url: String,
    pub event: EventTemplate,
}

#[derive(Serialize)]
pub struct EventTemplate {
    kind: u32,
    created_at: i64,
    tags: Vec<Vec<String>>,
    content: String,
}

pub enum NostrOutcome {
    Session(NewContext),
    Identity(NostrIdentity),
    Removed,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NostrAuthorizationStart {
    ChallengeRequired {
        challenge: NostrChallenge,
    },
    Authorized {
        authorization: OperationAuthorization,
    },
}

#[derive(Clone, Serialize, Deserialize)]
struct Binding {
    purpose: String,
    token_hash: Option<Vec<u8>>,
    target: Option<String>,
    operation: Option<GrantBinding>,
    tags: Vec<Vec<String>>,
}

struct StoredChallenge {
    owner: String,
    generation: i64,
    nonce_hash: Vec<u8>,
    binding: Binding,
    expires: i64,
    attempts: i64,
}

impl StoredChallenge {
    fn load(connection: &rusqlite::Connection, id: Uuid) -> Result<Option<Self>, JournalError> {
        let record = connection.query_row(
            "SELECT owner,generation,nonce_hash,binding,expires_at,attempts FROM nostr_challenges WHERE id=?1",
            [id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, String>(3)?, row.get::<_, i64>(4)?, row.get::<_, i64>(5)?)),
        ).optional()?;
        record
            .map(
                |(owner, generation, nonce_hash, binding, expires, attempts)| {
                    Ok(Self {
                        owner,
                        generation,
                        nonce_hash,
                        binding: serde_json::from_str(&binding)?,
                        expires,
                        attempts,
                    })
                },
            )
            .transpose()
    }

    fn validate(
        &self,
        context: &Context,
        generation: i64,
        memory: &Memory,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        if self.owner != context.id.to_string()
            || self.generation != context.generation
            || generation != self.generation
        {
            return Err(AuthError::Challenge);
        }
        if self.attempts == CONSUMED_ATTEMPTS {
            return Err(if self.binding.purpose == "enrollment" {
                AuthError::Authentication
            } else {
                AuthError::Challenge
            });
        }
        if !memory.contexts.get(&context.key).is_some_and(|live| {
            live.id == context.id
                && live.generation == generation
                && live.expires_at > now
                && live.idle_expires_at > now
        }) {
            return Err(AuthError::Challenge);
        }
        if self.expires <= now.timestamp() {
            return Err(AuthError::Expired);
        }
        if self.attempts >= MAX_ATTEMPTS {
            return Err(AuthError::Challenge);
        }
        Ok(())
    }
}

impl Journal {
    pub async fn nostr_identities(&self) -> Result<Vec<NostrIdentity>, JournalError> {
        self.run(|connection| {
            let mut statement = connection.prepare("SELECT pubkey,npub,label,created_at,last_used_at FROM nostr_identities ORDER BY created_at,pubkey")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, i64>(3)?, row.get::<_, Option<i64>>(4)?))
            })?;
            rows.map(|row| {
                let (pubkey, npub, label, created, used) = row?;
                Ok(NostrIdentity { pubkey, npub, label,
                    created_at: DateTime::from_timestamp(created, 0).ok_or(JournalError::Storage)?,
                    last_used_at: used.map(|time| DateTime::from_timestamp(time, 0).ok_or(JournalError::Storage)).transpose()?,
                })
            }).collect()
        }).await
    }

    pub async fn credential_counts(&self) -> Result<(i64, i64), JournalError> {
        self.run(|connection| {
            Ok(connection.query_row(
                "SELECT (SELECT count(*) FROM credentials),(SELECT count(*) FROM nostr_identities)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?)
        })
        .await
    }
}

fn identity(pubkey: String, now: DateTime<Utc>) -> Result<NostrIdentity, AuthError> {
    let bytes = hex::decode(&pubkey).map_err(|_| AuthError::Authentication)?;
    let npub = bech32::encode::<bech32::Bech32>(
        bech32::Hrp::parse("npub").map_err(|_| AuthError::Storage)?,
        &bytes,
    )
    .map_err(|_| AuthError::Storage)?;
    Ok(NostrIdentity {
        pubkey,
        npub,
        label: None,
        created_at: now,
        last_used_at: None,
    })
}

impl AuthManager {
    pub async fn nostr_login_available(&self) -> Result<bool, AuthError> {
        Ok(self.journal.credential_counts().await?.1 > 0)
    }

    pub async fn start_nostr(
        &self,
        context: &Context,
        request: NostrStart,
        now: DateTime<Utc>,
    ) -> Result<NostrChallenge, AuthError> {
        let authenticated = context.last_authenticated_at.is_some();
        if !matches!(
            request.purpose.as_str(),
            "login" | "enrollment" | "link" | "unlink"
        ) || (request.purpose != "enrollment" && request.token.is_some())
            || (request.purpose != "unlink" && request.pubkey.is_some())
        {
            return Err(AuthError::InvalidRequest);
        }
        if authenticated != matches!(request.purpose.as_str(), "link" | "unlink") {
            return Err(AuthError::Session);
        }
        // Adding an authenticator needs proof of the method that owns this session: a
        // stolen live session must not be able to link a key it controls. The operator
        // re-authenticates (passkey assertion or a linked key's signature), which stamps
        // `last_authenticated_at` on the rotated session; unlink keeps its own stronger
        // rule, a fresh signature from the exact identity being removed.
        if request.purpose == "link" {
            let window = i64::from(self.limits.authorization_seconds);
            let fresh = context.last_authenticated_at.is_some_and(|at| {
                let age = now.signed_duration_since(at).num_seconds();
                (0..=window).contains(&age)
            });
            if !fresh {
                return Err(AuthError::ReauthRequired);
            }
        }
        let target = request
            .pubkey
            .as_deref()
            .map(normalize_pubkey)
            .transpose()?;
        if request.purpose == "unlink" && target.is_none() {
            return Err(AuthError::InvalidRequest);
        }
        let token_hash = if request.purpose == "enrollment" {
            if !self.journal.enrollment_available(now).await? {
                return Err(AuthError::EnrollmentUnavailable);
            }
            let token = Zeroizing::new(request.token.ok_or(AuthError::Authentication)?);
            if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(AuthError::Authentication);
            }
            Some(token_hash(token.as_bytes()).to_vec())
        } else {
            None
        };
        let binding = Binding {
            purpose: request.purpose,
            token_hash,
            target,
            operation: None,
            tags: vec![],
        };
        self.insert_nostr(context, binding, "/api/v1/auth/nostr/finish".into(), now)
            .await
    }

    async fn insert_nostr(
        &self,
        context: &Context,
        mut binding: Binding,
        path: String,
        now: DateTime<Utc>,
    ) -> Result<NostrChallenge, AuthError> {
        let nonce = random_token().to_string();
        let nonce_hash = token_hash(nonce.as_bytes()).to_vec();
        let url = self
            .public_origin
            .join(&path)
            .map_err(|_| AuthError::Storage)?
            .to_string();
        let mut tags = vec![
            vec!["u".into(), url.clone()],
            vec!["method".into(), "POST".into()],
            vec!["challenge".into(), nonce.clone()],
            vec!["purpose".into(), binding.purpose.clone()],
        ];
        if let Some(operation) = &binding.operation {
            tags.push(vec!["operation".into(), operation.operation_id.to_string()]);
            tags.push(vec!["digest".into(), operation.digest.clone()]);
        }
        if let Some(target) = &binding.target {
            tags.push(vec!["target".into(), target.clone()]);
        }
        binding.tags = tags.clone();
        // The returned template contains the nonce; durable storage contains its hash only.
        binding.tags[2][1].clear();
        let id = Uuid::new_v4();
        let expires = (now + Duration::seconds(TTL_SECONDS))
            .min(context.expires_at)
            .min(context.idle_expires_at);
        let context = context.clone();
        let manager = self.clone();
        self.journal.run(move |connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let generation: i64 = tx.query_row("SELECT generation FROM auth_meta WHERE singleton=1", [], |row| row.get(0))?;
            let mut memory = manager.memory.lock().map_err(|_| JournalError::Storage)?;
            memory.prune(now);
            let Some(live) = memory.contexts.get(&context.key) else { return Ok(Err(AuthError::Session)); };
            if live.id != context.id || live.generation != generation || expires <= now { return Ok(Err(AuthError::Session)); }
            if binding.purpose == "login" {
                let count: i64 = tx.query_row("SELECT count(*) FROM nostr_identities", [], |row| row.get(0))?;
                if count == 0 { return Ok(Err(AuthError::Authentication)); }
            }
            if let Some(hash) = &binding.token_hash {
                let valid: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM enrollment WHERE token_hash=?1 AND generation=?2 AND expires_at>?3)", params![hash, generation, now.timestamp()], |row| row.get(0))?;
                if !valid { return Ok(Err(AuthError::Authentication)); }
            }
            if let Some(target) = &binding.target {
                let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM nostr_identities WHERE pubkey=?1)", [target], |row| row.get(0))?;
                if !exists { return Ok(Err(AuthError::Authentication)); }
                let count: i64 = tx.query_row("SELECT (SELECT count(*) FROM credentials)+(SELECT count(*) FROM nostr_identities)", [], |row| row.get(0))?;
                if count <= 1 { return Ok(Err(AuthError::LastCredential)); }
            }
            tx.execute("DELETE FROM nostr_challenges WHERE expires_at<=?1 OR generation<>?2", params![now.timestamp(), generation])?;
            if let Err(error) = memory.admit_challenge(&context, manager.limits.max_challenges) { return Ok(Err(error)); }
            tx.execute("INSERT INTO nostr_challenges(id,owner,generation,nonce_hash,binding,expires_at) VALUES(?1,?2,?3,?4,?5,?6)", params![id.to_string(),context.id.to_string(),generation,nonce_hash,serde_json::to_string(&binding)?,expires.timestamp()])?;
            tx.commit()?;
            memory.nostr_pending.insert(id, (context.id, expires));
            Ok(Ok(()))
        }).await??;
        Ok(NostrChallenge {
            challenge_id: id,
            nonce,
            expires_at: expires,
            url,
            event: EventTemplate {
                kind: 27235,
                created_at: now.timestamp(),
                tags,
                content: String::new(),
            },
        })
    }

    pub async fn finish_nostr(
        &self,
        context: &Context,
        finish: NostrFinish,
        now: DateTime<Utc>,
    ) -> Result<NostrOutcome, AuthError> {
        let (purpose, key, session) = self.verify_nostr(context, finish, None, now).await?;
        match purpose.as_str() {
            "login" | "enrollment" => Ok(NostrOutcome::Session(session.ok_or(AuthError::Storage)?)),
            "link" => Ok(NostrOutcome::Identity(identity(key, now)?)),
            "unlink" => Ok(NostrOutcome::Removed),
            _ => Err(AuthError::Challenge),
        }
    }

    async fn verify_nostr(
        &self,
        context: &Context,
        finish: NostrFinish,
        operation: Option<&Operation>,
        now: DateTime<Utc>,
    ) -> Result<(String, String, Option<NewContext>), AuthError> {
        self.preflight_nostr(context, finish.challenge_id, now)
            .await?;
        self.verify_nostr_transaction(context, finish, operation, now)
            .await
    }

    pub(crate) async fn preflight_nostr(
        &self,
        context: &Context,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let context = context.clone();
        let manager = self.clone();
        self.journal
            .run(move |connection| {
                // Only WAL reads occur here. Hold the context lock while reading so a
                // concurrent rotation cannot pair an old challenge with a revoked context.
                let memory = manager.memory.lock().map_err(|_| JournalError::Storage)?;
                let Some(challenge) = StoredChallenge::load(connection, id)? else {
                    return Ok(Err(AuthError::Challenge));
                };
                let generation = connection.query_row(
                    "SELECT generation FROM auth_meta WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )?;
                Ok(challenge.validate(&context, generation, &memory, now))
            })
            .await?
    }

    async fn verify_nostr_transaction(
        &self,
        context: &Context,
        finish: NostrFinish,
        operation: Option<&Operation>,
        now: DateTime<Utc>,
    ) -> Result<(String, String, Option<NewContext>), AuthError> {
        let context = context.clone();
        let operation = operation.cloned();
        let manager = self.clone();
        let permit = self
            .workers
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| AuthError::Storage)?;
        self.journal.run(move |connection| {
            let _permit = permit;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let Some(challenge) = StoredChallenge::load(&tx, finish.challenge_id)? else { return Ok(Err(AuthError::Challenge)); };
            let mut memory = manager.memory.lock().map_err(|_| JournalError::Storage)?;
            memory.prune(now);
            let current: i64 = tx.query_row("SELECT generation FROM auth_meta WHERE singleton=1", [], |row| row.get(0))?;
            if let Err(error) = challenge.validate(&context, current, &memory, now) { return Ok(Err(error)); }
            let StoredChallenge { generation, nonce_hash, binding, .. } = challenge;
            memory.nostr_failures.retain(|_, queue| {
                while queue.front().is_some_and(|time| *time + Duration::seconds(RATE_WINDOW_SECONDS) <= now) { queue.pop_front(); }
                !queue.is_empty()
            });
            if memory.nostr_failures.get(&context.id).is_some_and(|queue| queue.len() >= manager.admission.starts_per_minute)
            { return Ok(Err(AuthError::Limited)); }
            if !memory.nostr_failures.contains_key(&context.id) && memory.nostr_failures.len() >= MAX_RATE_BUCKETS {
                // A flood of unrelated contexts must not lock another context out globally.
                if let Some(oldest) = memory.nostr_failures.iter().min_by_key(|(_, queue)| queue.back().copied()).map(|(key, _)| *key) {
                    memory.nostr_failures.remove(&oldest);
                }
            }
            let verified = (|| -> Result<String, AuthError> {
                match (&binding.operation, &operation) {
                    (None, None) => {},
                    (Some(expected), Some(operation)) if binding.purpose == "operation" && operation.binding_is_valid()
                        && *expected == GrantBinding::from_operation(operation)
                        && operation.state == OperationState::AwaitingConfirmation && operation.review.expires_at > now => {},
                    _ => return Err(AuthError::Authorization),
                }
                let key = finish.event.verify(&binding.tags, &nonce_hash, now.timestamp()).map_err(|error| if binding.operation.is_some() { AuthError::Authorization } else { error })?;
                if binding.target.as_ref().is_some_and(|target| *target != key)
                    || (binding.operation.is_some() && context.nostr_pubkey.as_ref() != Some(&key))
                { return Err(AuthError::Authentication); }
                let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM nostr_identities WHERE pubkey=?1)", [&key], |row| row.get(0)).map_err(|_| AuthError::Storage)?;
                if matches!(binding.purpose.as_str(), "login" | "operation" | "unlink") && !exists { return Err(AuthError::Authentication); }
                if matches!(binding.purpose.as_str(), "link" | "enrollment") && exists { return Err(AuthError::Authentication); }
                Ok(key)
            })();
            let key = match verified {
                Ok(key) => key,
                Err(error) => {
                    memory.nostr_failures.entry(context.id).or_default().push_back(now);
                    tx.execute("UPDATE nostr_challenges SET attempts=attempts+1 WHERE id=?1", [finish.challenge_id.to_string()])?;
                    tx.commit()?;
                    return Ok(Err(error));
                }
            };
            tx.execute("DELETE FROM nostr_replays WHERE expires_at<=?1", [now.timestamp()])?;
            let replay: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM nostr_replays WHERE event_id=?1)", [&finish.event.id], |row| row.get(0))?;
            if replay {
                tx.execute("UPDATE nostr_challenges SET attempts=attempts+1 WHERE id=?1", [finish.challenge_id.to_string()])?;
                tx.commit()?;
                return Ok(Err(AuthError::Authentication));
            }
            let replays: i64 = tx.query_row("SELECT count(*) FROM nostr_replays", [], |row| row.get(0))?;
            if replays >= manager.limits.max_challenges as i64 { return Ok(Err(AuthError::Limited)); }
            let session = if matches!(binding.purpose.as_str(), "login" | "enrollment") {
                if memory.contexts.values().filter(|context| context.last_authenticated_at.is_some()).count() >= manager.limits.max_sessions {
                    return Ok(Err(AuthError::Limited));
                }
                let mut session = manager.build_context(now, generation, true, context.identity);
                session.context.nostr_pubkey = Some(key.clone());
                Some(session)
            } else { None };
            if matches!(binding.purpose.as_str(), "enrollment" | "link") {
                let count: i64 = tx.query_row("SELECT count(*) FROM nostr_identities", [], |row| row.get(0))?;
                if count >= MAX_IDENTITIES { return Ok(Err(AuthError::Limited)); }
                if let Some(hash) = &binding.token_hash {
                    let deleted = tx.execute("DELETE FROM enrollment WHERE token_hash=?1 AND generation=?2 AND expires_at>?3", params![hash,generation,now.timestamp()])?;
                    if deleted != 1 {
                        tx.execute("UPDATE nostr_challenges SET attempts=attempts+1 WHERE id=?1", [finish.challenge_id.to_string()])?;
                        tx.commit()?;
                        return Ok(Err(AuthError::Authentication));
                    }
                } else if binding.purpose == "enrollment" { return Ok(Err(AuthError::Authentication)); }
                let record = match identity(key.clone(), now) { Ok(record) => record, Err(error) => return Ok(Err(error)) };
                tx.execute("INSERT INTO nostr_identities(pubkey,npub,created_at) VALUES(?1,?2,?3)", params![key,record.npub,now.timestamp()])?;
            } else if binding.purpose == "unlink" {
                let count: i64 = tx.query_row("SELECT (SELECT count(*) FROM credentials)+(SELECT count(*) FROM nostr_identities)", [], |row| row.get(0))?;
                if count <= 1 { return Ok(Err(AuthError::LastCredential)); }
                tx.execute("DELETE FROM nostr_identities WHERE pubkey=?1", [&key])?;
                tx.execute("UPDATE auth_meta SET generation=generation+1 WHERE singleton=1", [])?;
            } else {
                tx.execute("UPDATE nostr_identities SET last_used_at=?2 WHERE pubkey=?1", params![key,now.timestamp()])?;
            }
            tx.execute("UPDATE nostr_challenges SET attempts=?2 WHERE id=?1", params![finish.challenge_id.to_string(),CONSUMED_ATTEMPTS])?;
            tx.execute("INSERT INTO nostr_replays(event_id,expires_at) VALUES(?1,?2)", params![finish.event.id,(now + Duration::seconds(TTL_SECONDS)).timestamp()])?;
            tx.commit()?;
            memory.nostr_pending.remove(&finish.challenge_id);
            // SQLite commit and session rotation share the live-context lock with logout.
            // No authority enters memory before durable challenge/token consumption.
            if let Some(session) = &session {
                memory.contexts.remove(&context.key);
                memory.ceremonies.retain(|_, ceremony| ceremony.owner != context.id);
                memory.nostr_pending.retain(|_, (owner, _)| *owner != context.id);
                memory.grants.retain(|_, grant| grant.owner != context.id);
                memory.contexts.insert(session.context.key, session.context.clone());
            } else if binding.purpose == "unlink" {
                memory.contexts.retain(|_, context| context.generation > generation);
                memory.ceremonies.clear();
                memory.nostr_pending.clear();
                memory.grants.clear();
            }
            Ok(Ok((binding.purpose,key,session)))
        }).await?
    }

    pub async fn start_nostr_authorization(
        &self,
        context: &Context,
        operation: &Operation,
        now: DateTime<Utc>,
    ) -> Result<NostrAuthorizationStart, AuthError> {
        if context.nostr_pubkey.is_none() {
            return Err(AuthError::Authentication);
        }
        if !operation.binding_is_valid()
            || operation.state != OperationState::AwaitingConfirmation
            || operation.review.expires_at <= now
        {
            return Err(AuthError::Authorization);
        }
        if !operation.request.sensitive() {
            return Err(AuthError::NotRequired);
        }
        let recent = self.policy.mode == ReauthMode::Recent
            && context.last_authenticated_at.is_some_and(|last| {
                self.policy
                    .recent_auth_seconds
                    .is_some_and(|seconds| now < last + Duration::seconds(i64::from(seconds)))
            });
        if recent {
            return Ok(NostrAuthorizationStart::Authorized {
                authorization: self.issue_grant(context, operation, now)?,
            });
        }
        let binding = Binding {
            purpose: "operation".into(),
            token_hash: None,
            target: None,
            operation: Some(GrantBinding::from_operation(operation)),
            tags: vec![],
        };
        let path = format!(
            "/api/v1/nodes/{}/operations/{}/authorize/nostr/finish",
            operation.node_id, operation.id
        );
        Ok(NostrAuthorizationStart::ChallengeRequired {
            challenge: self.insert_nostr(context, binding, path, now).await?,
        })
    }

    pub async fn finish_nostr_authorization(
        &self,
        context: &Context,
        operation: &Operation,
        finish: NostrFinish,
        now: DateTime<Utc>,
    ) -> Result<OperationAuthorization, AuthError> {
        if context.nostr_pubkey.is_none() {
            return Err(AuthError::Authentication);
        }
        self.verify_nostr(context, finish, Some(operation), now)
            .await?;
        let refreshed = {
            let mut memory = self.memory.lock().map_err(|_| AuthError::Storage)?;
            let live = memory
                .contexts
                .get_mut(&context.key)
                .ok_or(AuthError::Session)?;
            live.last_authenticated_at = Some(now);
            live.clone()
        };
        self.issue_grant(&refreshed, operation, now)
    }
}
