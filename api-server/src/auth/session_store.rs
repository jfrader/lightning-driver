use super::{ActiveSession, AuthError, ClientIdentity, Context};
use crate::journal::Journal;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const IDLE_WRITE_SECONDS: i64 = 30;

#[derive(Clone)]
pub(super) struct SessionStore {
    path: PathBuf,
}

impl SessionStore {
    pub(super) fn new(path: &Path) -> Self {
        Self { path: path.into() }
    }

    fn connection(&self) -> Result<Connection, AuthError> {
        Journal::connection(&self.path).map_err(|_| AuthError::Storage)
    }

    pub(super) fn prune(
        connection: &Connection,
        generation: i64,
        now: DateTime<Utc>,
        live_keys: &[[u8; 32]],
    ) -> Result<(), AuthError> {
        let mut statement = connection.prepare(
            "SELECT key,generation,expires_at FROM sessions WHERE generation<?1 OR expires_at<=?2 OR idle_expires_at<=?2",
        ).map_err(|_| AuthError::Storage)?;
        let rows = statement
            .query_map(params![generation, now.timestamp()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| AuthError::Storage)?;
        let mut expired = Vec::new();
        for row in rows {
            let (key, stored_generation, expires) = row.map_err(|_| AuthError::Storage)?;
            // Coalesced idle writes can lag memory; never prune a still-live cached session.
            if stored_generation < generation
                || expires <= now.timestamp()
                || !live_keys.iter().any(|live| live.as_slice() == key)
            {
                expired.push(key);
            }
        }
        drop(statement);
        for key in expired {
            connection
                .execute("DELETE FROM sessions WHERE key=?1", [key])
                .map_err(|_| AuthError::Storage)?;
        }
        Ok(())
    }

    pub(super) fn maintain(
        &self,
        generation: i64,
        now: DateTime<Utc>,
        live_keys: &[[u8; 32]],
    ) -> Result<(), AuthError> {
        Self::prune(&self.connection()?, generation, now, live_keys)
    }

    pub(super) fn admit(
        connection: &Connection,
        generation: i64,
        maximum: usize,
        now: DateTime<Utc>,
        live_keys: &[[u8; 32]],
    ) -> Result<(), AuthError> {
        let current: i64 = connection
            .query_row(
                "SELECT generation FROM auth_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AuthError::Storage)?;
        if current != generation {
            return Err(AuthError::Session);
        }
        Self::prune(connection, current, now, live_keys)?;
        let count: i64 = connection
            .query_row(
                "SELECT count(*) FROM sessions WHERE generation=?1",
                [current],
                |row| row.get(0),
            )
            .map_err(|_| AuthError::Storage)?;
        if count >= i64::try_from(maximum).map_err(|_| AuthError::Storage)? {
            return Err(AuthError::Limited);
        }
        Ok(())
    }

    pub(super) fn insert(connection: &Connection, context: &Context) -> Result<(), AuthError> {
        let (kind, ip) = match context.identity {
            ClientIdentity::Socket(ip) => ("socket", ip),
            ClientIdentity::Forwarded(ip) => ("forwarded", ip),
        };
        connection.execute(
            "INSERT INTO sessions(key,context_id,csrf,generation,identity_kind,identity_ip,nostr_pubkey,created_at,expires_at,idle_expires_at,last_authenticated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![context.key.as_slice(), context.id.to_string(), context.csrf.as_str(), context.generation,
                kind, ip.to_string(), context.nostr_pubkey, context.created_at.timestamp(), context.expires_at.timestamp(),
                context.idle_expires_at.timestamp(), context.last_authenticated_at.ok_or(AuthError::Session)?.timestamp()],
        ).map_err(|_| AuthError::Storage)?;
        Ok(())
    }

    pub(super) fn create(
        &self,
        context: &Context,
        maximum: usize,
        now: DateTime<Utc>,
        live_keys: &[[u8; 32]],
    ) -> Result<(), AuthError> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthError::Storage)?;
        Self::admit(&tx, context.generation, maximum, now, live_keys)?;
        Self::insert(&tx, context)?;
        tx.commit().map_err(|_| AuthError::Storage)
    }

    pub(super) fn load(&self, key: &[u8; 32]) -> Result<Option<Context>, AuthError> {
        let connection = self.connection()?;
        connection.query_row(
            "SELECT context_id,csrf,generation,identity_kind,identity_ip,nostr_pubkey,created_at,expires_at,idle_expires_at,last_authenticated_at FROM sessions WHERE key=?1",
            [key.as_slice()],
            |row| {
                // SQL failures and malformed authority are deliberately distinct.
                let id: String = row.get(0)?;
                let csrf: String = row.get(1)?;
                let generation: i64 = row.get(2)?;
                let kind: String = row.get(3)?;
                let ip: String = row.get(4)?;
                let nostr_pubkey: Option<String> = row.get(5)?;
                let created: i64 = row.get(6)?;
                let expires: i64 = row.get(7)?;
                let idle: i64 = row.get(8)?;
                let last: i64 = row.get(9)?;
                Ok((|| {
                    let token = |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
                    if generation < 0 || !token(&csrf)
                        || nostr_pubkey.as_deref().is_some_and(|key| !token(key))
                        || created > last || last > expires || idle < created || idle > expires
                    {
                        return Err(AuthError::Session);
                    }
                    let ip = ip.parse().map_err(|_| AuthError::Session)?;
                    let identity = match kind.as_str() {
                        "socket" => ClientIdentity::Socket(ip),
                        "forwarded" => ClientIdentity::Forwarded(ip),
                        _ => return Err(AuthError::Session),
                    };
                    let time = |value| DateTime::from_timestamp(value, 0).ok_or(AuthError::Session);
                    Ok(Context {
                        key: *key, id: Uuid::parse_str(&id).map_err(|_| AuthError::Session)?,
                        csrf: Zeroizing::new(csrf), generation, identity, nostr_pubkey,
                        created_at: time(created)?, expires_at: time(expires)?, idle_expires_at: time(idle)?,
                        last_authenticated_at: Some(time(last)?),
                    })
                })())
            },
        ).optional().map_err(|error| match error {
            rusqlite::Error::InvalidColumnType(..) => AuthError::Session,
            _ => AuthError::Storage,
        })?.transpose()
    }

    pub(super) fn delete(&self, key: &[u8; 32]) -> Result<(), AuthError> {
        self.connection()?
            .execute("DELETE FROM sessions WHERE key=?1", [key.as_slice()])
            .map_err(|_| AuthError::Storage)?;
        Ok(())
    }

    pub(super) fn list(
        &self,
        generation: i64,
        current: Uuid,
        now: DateTime<Utc>,
        cached: &HashMap<[u8; 32], Context>,
    ) -> Result<Vec<ActiveSession>, AuthError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT context_id,created_at,expires_at,idle_expires_at,last_authenticated_at,nostr_pubkey FROM sessions WHERE generation=?1 AND expires_at>?2 ORDER BY created_at DESC,context_id DESC",
        ).map_err(|_| AuthError::Storage)?;
        let rows = statement
            .query_map(params![generation, now.timestamp()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })
            .map_err(|_| AuthError::Storage)?;
        let time = |value| DateTime::from_timestamp(value, 0).ok_or(AuthError::Storage);
        let mut sessions = Vec::new();
        let cached: HashMap<_, _> = cached
            .values()
            .filter(|context| context.generation == generation)
            .map(|context| (context.id, context))
            .collect();
        for row in rows {
            let (id, created, expires, idle, last, nostr_pubkey) =
                row.map_err(|_| AuthError::Storage)?;
            let id = Uuid::parse_str(&id).map_err(|_| AuthError::Storage)?;
            // Idle writes are coalesced; cached authority can be newer than the row.
            let idle_expires_at = cached
                .get(&id)
                .map(|context| context.idle_expires_at)
                .unwrap_or(time(idle)?);
            if idle_expires_at <= now {
                continue;
            }
            sessions.push(ActiveSession {
                id,
                created_at: time(created)?,
                expires_at: time(expires)?,
                idle_expires_at,
                last_authenticated_at: time(last)?,
                method: if nostr_pubkey.is_some() {
                    "nostr"
                } else {
                    "passkey"
                },
                nostr_pubkey,
                current: id == current,
            });
        }
        Ok(sessions)
    }

    pub(super) fn delete_by_id(&self, id: Uuid, generation: i64) -> Result<(), AuthError> {
        let changed = self
            .connection()?
            .execute(
                "DELETE FROM sessions WHERE context_id=?1 AND generation=?2",
                params![id.to_string(), generation],
            )
            .map_err(|_| AuthError::Storage)?;
        if changed == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    pub(super) fn refresh(&self, context: &Context) -> Result<(), AuthError> {
        let changed = self.connection()?.execute(
            "UPDATE sessions SET last_authenticated_at=?2,nostr_pubkey=?3 WHERE key=?1 AND generation=?4",
            params![context.key.as_slice(), context.last_authenticated_at.ok_or(AuthError::Session)?.timestamp(), context.nostr_pubkey, context.generation],
        ).map_err(|_| AuthError::Storage)?;
        if changed != 1 {
            return Err(AuthError::Session);
        }
        Ok(())
    }

    pub(super) fn slide(&self, context: &Context) -> Result<(), AuthError> {
        let connection = self.connection()?;
        let stored: Option<i64> = connection
            .query_row(
                "SELECT idle_expires_at FROM sessions WHERE key=?1 AND generation=?2",
                params![context.key.as_slice(), context.generation],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| AuthError::Storage)?;
        let stored = stored.ok_or(AuthError::Session)?;
        if context.idle_expires_at.timestamp() - stored < IDLE_WRITE_SECONDS {
            return Ok(());
        }
        connection.execute(
            "UPDATE sessions SET idle_expires_at=?2 WHERE key=?1 AND generation=?3 AND idle_expires_at<=?2-?4",
            params![context.key.as_slice(), context.idle_expires_at.timestamp(), context.generation, IDLE_WRITE_SECONDS],
        ).map_err(|_| AuthError::Storage)?;
        Ok(())
    }
}
