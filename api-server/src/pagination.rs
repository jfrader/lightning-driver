use crate::{auth::Context, error::ApiError};
use chrono::{DateTime, Utc};
use lightning_client::{
    model::{ErrorCode, Network, NodeSummary, Operation, Page},
    settings::Limits,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selector {
    pub resource: &'static str,
    pub node: Option<String>,
    pub scope: String,
    pub filters: Vec<(String, String)>,
    pub limit: usize,
}

#[derive(Clone)]
pub enum Rows {
    Nodes(Vec<NodeSummary>),
    Operations(Vec<Operation>),
}
impl Rows {
    fn len(&self) -> usize {
        match self {
            Self::Nodes(rows) => rows.len(),
            Self::Operations(rows) => rows.len(),
        }
    }
    fn bytes(&self) -> Result<usize, ApiError> {
        let result = match self {
            Self::Nodes(rows) => serde_json::to_vec(rows),
            Self::Operations(rows) => serde_json::to_vec(rows),
        };
        result
            .map(|bytes| bytes.len())
            .map_err(|_| ApiError::new(ErrorCode::InternalError))
    }
}
struct Snapshot {
    owner: Uuid,
    selector: Selector,
    rows: Rows,
    network: Option<Network>,
    observed: DateTime<Utc>,
    expires: DateTime<Utc>,
    truncated: bool,
    tokens: Vec<String>,
    bytes: usize,
}
#[derive(Default)]
struct Cache {
    snapshots: Vec<Snapshot>,
}
#[derive(Clone)]
pub struct Snapshots {
    cache: Arc<Mutex<Cache>>,
    limits: Limits,
}
pub enum Paged {
    Nodes(Page<NodeSummary>),
    Operations(Page<Operation>),
}

impl Snapshots {
    pub fn new(limits: Limits) -> Self {
        Self {
            cache: Arc::new(Mutex::new(Cache::default())),
            limits,
        }
    }
    pub fn begin(
        &self,
        context: &Context,
        selector: Selector,
        rows: Rows,
        network: Option<Network>,
        truncated: bool,
        now: DateTime<Utc>,
    ) -> Result<Paged, ApiError> {
        if selector.limit == 0
            || selector.limit > self.limits.pagination.max_limit
            || rows.len() > self.limits.pagination.snapshot_max_items
        {
            return Err(ApiError::new(ErrorCode::InternalError));
        }
        let bytes = rows.bytes()?;
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
        cache.snapshots.retain(|snapshot| snapshot.expires > now);
        if cache.snapshots.len() >= self.limits.snapshot_max_entries
            || cache
                .snapshots
                .iter()
                .filter(|snapshot| snapshot.owner == context.snapshot_owner())
                .count()
                >= self.limits.snapshot_per_session
            || bytes
                > self
                    .limits
                    .snapshot_cache_bytes
                    .saturating_sub(cache.snapshots.iter().map(|snapshot| snapshot.bytes).sum())
        {
            return Err(ApiError::new(ErrorCode::RateLimited));
        }
        let pages = rows.len().div_ceil(selector.limit).max(1);
        let tokens = (0..pages)
            .map(|_| {
                let mut bytes = [0u8; 32];
                OsRng.fill_bytes(&mut bytes);
                hex::encode(bytes)
            })
            .collect();
        let snapshot = Snapshot {
            owner: context.snapshot_owner(),
            selector,
            rows,
            network,
            observed: now,
            expires: (now
                + chrono::Duration::seconds(i64::from(
                    self.limits.pagination.snapshot_ttl_seconds,
                )))
            .min(context.expires_at),
            truncated,
            tokens,
            bytes,
        };
        let page = snapshot.page(0);
        if pages > 1 {
            cache.snapshots.push(snapshot);
        }
        Ok(page)
    }
    pub fn next(
        &self,
        context: &Context,
        selector: &Selector,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<Paged, ApiError> {
        if token.len() != 64
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ApiError::new(ErrorCode::InvalidCursor));
        }
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
        cache.snapshots.retain(|snapshot| snapshot.expires > now);
        for snapshot in &cache.snapshots {
            if let Some(index) = snapshot
                .tokens
                .iter()
                .position(|candidate| candidate == token)
            {
                if snapshot.owner != context.snapshot_owner() || &snapshot.selector != selector {
                    return Err(ApiError::new(ErrorCode::InvalidCursor));
                }
                return Ok(snapshot.page(index));
            }
        }
        Err(ApiError::new(ErrorCode::CursorExpired))
    }
}
impl Snapshot {
    fn page(&self, index: usize) -> Paged {
        let start = index * self.selector.limit;
        let end = (start + self.selector.limit).min(self.rows.len());
        let next_cursor = self.tokens.get(index + 1).cloned();
        match &self.rows {
            Rows::Nodes(rows) => Paged::Nodes(Page {
                node_id: self.selector.node.clone(),
                network: self.network,
                next_cursor,
                observed_at: self.observed,
                stale: false,
                truncated: self.truncated,
                items: rows[start..end].to_vec(),
            }),
            Rows::Operations(rows) => Paged::Operations(Page {
                node_id: self.selector.node.clone(),
                network: self.network,
                next_cursor,
                observed_at: self.observed,
                stale: false,
                truncated: self.truncated,
                items: rows[start..end].to_vec(),
            }),
        }
    }
}

pub struct Query {
    pub cursor: Option<String>,
    pub limit: usize,
    pub filters: Vec<(String, String)>,
}
impl Query {
    pub fn parse(raw: &str, allowed: &[&str], limits: &Limits) -> Result<Self, ApiError> {
        let invalid = || ApiError::new(ErrorCode::InvalidRequest);
        let mut values = HashMap::new();
        for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
            if !allowed.contains(&key.as_ref())
                || values.insert(key.to_string(), value.to_string()).is_some()
            {
                return Err(invalid());
            }
        }
        let limit = if let Some(text) = values.remove("limit") {
            if text.is_empty()
                || text.starts_with('0')
                || !text.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(invalid());
            }
            let limit = text.parse::<usize>().map_err(|_| invalid())?;
            if limit > limits.pagination.max_limit {
                return Err(invalid());
            }
            limit
        } else {
            limits.pagination.default_limit
        };
        let cursor = values.remove("cursor");
        let mut filters: Vec<_> = values.into_iter().collect();
        filters.sort();
        Ok(Self {
            cursor,
            limit,
            filters,
        })
    }
}
