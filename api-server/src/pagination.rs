use crate::{auth::Context, error::ApiError};
use chrono::{DateTime, Utc};
use lightning_client::{
    model::{ErrorCode, Network, NodeSummary, Operation, Page},
    settings::Limits,
};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::{
    collections::HashMap,
    io::{self, Write},
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
        match self {
            Self::Nodes(rows) => serialized_size(rows, usize::MAX),
            Self::Operations(rows) => serialized_size(rows, usize::MAX),
        }
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

struct ByteLimit<W> {
    writer: W,
    bytes: usize,
    max: usize,
}
impl<W: Write> Write for ByteLimit<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.max.saturating_sub(self.bytes) {
            return Err(io::Error::other("Response byte limit exceeded"));
        }
        let written = self.writer.write(bytes)?;
        self.bytes += written;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_size(value: &impl Serialize, max: usize) -> Result<usize, ApiError> {
    let mut counter = ByteLimit {
        writer: io::sink(),
        bytes: 0,
        max,
    };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    Ok(counter.bytes)
}

pub(crate) fn bounded_json(value: &impl Serialize, max: usize) -> Result<Vec<u8>, ApiError> {
    let mut buffer = ByteLimit {
        writer: Vec::new(),
        bytes: 0,
        max,
    };
    serde_json::to_writer(&mut buffer, value)
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    Ok(buffer.writer)
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
        let page = snapshot.page(0, self.limits.max_response_bytes)?;
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
                return snapshot.page(index, self.limits.max_response_bytes);
            }
        }
        Err(ApiError::new(ErrorCode::CursorExpired))
    }
}
impl Snapshot {
    fn page(&self, index: usize, max_bytes: usize) -> Result<Paged, ApiError> {
        let start = index * self.selector.limit;
        let end = (start + self.selector.limit).min(self.rows.len());
        let next_cursor = self.tokens.get(index + 1).cloned();
        match &self.rows {
            Rows::Nodes(rows) => self
                .materialize(&rows[start..end], next_cursor, max_bytes)
                .map(Paged::Nodes),
            Rows::Operations(rows) => self
                .materialize(&rows[start..end], next_cursor, max_bytes)
                .map(Paged::Operations),
        }
    }

    fn materialize<T: Serialize + Clone>(
        &self,
        items: &[T],
        next_cursor: Option<String>,
        max_bytes: usize,
    ) -> Result<Page<T>, ApiError> {
        // Measure borrowed rows before cloning the requested page. Cache bytes bound
        // retained JSON size, not the Rust heap of the initial snapshot observation.
        #[derive(Serialize)]
        struct BorrowedPage<'a, T> {
            node_id: &'a Option<String>,
            network: Option<Network>,
            next_cursor: &'a Option<String>,
            observed_at: DateTime<Utc>,
            stale: bool,
            truncated: bool,
            items: &'a [T],
        }
        let borrowed = BorrowedPage {
            node_id: &self.selector.node,
            network: self.network,
            next_cursor: &next_cursor,
            observed_at: self.observed,
            stale: false,
            truncated: self.truncated,
            items,
        };
        serialized_size(&borrowed, max_bytes)?;
        Ok(Page {
            node_id: self.selector.node.clone(),
            network: self.network,
            next_cursor,
            observed_at: self.observed,
            stale: false,
            truncated: self.truncated,
            items: items.to_vec(),
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn snapshot() -> Snapshot {
        Snapshot {
            owner: Uuid::nil(),
            selector: Selector {
                resource: "nodes",
                node: None,
                scope: String::new(),
                filters: vec![],
                limit: 1,
            },
            rows: Rows::Nodes(vec![]),
            network: None,
            observed: Utc::now(),
            expires: Utc::now(),
            truncated: false,
            tokens: vec![],
            bytes: 0,
        }
    }

    #[test]
    fn serialization_ceiling_counts_wire_bytes_and_accepts_exact_boundary() {
        let value = vec!["escaped\n\"value", "á"];
        let expected = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            serialized_size(&value, expected.len()).unwrap(),
            expected.len()
        );
        assert_eq!(bounded_json(&value, expected.len()).unwrap(), expected);
        assert_eq!(
            bounded_json(&value, expected.len() - 1).unwrap_err().code,
            ErrorCode::InternalError
        );
        assert!(serialized_size(&value, expected.len() - 1).is_err());
        let mut writer = ByteLimit {
            writer: Vec::new(),
            bytes: 0,
            max: 3,
        };
        writer.write_all(b"ab").unwrap();
        assert!(writer.write_all(b"cd").is_err());
        assert_eq!(writer.writer, b"ab");
    }

    #[test]
    fn page_envelope_is_included_and_oversized_pages_are_rejected_before_cloning() {
        #[derive(Serialize)]
        struct Counted<'a> {
            value: &'a str,
            #[serde(skip)]
            clones: &'a AtomicUsize,
        }
        impl Clone for Counted<'_> {
            fn clone(&self) -> Self {
                self.clones.fetch_add(1, Ordering::Relaxed);
                Self {
                    value: self.value,
                    clones: self.clones,
                }
            }
        }
        let clones = AtomicUsize::new(0);
        let rows = [
            Counted {
                value: "synthetic",
                clones: &clones,
            },
            Counted {
                value: "escaped\n\"",
                clones: &clones,
            },
        ];
        let snapshot = snapshot();
        let next = Some("a".repeat(64));
        let page = snapshot
            .materialize(&rows, next.clone(), usize::MAX)
            .unwrap();
        let wire = serde_json::to_vec(&page).unwrap();
        clones.store(0, Ordering::Relaxed);
        assert_eq!(
            snapshot
                .materialize(&rows, next.clone(), wire.len() - 1)
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalError
        );
        assert_eq!(clones.load(Ordering::Relaxed), 0);
        let exact = snapshot.materialize(&rows, next, wire.len()).unwrap();
        assert_eq!(serde_json::to_vec(&exact).unwrap(), wire);
        assert_eq!(clones.load(Ordering::Relaxed), rows.len());
        let oversized = "x".repeat(wire.len());
        let rows = [Counted {
            value: &oversized,
            clones: &clones,
        }];
        clones.store(0, Ordering::Relaxed);
        assert!(snapshot.materialize(&rows, None, wire.len()).is_err());
        assert_eq!(clones.load(Ordering::Relaxed), 0);
    }
}
