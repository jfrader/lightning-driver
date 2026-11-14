use crate::{
    error::ApiError,
    operations::{ReadQuery, ReadResult},
    registry::Entry,
    state::ApplicationState,
};
use chrono::{DateTime, Utc};
use lightning_client::model::ErrorCode;
use serde_json::Value;
use std::collections::BTreeMap;

const FLEET_REFRESH_CONCURRENCY: usize = 8;

#[cfg(test)]
mod fleet_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn slow_fleet_has_one_deadline_and_bounded_cancelled_work() {
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let active = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let begin = std::time::Instant::now();
        refresh_bounded(
            (0..100).map(|id| id.to_string()),
            std::time::Duration::from_millis(30),
            |_| {
                let active = active.clone();
                let started = started.clone();
                async move {
                    let _guard = Active(active.clone());
                    assert!(active.fetch_add(1, Ordering::SeqCst) < FLEET_REFRESH_CONCURRENCY);
                    started.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            },
        )
        .await;
        assert!(begin.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(started.load(Ordering::SeqCst), FLEET_REFRESH_CONCURRENCY);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}

struct RefreshGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

async fn refresh_bounded<I, F, Fut>(ids: I, deadline: std::time::Duration, refresh: F)
where
    I: IntoIterator<Item = String>,
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let mut tasks = tokio::task::JoinSet::new();
    let _ = tokio::time::timeout(deadline, async {
        for id in ids {
            if tasks.len() == FLEET_REFRESH_CONCURRENCY {
                tasks.join_next().await;
            }
            tasks.spawn(refresh(id));
        }
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

#[derive(Default)]
pub(crate) struct Cache {
    pub(crate) checked: Option<DateTime<Utc>>,
    values: BTreeMap<String, Observed>,
}

#[cfg(test)]
impl Cache {
    pub(crate) fn cached_for_test(&self, resource: &str) -> Option<Observed> {
        self.values.get(resource).cloned()
    }

    /// Puts a value in the cache so a test can prove it is dropped.
    pub(crate) fn seed_for_test(&mut self, resource: &'static str, bytes: usize) -> usize {
        self.values.insert(
            resource.into(),
            Observed {
                value: Value::Array(Vec::new()),
                at: Utc::now(),
                stale: false,
                truncated: false,
                bytes,
            },
        );
        self.values.values().map(|value| value.bytes).sum()
    }
}

impl Cache {
    /// Drops every cached read and returns the bytes it held.
    pub(crate) fn invalidate(&mut self) -> usize {
        self.checked = None;
        let released = self.values.values().map(|value| value.bytes).sum();
        self.values.clear();
        released
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub(crate) struct Observed {
    pub value: Value,
    pub at: DateTime<Utc>,
    pub stale: bool,
    pub truncated: bool,
    bytes: usize,
}

fn record_error(entry: &Entry, error: &ApiError, now: DateTime<Utc>) -> Result<(), ApiError> {
    *entry
        .last_error
        .lock()
        .map_err(|_| ApiError::new(ErrorCode::InternalError))? = Some((now, error.code));
    Ok(())
}

impl ApplicationState {
    pub(crate) fn schedule_fleet_refresh(&self) {
        if self
            .fleet_refreshing
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        let guard = RefreshGuard(self.fleet_refreshing.clone());
        let state = self.clone();
        let ids: Vec<_> = self
            .registry
            .entries()
            .map(|(id, _)| id.to_owned())
            .collect();
        tokio::spawn(async move {
            let _guard = guard;
            let deadline = std::time::Duration::from_secs(u64::from(state.limits().rpc_seconds));
            refresh_bounded(ids, deadline, |id| {
                let state = state.clone();
                async move {
                    let _ = state.refresh_node(&id).await;
                }
            })
            .await;
        });
    }
    async fn read_cache<'a>(
        &self,
        entry: &'a Entry,
    ) -> Result<tokio::sync::MutexGuard<'a, Cache>, ApiError> {
        tokio::time::timeout(
            std::time::Duration::from_secs(u64::from(self.limits().rpc_seconds)),
            entry.reads.lock(),
        )
        .await
        .map_err(|_| ApiError::new(ErrorCode::RateLimited))
    }
    pub(crate) async fn refresh_node(&self, id: &str) -> Result<(), ApiError> {
        let entry = self
            .registry
            .get(id)
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
        let mut cache = self.read_cache(entry).await.inspect_err(|error| {
            crate::observability::Event::ReadFailure {
                node_id: id,
                surface: "info",
                error_code: error.code,
                stale: false,
            }
            .emit();
        })?;
        let now = Utc::now();
        if cache.checked.is_some_and(|at| {
            now.signed_duration_since(at).num_seconds() < i64::from(self.limits().rpc_seconds)
        }) {
            return Ok(());
        }
        let result = self.engine.read_node(id, ReadQuery::Info).await;
        if let Err(error) = &result {
            crate::observability::Event::ReadFailure {
                node_id: id,
                surface: "info",
                error_code: error.code,
                stale: error.code != ErrorCode::RateLimited,
            }
            .emit();
        }
        match result {
            Ok((ReadResult::Info(info), revision)) => {
                *entry
                    .observation
                    .lock()
                    .map_err(|_| ApiError::new(ErrorCode::InternalError))? = Some((info, revision));
                *entry
                    .last_error
                    .lock()
                    .map_err(|_| ApiError::new(ErrorCode::InternalError))? = None;
            }
            Ok(_) => return Err(ApiError::new(ErrorCode::InternalError)),
            Err(error) if error.code == ErrorCode::RateLimited => return Err(error),
            Err(error) => record_error(entry, &error, Utc::now())?,
        }
        cache.checked = Some(Utc::now());
        Ok(())
    }

    pub(crate) async fn observed(
        &self,
        id: &str,
        resource: &'static str,
        query: ReadQuery,
    ) -> Result<Observed, ApiError> {
        if !query.is_watchtower() && !matches!(query, ReadQuery::Bitcoin | ReadQuery::BitcoinPeers)
        {
            self.refresh_node(id).await?;
        }
        let entry = self
            .registry
            .get(id)
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
        let mut cache = self.read_cache(entry).await.inspect_err(|error| {
            crate::observability::Event::ReadFailure {
                node_id: id,
                surface: resource,
                error_code: error.code,
                stale: false,
            }
            .emit();
        })?;
        let now = Utc::now();
        let key = match query {
            ReadQuery::WatchtowerTower(key) => format!("{resource}:{}", hex::encode(key)),
            _ => resource.to_owned(),
        };
        if let Some(value) = cache.values.get(&key) {
            if now.signed_duration_since(value.at).num_seconds()
                < i64::from(self.limits().rpc_seconds)
            {
                return Ok(value.clone());
            }
        }
        let result = self.engine.read_node(id, query).await;
        if let Err(error) = &result {
            let invalidates = (query.is_watchtower()
                || matches!(query, ReadQuery::Bitcoin | ReadQuery::BitcoinPeers))
                && matches!(
                    error.code,
                    ErrorCode::IdentityChanged | ErrorCode::NetworkMismatch
                );
            let stale = error.code != ErrorCode::RateLimited
                && !invalidates
                && !matches!(query, ReadQuery::WatchtowerTower(_))
                && cache.values.contains_key(&key);
            crate::observability::Event::ReadFailure {
                node_id: id,
                surface: resource,
                error_code: error.code,
                stale,
            }
            .emit();
        }
        let result = match result {
            Ok((value, _)) => value,
            Err(error) if error.code == ErrorCode::RateLimited => return Err(error),
            Err(error)
                if (query.is_watchtower()
                    || matches!(query, ReadQuery::Bitcoin | ReadQuery::BitcoinPeers))
                    && matches!(
                        error.code,
                        ErrorCode::IdentityChanged | ErrorCode::NetworkMismatch
                    ) =>
            {
                let released = cache.invalidate();
                self.registry.release_retained_bytes(released);
                return Err(error);
            }
            Err(error) => {
                if matches!(query, ReadQuery::WatchtowerTower(_)) {
                    // Tower detail cannot label an expired observation as stale.
                    return Err(error);
                }
                return cache
                    .values
                    .get(&key)
                    .cloned()
                    .map(|mut value| {
                        value.stale = true;
                        value
                    })
                    .ok_or(error);
            }
        };
        let (value, truncated) = match result {
            ReadResult::Balances(value) => (serde_json::to_value(value), false),
            ReadResult::Fees(value) => (serde_json::to_value(value), false),
            ReadResult::Bitcoin(value) => (serde_json::to_value(value), false),
            ReadResult::WatchtowerServer(value) => (serde_json::to_value(value), false),
            ReadResult::WatchtowerClient(value) => (serde_json::to_value(value), false),
            ReadResult::WatchtowerTower(value) => (serde_json::to_value(value), false),
            ReadResult::WatchtowerTowers(value) => {
                (serde_json::to_value(value.items), value.truncated)
            }
            ReadResult::BitcoinPeers(value) => (serde_json::to_value(value.items), value.truncated),
            ReadResult::Invoices(value) => (serde_json::to_value(value.items), value.truncated),
            ReadResult::Payments(value) => (serde_json::to_value(value.items), value.truncated),
            ReadResult::Peers(value) => (serde_json::to_value(value.items), value.truncated),
            ReadResult::Channels(value) => (serde_json::to_value(value.items), value.truncated),
            ReadResult::Transactions(value) => (serde_json::to_value(value.items), value.truncated),
            ReadResult::Info(_) => return Err(ApiError::new(ErrorCode::InternalError)),
        };
        let value = value.map_err(|_| ApiError::new(ErrorCode::InternalError))?;
        let bytes =
            crate::pagination::bounded_json(&value, self.limits().max_response_bytes)?.len();
        let observed = Observed {
            value,
            at: Utc::now(),
            stale: false,
            truncated,
            bytes,
        };
        let replaced = cache.values.get(&key).map_or(0, |value| value.bytes);
        if !self.registry.replace_retained_bytes(
            replaced,
            bytes,
            self.limits().snapshot_cache_bytes,
        ) {
            return Err(ApiError::new(ErrorCode::RateLimited));
        }
        cache.values.insert(key, observed.clone());
        Ok(observed)
    }
}
