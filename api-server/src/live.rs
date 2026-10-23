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

#[derive(Default)]
pub(crate) struct Cache {
    pub(crate) checked: Option<DateTime<Utc>>,
    values: BTreeMap<String, Observed>,
}

#[cfg(test)]
impl Cache {
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
