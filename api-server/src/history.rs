use crate::journal::{expire_reviews, Journal, JournalError};
use chrono::{DateTime, Utc};
use lightning_client::{
    model::{Network, Operation},
    money::Decimal,
};
use rusqlite::{functions::FunctionFlags, Connection, TransactionBehavior};
use sha2::Digest;
use std::collections::BTreeMap;

pub struct HistoryScope {
    pub exists: bool,
    pub revision: String,
    pub network: Network,
}

pub struct HistoryObservation {
    pub scope: HistoryScope,
    pub operations: Vec<Operation>,
    pub truncated: bool,
}

impl Journal {
    pub async fn unresolved_counts(&self) -> Result<BTreeMap<String, Decimal>, JournalError> {
        self.run(|connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            expire_reviews(&tx, Utc::now())?;
            let counts = {
                let mut statement = tx.prepare(
                    "SELECT node_id,COUNT(*)
                     FROM operations
                     WHERE terminal=0
                     GROUP BY node_id",
                )?;
                let mut rows = statement.query([])?;
                let mut counts = BTreeMap::new();
                while let Some(row) = rows.next()? {
                    let count: i64 = row.get(1)?;
                    let count =
                        Decimal::new(u64::try_from(count).map_err(|_| JournalError::Storage)?)
                            .map_err(|_| JournalError::Storage)?;
                    counts.insert(row.get(0)?, count);
                }
                counts
            };
            tx.commit()?;
            Ok(counts)
        })
        .await
    }

    pub async fn history_scope(&self, node: String) -> Result<HistoryScope, JournalError> {
        self.run(move |connection| scope(connection, &node)).await
    }

    pub async fn history(
        &self,
        node: String,
        state: Option<String>,
        kind: Option<String>,
        max: usize,
    ) -> Result<(Vec<Operation>, bool), JournalError> {
        let observation = self.history_observation(node, state, kind, max).await?;
        Ok((observation.operations, observation.truncated))
    }

    pub async fn history_observation(
        &self,
        node: String,
        state: Option<String>,
        kind: Option<String>,
        max: usize,
    ) -> Result<HistoryObservation, JournalError> {
        self.history_observation_bounded(node, state, kind, max, usize::MAX)
            .await
    }

    pub async fn history_observation_bounded(
        &self,
        node: String,
        state: Option<String>,
        kind: Option<String>,
        max: usize,
        max_record_bytes: usize,
    ) -> Result<HistoryObservation, JournalError> {
        self.run(move |connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            expire_reviews(&tx, Utc::now())?;
            let scope = scope(&tx, &node)?;
            let mut operations = Vec::new();
            let truncated = {
                let mut sql = "SELECT body FROM operations WHERE node_id=?1".to_string();
                let mut values = vec![rusqlite::types::Value::Text(node)];
                if let Some(state) = state {
                    if state == "nonterminal" {
                        sql.push_str(" AND terminal=0");
                    } else {
                        values.push(state.into());
                        sql.push_str(&format!(" AND state=?{}", values.len()));
                    }
                }
                if let Some(kind) = kind {
                    values.push(kind.into());
                    sql.push_str(&format!(" AND kind=?{}", values.len()));
                }
                let limit = i64::try_from(max.checked_add(1).ok_or(JournalError::Storage)?)
                    .map_err(|_| JournalError::Storage)?;
                values.push(limit.into());
                sql.push_str(&format!(
                    " ORDER BY created_at_ns DESC,id ASC LIMIT ?{}",
                    values.len()
                ));
                let mut statement = tx.prepare(&sql)?;
                let mut rows = statement.query(rusqlite::params_from_iter(values))?;
                let mut truncated = false;
                while let Some(row) = rows.next()? {
                    if operations.len() == max {
                        truncated = true;
                        break;
                    }
                    let body = row
                        .get_ref(0)?
                        .as_str()
                        .map_err(|_| JournalError::Storage)?;
                    if body.len() > max_record_bytes {
                        return Err(JournalError::ResponseTooLarge);
                    }
                    operations.push(serde_json::from_str(body)?);
                }
                truncated
            };
            tx.commit()?;
            Ok(HistoryObservation {
                scope,
                operations,
                truncated,
            })
        })
        .await
    }
}

fn scope(connection: &Connection, node: &str) -> Result<HistoryScope, JournalError> {
    use rusqlite::OptionalExtension;
    let stored: Option<(String, String)> = connection
        .query_row(
            "SELECT revision,network FROM history_scope WHERE node_id=?1",
            [node],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match stored {
        Some((revision, network)) => Ok(HistoryScope {
            exists: true,
            revision,
            network: serde_json::from_value(serde_json::Value::String(network))?,
        }),
        None => Ok(HistoryScope {
            exists: false,
            revision: hex::encode(sha2::Sha256::digest([])),
            network: Network::Unknown,
        }),
    }
}

pub(crate) fn register_time_functions(connection: &Connection) -> Result<(), JournalError> {
    for (name, nanos) in [("creation_seconds", false), ("creation_nanos", true)] {
        connection.create_scalar_function(
            name,
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            move |context| {
                let text: String = context.get(0)?;
                let time: DateTime<Utc> = text
                    .parse()
                    .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
                Ok(if nanos {
                    i64::from(time.timestamp_subsec_nanos())
                } else {
                    time.timestamp()
                })
            },
        )?;
    }
    Ok(())
}
