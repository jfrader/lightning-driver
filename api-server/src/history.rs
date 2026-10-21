use crate::journal::{expire_reviews, Journal, JournalError};
use chrono::{DateTime, Utc};
use lightning_client::{
    model::{Network, NodeBinding, Operation, VerifiedNetwork},
    money::Decimal,
};
use rusqlite::{functions::FunctionFlags, params, Connection, TransactionBehavior};
use sha2::{Digest, Sha256};
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
                     WHERE json_extract(body,'$.state') IN
                       ('awaiting_confirmation','dispatching','pending','unknown')
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
        self.run(move |connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            expire_reviews(&tx, Utc::now())?;
            let scope = scope(&tx, &node)?;
            let mut operations = Vec::new();
            {
                let mut statement = tx.prepare(
                    "SELECT body FROM operations WHERE node_id=?1
                     AND (?2 IS NULL OR json_extract(body,'$.state')=?2 OR
                       (?2='nonterminal' AND json_extract(body,'$.state') IN
                        ('awaiting_confirmation','dispatching','pending','unknown')))
                     AND (?3 IS NULL OR json_extract(body,'$.request.kind')=?3)
                     ORDER BY creation_seconds(json_extract(body,'$.created_at')) DESC,
                       creation_nanos(json_extract(body,'$.created_at')) DESC,id ASC LIMIT ?4",
                )?;
                let limit = i64::try_from(max.checked_add(1).ok_or(JournalError::Storage)?)
                    .map_err(|_| JournalError::Storage)?;
                let rows = statement.query_map(params![node, state, kind, limit], |row| {
                    row.get::<_, String>(0)
                })?;
                for row in rows {
                    operations.push(serde_json::from_str(&row?)?);
                }
            }
            let truncated = operations.len() > max;
            operations.truncate(max);
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
    let mut statement = connection.prepare(
        "SELECT DISTINCT json_extract(body,'$.review.node') FROM operations
         WHERE node_id=?1 ORDER BY json_extract(body,'$.review.node')",
    )?;
    let mut rows = statement.query([node])?;
    let mut hash = Sha256::new();
    let mut network = Network::Unknown;
    let mut exists = false;
    while let Some(row) = rows.next()? {
        let binding: String = row.get(0)?;
        let binding: NodeBinding = serde_json::from_str(&binding)?;
        network = if exists {
            Network::Unknown
        } else {
            match binding.network {
                VerifiedNetwork::Mainnet => Network::Mainnet,
                VerifiedNetwork::Testnet => Network::Testnet,
                VerifiedNetwork::Signet => Network::Signet,
                VerifiedNetwork::Regtest => Network::Regtest,
            }
        };
        hash.update(serde_json::to_vec(&binding)?);
        exists = true;
    }
    Ok(HistoryScope {
        exists,
        revision: hex::encode(hash.finalize()),
        network,
    })
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
