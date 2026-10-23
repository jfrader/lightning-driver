use crate::journal::JournalError;
use chrono::{DateTime, Utc};
use rusqlite::{functions::FunctionFlags, Connection, TransactionBehavior};
use sha2::{Digest, Sha256};

// Version zero is the accepted, unversioned journal schema.
const BASELINE: &str = "
CREATE TABLE IF NOT EXISTS auth_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), operator_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation>=0));
CREATE TABLE IF NOT EXISTS credentials (credential_id TEXT PRIMARY KEY, passkey TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS enrollment (token_hash BLOB PRIMARY KEY, generation INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, node_id TEXT NOT NULL, request_key TEXT NOT NULL, request_digest BLOB NOT NULL, body TEXT NOT NULL, dispatched INTEGER NOT NULL DEFAULT 0, UNIQUE(node_id,request_key));
CREATE TABLE IF NOT EXISTS resource_claims (node_id TEXT NOT NULL, resource TEXT NOT NULL, operation_id TEXT NOT NULL REFERENCES operations(id), PRIMARY KEY(node_id,resource));
CREATE TABLE IF NOT EXISTS pending_invoice_secrets (operation_id TEXT PRIMARY KEY REFERENCES operations(id), ciphertext BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS operations_node ON operations(node_id);";

const METADATA: &str = "
ALTER TABLE operations ADD COLUMN created_at_ns INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operations ADD COLUMN updated_at_ns INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operations ADD COLUMN kind TEXT NOT NULL DEFAULT '';
ALTER TABLE operations ADD COLUMN state TEXT NOT NULL DEFAULT '';
ALTER TABLE operations ADD COLUMN terminal INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operations ADD COLUMN sensitivity INTEGER NOT NULL DEFAULT 0;
CREATE TABLE history_bindings (node_id TEXT NOT NULL, binding TEXT NOT NULL, PRIMARY KEY(node_id,binding));
CREATE TABLE history_scope (node_id TEXT PRIMARY KEY, revision TEXT NOT NULL, network TEXT NOT NULL);
CREATE TRIGGER history_binding_insert AFTER INSERT ON history_bindings BEGIN
  INSERT INTO history_scope(node_id,revision,network)
    VALUES(NEW.node_id,'',json_extract(NEW.binding,'$.network'))
    ON CONFLICT(node_id) DO UPDATE SET network='unknown';
  UPDATE history_scope SET revision=history_revision(
    (SELECT json_group_array(binding) FROM
      (SELECT binding FROM history_bindings WHERE node_id=NEW.node_id ORDER BY binding)))
    WHERE node_id=NEW.node_id;
END;
CREATE TRIGGER operation_metadata_insert AFTER INSERT ON operations BEGIN
  UPDATE operations SET
    created_at_ns=timestamp_ns(json_extract(NEW.body,'$.created_at')),
    updated_at_ns=timestamp_ns(json_extract(NEW.body,'$.updated_at')),
    kind=json_extract(NEW.body,'$.request.kind'),
    state=json_extract(NEW.body,'$.state'),
    terminal=json_extract(NEW.body,'$.state') IN ('succeeded','failed','expired'),
    sensitivity=json_extract(NEW.body,'$.review.sensitive')
    WHERE id=NEW.id;
  INSERT OR IGNORE INTO history_bindings(node_id,binding)
    VALUES(NEW.node_id,json_extract(NEW.body,'$.review.node'));
END;
CREATE TRIGGER operation_metadata_update AFTER UPDATE OF body ON operations BEGIN
  UPDATE operations SET
    created_at_ns=timestamp_ns(json_extract(NEW.body,'$.created_at')),
    updated_at_ns=timestamp_ns(json_extract(NEW.body,'$.updated_at')),
    kind=json_extract(NEW.body,'$.request.kind'),
    state=json_extract(NEW.body,'$.state'),
    terminal=json_extract(NEW.body,'$.state') IN ('succeeded','failed','expired'),
    sensitivity=json_extract(NEW.body,'$.review.sensitive')
    WHERE id=NEW.id;
  INSERT OR IGNORE INTO history_bindings(node_id,binding)
    VALUES(NEW.node_id,json_extract(NEW.body,'$.review.node'));
END;
UPDATE operations SET body=body;
CREATE INDEX operations_history ON operations(node_id,created_at_ns DESC,id ASC);
CREATE INDEX operations_state ON operations(state,created_at_ns DESC);
CREATE INDEX operations_state_history ON operations(node_id,state,created_at_ns DESC,id ASC);
CREATE INDEX operations_kind_history ON operations(node_id,kind,created_at_ns DESC,id ASC);
CREATE INDEX operations_kind_state_history ON operations(node_id,kind,state,created_at_ns DESC,id ASC);
CREATE INDEX operations_terminal ON operations(terminal,node_id);
CREATE INDEX operations_nonterminal_history ON operations(node_id,terminal,created_at_ns DESC,id ASC);
CREATE INDEX operations_kind_nonterminal_history ON operations(node_id,kind,terminal,created_at_ns DESC,id ASC);
";

const ENGINE: &str = "
CREATE TABLE operation_intents (
 operation_id TEXT PRIMARY KEY REFERENCES operations(id),
 encoding_version INTEGER NOT NULL CHECK(encoding_version IN (0,1)),
 intent TEXT,
 claim_id TEXT UNIQUE,
 next_sequence INTEGER NOT NULL DEFAULT 0,
 evidence TEXT
);
INSERT INTO operation_intents(operation_id,encoding_version) SELECT id,0 FROM operations;
CREATE TABLE paid_hashes (
 node_id TEXT NOT NULL, payment_hash TEXT NOT NULL,
 operation_id TEXT NOT NULL REFERENCES operations(id),
 PRIMARY KEY(node_id,payment_hash)
);
INSERT OR IGNORE INTO paid_hashes(node_id,payment_hash,operation_id)
 SELECT node_id,json_extract(body,'$.review.payment_hash'),id FROM operations
 WHERE kind='pay_invoice' AND state='succeeded'
 AND json_extract(body,'$.review.payment_hash') IS NOT NULL;
";

const NOSTR: &str = "
CREATE TABLE nostr_identities (
 pubkey TEXT PRIMARY KEY CHECK(length(pubkey)=64 AND pubkey NOT GLOB '*[^0-9a-f]*'),
 npub TEXT NOT NULL, label TEXT, created_at INTEGER NOT NULL, last_used_at INTEGER
);
CREATE TABLE nostr_challenges (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, generation INTEGER NOT NULL,
 nonce_hash BLOB NOT NULL, binding TEXT NOT NULL, expires_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE nostr_replays (event_id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
";

const MIGRATIONS: &[&str] = &[BASELINE, METADATA, ENGINE, NOSTR];

pub(crate) fn register_functions(connection: &Connection) -> Result<(), JournalError> {
    connection.create_scalar_function(
        "history_revision",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |context| {
            let text: String = context.get(0)?;
            let hash = || -> Result<String, serde_json::Error> {
                let bindings: Vec<String> = serde_json::from_str(&text)?;
                let mut hash = Sha256::new();
                for binding in bindings {
                    let binding: lightning_client::model::NodeBinding =
                        serde_json::from_str(&binding)?;
                    hash.update(serde_json::to_vec(&binding)?);
                }
                Ok(hex::encode(hash.finalize()))
            };
            hash().map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))
        },
    )?;
    connection.create_scalar_function(
        "timestamp_ns",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |context| {
            let text: String = context.get(0)?;
            let time: DateTime<Utc> = text
                .parse()
                .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
            time.timestamp_nanos_opt().ok_or_else(|| {
                rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other(
                    "Timestamp outside storage range",
                )))
            })
        },
    )?;
    Ok(())
}

pub(crate) fn migrate(connection: &mut Connection) -> Result<(), JournalError> {
    apply(connection, MIGRATIONS)
}

fn apply(connection: &mut Connection, migrations: &[&str]) -> Result<(), JournalError> {
    // An immediate transaction also serializes version inspection with another opener.
    loop {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let version = usize::try_from(version).map_err(|_| JournalError::Storage)?;
        if version > migrations.len() {
            return Err(JournalError::Storage);
        }
        let Some(migration) = migrations.get(version) else {
            return Ok(());
        };
        tx.execute_batch(migration)?;
        tx.pragma_update(
            None,
            "user_version",
            i64::try_from(version + 1).map_err(|_| JournalError::Storage)?,
        )?;
        tx.commit()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightning_client::model::{Operation, OperationState};
    use rusqlite::params;
    use std::os::unix::fs::PermissionsExt;
    use uuid::Uuid;

    #[test]
    fn version_two_checkpoint_upgrade_keeps_legacy_review_and_claim_bytes() {
        let mut connection = Connection::open_in_memory().unwrap();
        register_functions(&connection).unwrap();
        apply(&mut connection, &MIGRATIONS[..2]).unwrap();
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/api-examples.json")).unwrap();
        let operation: Operation =
            serde_json::from_value(fixtures["fixtures"]["operation_review"]["value"].clone())
                .unwrap();
        let body = serde_json::to_string(&operation).unwrap();
        let id = operation.id.to_string();
        connection.execute("INSERT INTO operations(id,node_id,request_key,request_digest,body,dispatched) VALUES(?1,?2,'checkpoint-key',x'0102',?3,1)",params![id,operation.node_id,body]).unwrap();
        connection
            .execute(
                "INSERT INTO resource_claims VALUES(?1,'wallet',?2)",
                params![operation.node_id, id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO pending_invoice_secrets VALUES(?1,x'030405')",
                [&id],
            )
            .unwrap();
        migrate(&mut connection).unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            i64::try_from(MIGRATIONS.len()).unwrap()
        );
        let row: (String, Vec<u8>, bool) = connection
            .query_row(
                "SELECT body,request_digest,dispatched FROM operations WHERE id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, (body, vec![1, 2], true));
        let provenance:(i64,Option<String>,Option<String>)=connection.query_row("SELECT encoding_version,intent,claim_id FROM operation_intents WHERE operation_id=?1",[&id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
        assert_eq!(provenance, (0, None, None));
        assert_eq!(
            connection
                .query_row(
                    "SELECT hex(ciphertext) FROM pending_invoice_secrets WHERE operation_id=?1",
                    [&id],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "030405"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM resource_claims WHERE operation_id=?1",
                    [&id],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn checkpoint_upgrade_preserves_rows_and_backfills_exact_metadata() {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = directory.path().join("checkpoint.sqlite");
        let connection = Connection::open(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        // This is precisely the schema used by the unversioned accepted checkpoint.
        connection.execute_batch(BASELINE).unwrap();
        connection
            .execute(
                "INSERT INTO auth_meta VALUES(1,?1,7)",
                [Uuid::nil().to_string()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO credentials VALUES('synthetic-id','synthetic-passkey')",
                [],
            )
            .unwrap();
        connection
            .execute("INSERT INTO enrollment VALUES(x'01',7,42)", [])
            .unwrap();
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/api-examples.json")).unwrap();
        let template: Operation =
            serde_json::from_value(fixtures["fixtures"]["operation_review"]["value"].clone())
                .unwrap();
        let mut expected = Vec::new();
        for (index, state) in [
            OperationState::AwaitingConfirmation,
            OperationState::Dispatching,
            OperationState::Pending,
            OperationState::Unknown,
            OperationState::Succeeded,
            OperationState::Failed,
            OperationState::Expired,
        ]
        .into_iter()
        .enumerate()
        {
            let mut operation = template.clone();
            operation.id = Uuid::new_v4();
            operation.review.operation_id = operation.id;
            operation.created_at += chrono::Duration::nanoseconds(i64::try_from(index).unwrap());
            operation.updated_at = operation.created_at + chrono::Duration::nanoseconds(1);
            operation.state = state;
            let body = serde_json::to_string(&operation).unwrap();
            connection.execute("INSERT INTO operations(id,node_id,request_key,request_digest,body,dispatched) VALUES(?1,?2,?3,x'02',?4,?5)", params![operation.id.to_string(), operation.node_id, Uuid::new_v4().to_string(), body, index != 0]).unwrap();
            expected.push((operation, body));
        }
        let id = expected[1].0.id.to_string();
        connection
            .execute(
                "INSERT INTO resource_claims VALUES('lnd-lab','wallet',?1)",
                [&id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO pending_invoice_secrets VALUES(?1,x'0304')",
                [&id],
            )
            .unwrap();
        drop(connection);
        let journal = crate::journal::Journal::open(path.clone()).await.unwrap();
        assert_eq!(journal.authentication().await.unwrap(), (Uuid::nil(), 7));
        journal.run(move |connection| {
            assert_eq!(connection.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))?, i64::try_from(MIGRATIONS.len()).unwrap());
            for (operation, body) in expected {
                let (stored, created, updated, kind, state, terminal, sensitive, dispatched): (String,i64,i64,String,String,bool,bool,bool) = connection.query_row("SELECT body,created_at_ns,updated_at_ns,kind,state,terminal,sensitivity,dispatched FROM operations WHERE id=?1", [operation.id.to_string()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)))?;
                assert_eq!(stored, body);
                assert_eq!(created, operation.created_at.timestamp_nanos_opt().unwrap());
                assert_eq!(updated, operation.updated_at.timestamp_nanos_opt().unwrap());
                assert_eq!(kind, serde_json::to_value(&operation.request)?["kind"].as_str().unwrap());
                assert_eq!(state, serde_json::to_value(operation.state)?.as_str().unwrap());
                assert_eq!(terminal, operation.state.terminal());
                assert_eq!(sensitive, operation.review.sensitive);
                assert_eq!(dispatched, operation.state != OperationState::AwaitingConfirmation);
            }
            for table in ["credentials", "enrollment", "resource_claims", "pending_invoice_secrets"] {
                assert_eq!(connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get::<_, i64>(0))?, 1);
            }
            assert_eq!(connection.query_row("SELECT hex(ciphertext) FROM pending_invoice_secrets", [], |row| row.get::<_, String>(0))?, "0304");
            Ok(())
        }).await.unwrap();
        crate::journal::Journal::open(path).await.unwrap();
    }

    #[test]
    fn failed_backfill_rolls_back_all_metadata_and_scope() {
        let mut connection = Connection::open_in_memory().unwrap();
        register_functions(&connection).unwrap();
        apply(&mut connection, &[BASELINE]).unwrap();
        connection
            .execute(
                "INSERT INTO operations VALUES('id','node','key',x'01','invalid json',0)",
                [],
            )
            .unwrap();
        assert!(migrate(&mut connection).is_err());
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(connection
            .prepare("SELECT created_at_ns FROM operations")
            .is_err());
        assert!(connection.prepare("SELECT * FROM history_scope").is_err());
        assert_eq!(
            connection
                .query_row("SELECT body FROM operations", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "invalid json"
        );
    }

    #[test]
    fn history_queries_use_filter_and_order_indexes_without_temporary_sort() {
        let mut connection = Connection::open_in_memory().unwrap();
        register_functions(&connection).unwrap();
        migrate(&mut connection).unwrap();
        for (filter, index) in [
            ("", "operations_history"),
            (" AND state='pending'", "operations_state_history"),
            (" AND kind='pay_invoice'", "operations_kind_history"),
            (
                " AND kind='pay_invoice' AND state='pending'",
                "operations_kind_state_history",
            ),
            (" AND terminal=0", "operations_nonterminal_history"),
            (
                " AND kind='pay_invoice' AND terminal=0",
                "operations_kind_nonterminal_history",
            ),
        ] {
            let sql = format!("EXPLAIN QUERY PLAN SELECT body FROM operations WHERE node_id='synthetic'{filter} ORDER BY created_at_ns DESC,id ASC LIMIT 4");
            let plan = connection
                .prepare(&sql)
                .unwrap()
                .query_map([], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .join("\n");
            assert!(plan.contains(index), "{plan}");
            assert!(!plan.contains("TEMP B-TREE"), "{plan}");
        }
    }

    #[test]
    fn migration_failure_rolls_back_schema_data_and_version() {
        let mut connection = Connection::open_in_memory().unwrap();
        let migrations = ["CREATE TABLE preserved (value TEXT); INSERT INTO preserved VALUES('kept');", "ALTER TABLE preserved ADD COLUMN extra TEXT; DELETE FROM preserved; SELECT missing FROM absent;"];
        assert!(apply(&mut connection, &migrations).is_err());
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT value FROM preserved", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "kept"
        );
        assert!(connection.prepare("SELECT extra FROM preserved").is_err());
    }

    #[test]
    fn newer_database_is_refused_without_mutation() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(
                None,
                "user_version",
                i64::try_from(MIGRATIONS.len() + 1).unwrap(),
            )
            .unwrap();
        assert!(migrate(&mut connection).is_err());
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM sqlite_master", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
