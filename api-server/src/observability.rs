//! JSON Lines on stderr. Only this allowlisted projection is serialized, never domain payloads.
use lightning_client::{
    model::{
        Backend, ErrorCode, ErrorOutcome, NodeKind, Operation, OperationKind, OperationStage,
        OperationState,
    },
    settings::{NodeSettings, Settings},
};
use serde::Serialize;
use std::io::Write;
use uuid::Uuid;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Method {
    Passkey,
    Nostr,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuthAction {
    SignIn,
    Enroll,
    Link,
    Unlink,
    SignOut,
    Challenge,
}

impl AuthAction {
    pub(crate) fn nostr(purpose: &str) -> Self {
        match purpose {
            "login" => Self::SignIn,
            "enrollment" => Self::Enroll,
            "link" => Self::Link,
            "unlink" => Self::Unlink,
            _ => Self::Challenge,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub(crate) enum Event<'a> {
    Startup {
        version: &'a str,
        bind: std::net::SocketAddr,
        node_count: usize,
        database: std::borrow::Cow<'a, str>,
    },
    StartupFailure {
        error_code: &'static str,
    },
    NodeRegistration {
        #[serde(serialize_with = "serialize_node_id")]
        node_id: &'a str,
        backend: Backend,
        kind: NodeKind,
        outcome: &'static str,
        error_code: Option<ErrorCode>,
    },
    ReadFailure {
        #[serde(serialize_with = "serialize_node_id")]
        node_id: &'a str,
        surface: &'static str,
        error_code: ErrorCode,
        stale: bool,
    },
    OperationTransition {
        operation_id: Uuid,
        kind: OperationKind,
        from: Option<OperationState>,
        to: OperationState,
        stage: OperationStage,
        outcome: ErrorOutcome,
    },
    Reconciliation {
        operation_id: Uuid,
        attempt: u32,
        next_delay_seconds: Option<i64>,
        exhausted: bool,
    },
    Auth {
        method: Method,
        action: AuthAction,
        outcome: &'static str,
    },
    RateLimited {
        scope: &'static str,
        retry_after_seconds: Option<u64>,
    },
    InstanceLock {
        outcome: &'static str,
    },
}

fn serialize_node_id<S: serde::Serializer>(id: &str, serializer: S) -> Result<S::Ok, S::Error> {
    // Normal IDs follow the settings slug contract. Reject token/URL-shaped mistakes too.
    let safe = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
        && !(id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        && !["lnbc", "lntb", "lnbcrt"]
            .iter()
            .any(|prefix| id.starts_with(prefix));
    serializer.serialize_str(if safe { id } else { "[redacted]" })
}

impl<'a> Event<'a> {
    pub(crate) fn startup(settings: &'a Settings, bind: std::net::SocketAddr) -> Self {
        Self::Startup {
            version: env!("CARGO_PKG_VERSION"),
            bind,
            node_count: settings.nodes.len(),
            database: settings.api.database.to_string_lossy(),
        }
    }
    pub(crate) fn registration(node: &'a NodeSettings, error_code: Option<ErrorCode>) -> Self {
        Self::NodeRegistration {
            node_id: &node.id,
            backend: node.backend,
            kind: node.kind(),
            outcome: if error_code.is_some() {
                "failure"
            } else {
                "success"
            },
            error_code,
        }
    }
    pub(crate) fn transition(from: Option<OperationState>, operation: &Operation) -> Self {
        Self::OperationTransition {
            operation_id: operation.id,
            kind: operation.request.kind(),
            from,
            to: operation.state,
            stage: operation.stage,
            outcome: operation.error.as_ref().map_or_else(
                || match operation.state {
                    OperationState::Succeeded => ErrorOutcome::NotApplicable,
                    OperationState::AwaitingConfirmation | OperationState::Expired => {
                        ErrorOutcome::NotDispatched
                    }
                    _ => ErrorOutcome::Unknown,
                },
                |error| error.outcome,
            ),
        }
    }
    fn level(&self) -> &'static str {
        match self {
            Self::StartupFailure { .. } => "error",
            Self::NodeRegistration {
                error_code: Some(_),
                ..
            }
            | Self::ReadFailure { .. }
            | Self::Reconciliation {
                exhausted: true, ..
            }
            | Self::Auth {
                outcome: "failure", ..
            }
            | Self::RateLimited { .. }
            | Self::InstanceLock { outcome: "failure" } => "warn",
            _ => "info",
        }
    }
    fn render(&self, writer: &mut impl Write) -> std::io::Result<()> {
        #[derive(Serialize)]
        struct Line<'a, 'b> {
            level: &'static str,
            #[serde(flatten)]
            event: &'a Event<'b>,
        }
        serde_json::to_writer(
            &mut *writer,
            &Line {
                level: self.level(),
                event: self,
            },
        )?;
        writer.write_all(b"\n")
    }
    pub(crate) fn emit(&self) {
        // Buffer before locking stderr: serialization failure cannot leave a partial JSON line.
        let mut line = Vec::with_capacity(256);
        if self.render(&mut line).is_ok() {
            let _ = std::io::stderr().lock().write_all(&line);
        }
    }
}

/// Failed/aborted ceremonies log once on drop, including early returns; no auth input is retained.
pub(crate) struct AuthAttempt {
    method: Method,
    action: AuthAction,
    success: bool,
}
impl AuthAttempt {
    pub(crate) fn new(method: Method, action: AuthAction) -> Self {
        Self {
            method,
            action,
            success: false,
        }
    }
    pub(crate) fn action(&mut self, action: AuthAction) {
        self.action = action;
    }
    pub(crate) fn success(&mut self) {
        self.success = true;
    }
}
impl Drop for AuthAttempt {
    fn drop(&mut self) {
        Event::Auth {
            method: self.method,
            action: self.action,
            outcome: if self.success { "success" } else { "failure" },
        }
        .emit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const SECRETS: [&str; 5] = [
        "0201036c6e6402deadbeefcafebabe00000000000000000000000000000000000000",
        "rune=SYNTHETIC_RUNE_SECRET==",
        "__Host-ld_session=SYNTHETIC_COOKIE_SECRET",
        "lnbc100n1syntheticbolt11secret",
        "https://alice:SYNTHETIC_PASSWORD@node.example.invalid:10009/?rune=SYNTHETIC_RUNE_SECRET",
    ];

    fn render(event: &Event<'_>) -> String {
        let mut output = Vec::new();
        event.render(&mut output).unwrap();
        String::from_utf8(output).unwrap()
    }

    fn assert_redacted(output: &str) {
        for secret in SECRETS {
            assert!(!output.contains(secret), "secret leaked: {output}");
        }
        for fragment in [
            "SYNTHETIC_RUNE_SECRET",
            "SYNTHETIC_COOKIE_SECRET",
            "SYNTHETIC_PASSWORD",
        ] {
            assert!(
                !output.contains(fragment),
                "secret fragment leaked: {output}"
            );
        }
    }

    fn settings() -> Settings {
        serde_json::from_value(json!({
            "api": {"bind":"127.0.0.1:8080", "public_origin":SECRETS[4], "rp_id":"example.invalid", "database":"/state/manager.sqlite", "invoice_key_file":SECRETS[0]},
            "nodes":[{"id":"node-a", "label":SECRETS.join(" "), "backend":"lnd_grpc", "endpoint":SECRETS[4], "certificate_file":SECRETS[1], "credential_file":SECRETS[2], "network":"regtest"}]
        })).unwrap()
    }

    fn operation() -> Operation {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/api-examples.json")).unwrap();
        let mut body = fixture["fixtures"]["operation_unknown"]["value"].clone();
        body["request"] = fixture["fixtures"]["pay_invoice_request"]["value"].clone();
        body["request"]["params"]["bolt11"] = json!(SECRETS[3]);
        body["error"]["message"] = json!(SECRETS.join(" "));
        body["review"]["digest"] = json!(SECRETS.join(" "));
        serde_json::from_value(body).unwrap()
    }

    #[test]
    fn startup_redacts_node_and_key_material() {
        let settings = settings();
        let output = render(&Event::startup(&settings, settings.api.bind));
        assert_redacted(&output);
        assert!(output.contains("/state/manager.sqlite"));
    }

    #[test]
    fn registration_redacts_credentials_endpoints_and_invalid_ids() {
        let mut settings = settings();
        assert_redacted(&render(&Event::registration(
            &settings.nodes[0],
            Some(ErrorCode::NodeAuthError),
        )));
        for secret in SECRETS {
            settings.nodes[0].id = secret.into();
            let output = render(&Event::registration(
                &settings.nodes[0],
                Some(ErrorCode::NotConfigured),
            ));
            assert_redacted(&output);
            assert!(output.contains("[redacted]"));
        }
    }

    #[test]
    fn read_failure_redacts_secret_bearing_node_ids() {
        for secret in SECRETS {
            assert_redacted(&render(&Event::ReadFailure {
                node_id: secret,
                surface: "payments",
                error_code: ErrorCode::NodeAuthError,
                stale: true,
            }));
        }
    }

    #[test]
    fn operation_transition_redacts_payload_and_error_message() {
        assert_redacted(&render(&Event::transition(
            Some(OperationState::Dispatching),
            &operation(),
        )));
    }

    #[test]
    fn auth_redacts_untrusted_purpose_and_has_no_identity_fields() {
        for secret in SECRETS {
            assert_redacted(&render(&Event::Auth {
                method: Method::Nostr,
                action: AuthAction::nostr(secret),
                outcome: "failure",
            }));
        }
    }

    #[test]
    fn closed_events_exclude_secret_bearing_operation_context() {
        // These events accept only typed counters/UUIDs and compile-time status literals.
        let operation = operation();
        for event in [
            Event::Reconciliation {
                operation_id: operation.id,
                attempt: 96,
                next_delay_seconds: None,
                exhausted: true,
            },
            Event::RateLimited {
                scope: "api",
                retry_after_seconds: Some(60),
            },
            Event::InstanceLock { outcome: "failure" },
            Event::StartupFailure {
                error_code: "storage_unavailable",
            },
        ] {
            assert_redacted(&render(&event));
        }
    }

    #[test]
    fn json_line_shape_pins_every_event_field() {
        let settings = settings();
        let operation = operation();
        let cases = [
            (
                Event::startup(&settings, settings.api.bind),
                "startup",
                vec!["version", "bind", "node_count", "database"],
            ),
            (
                Event::StartupFailure {
                    error_code: "configuration",
                },
                "startup_failure",
                vec!["error_code"],
            ),
            (
                Event::registration(&settings.nodes[0], None),
                "node_registration",
                vec!["node_id", "backend", "kind", "outcome", "error_code"],
            ),
            (
                Event::ReadFailure {
                    node_id: "node-a",
                    surface: "info",
                    error_code: ErrorCode::NodeOffline,
                    stale: true,
                },
                "read_failure",
                vec!["node_id", "surface", "error_code", "stale"],
            ),
            (
                Event::transition(None, &operation),
                "operation_transition",
                vec!["operation_id", "kind", "from", "to", "stage", "outcome"],
            ),
            (
                Event::Reconciliation {
                    operation_id: operation.id,
                    attempt: 1,
                    next_delay_seconds: Some(5),
                    exhausted: false,
                },
                "reconciliation",
                vec!["operation_id", "attempt", "next_delay_seconds", "exhausted"],
            ),
            (
                Event::Auth {
                    method: Method::Passkey,
                    action: AuthAction::SignIn,
                    outcome: "success",
                },
                "auth",
                vec!["method", "action", "outcome"],
            ),
            (
                Event::RateLimited {
                    scope: "api",
                    retry_after_seconds: None,
                },
                "rate_limited",
                vec!["scope", "retry_after_seconds"],
            ),
            (
                Event::InstanceLock {
                    outcome: "acquired",
                },
                "instance_lock",
                vec!["outcome"],
            ),
        ];
        for (event, name, mut fields) in cases {
            let line = render(&event);
            assert_eq!(line.lines().count(), 1);
            assert!(line.ends_with('\n'));
            let value: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(value["event"], name);
            assert_eq!(value["level"], event.level());
            fields.extend(["level", "event"]);
            fields.sort_unstable();
            assert_eq!(
                value
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                fields
            );
        }
    }

    #[test]
    fn expiry_projects_only_metadata_and_rolls_back_with_transaction() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        crate::migrations::register_functions(&connection).unwrap();
        crate::migrations::migrate(&mut connection).unwrap();
        let mut operation = operation();
        operation.state = OperationState::AwaitingConfirmation;
        operation.stage = OperationStage::NotDispatched;
        connection.execute(
            "INSERT INTO operations(id,node_id,request_key,request_digest,body) VALUES(?1,?2,?3,x'01',?4)",
            rusqlite::params![operation.id.to_string(), operation.node_id, Uuid::new_v4().to_string(), serde_json::to_string(&operation).unwrap()],
        ).unwrap();
        let now = operation.review.expires_at + chrono::Duration::seconds(1);
        let tx = connection.transaction().unwrap();
        let events = crate::journal::expire_reviews(&tx, now).unwrap();
        assert_eq!(events.len(), 1);
        let line = render(&events[0]);
        assert_redacted(&line);
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["from"], "awaiting_confirmation");
        assert_eq!(value["to"], "expired");
        assert_eq!(value["kind"], "pay_invoice");
        tx.rollback().unwrap();
        let tx = connection.transaction().unwrap();
        assert_eq!(crate::journal::expire_reviews(&tx, now).unwrap().len(), 1);
        tx.commit().unwrap();
        assert!(crate::journal::expire_reviews(&connection, now)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn broken_log_writer_returns_without_panicking() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(Event::InstanceLock {
            outcome: "acquired"
        }
        .render(&mut Broken)
        .is_err());
    }
}
