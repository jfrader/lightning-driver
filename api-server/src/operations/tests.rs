use super::*;
#[path = "http_tests.rs"]
mod operations_http;
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{Secp256k1, SecretKey},
};
use evidence::{Class, Facts, Rejection};
use lightning_client::{
    money::{Decimal, Msat, Sat},
    settings::{ApiSettings, Limits, ReauthPolicy},
};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use std::{
    collections::{HashMap, VecDeque},
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicUsize, Ordering},
};
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};

const KINDS: [OperationKind; 8] = [
    OperationKind::CreateInvoice,
    OperationKind::PayInvoice,
    OperationKind::ConnectPeer,
    OperationKind::DisconnectPeer,
    OperationKind::OpenChannel,
    OperationKind::CloseChannel,
    OperationKind::NewAddress,
    OperationKind::SendOnchain,
];

#[tokio::test]
async fn reconciliation_unknown_interval_budget_and_restart_never_redispatch() {
    let mut f = Fixture::new().await;
    let op = f.create(OperationKind::OpenChannel).await;
    let grant = f.authorize(&op).await;
    *f.fake.execute.lock().unwrap() = Script::Lost;
    f.confirm(&op, grant).await.unwrap();
    for attempt in 1..=RECONCILIATION_ATTEMPTS {
        f.fake.script(Script::Absent);
        let observed = f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
        assert_eq!(observed.state, OperationState::Unknown);
        assert_eq!(observed.stage, OperationStage::Reconciling);
        let reconciliation = observed.reconciliation.unwrap();
        assert_eq!(reconciliation.attempts, attempt);
        assert_eq!(reconciliation.exhausted, attempt == RECONCILIATION_ATTEMPTS);
        assert_eq!(
            reconciliation.last_outcome,
            Some(ReconciliationOutcome::NotFound)
        );
        let before = f.fake.counts();
        f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
        assert_eq!(f.fake.counts(), before);
        f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
        if attempt == 1 {
            f.reopen().await;
        }
    }
    f.reopen().await;
    for _ in 0..3 {
        f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
        let observed = f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
        assert!(observed.reconciliation.unwrap().exhausted);
    }
    assert_eq!(f.fake.counts(), (1, RECONCILIATION_ATTEMPTS as usize));
    assert!(f.stored(op.id).await.1 > 0);
}

#[tokio::test]
async fn reconciliation_open_resolves_after_absence_and_failed_read() {
    let mut f = Fixture::new().await;
    let op = f.create(OperationKind::OpenChannel).await;
    let grant = f.authorize(&op).await;
    *f.fake.execute.lock().unwrap() = Script::ReferencedLost;
    f.confirm(&op, grant).await.unwrap();
    for script in [Script::Absent, Script::Lost] {
        f.fake.script(script);
        let observed = f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
        assert_eq!(observed.state, OperationState::Unknown);
        f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
    }
    let observed = f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
    assert_eq!(observed.state, OperationState::Succeeded);
    assert_eq!(observed.stage, OperationStage::ChannelActive);
    assert!(observed.last_reconciled_at.is_some());
    assert_eq!(f.fake.counts(), (1, 3));
    assert_eq!(f.stored(op.id).await.1, 0);
}

#[tokio::test]
async fn reconciliation_exact_open_failure_releases_once_without_redispatch() {
    let mut f = Fixture::new().await;
    let op = f.create(OperationKind::OpenChannel).await;
    let grant = f.authorize(&op).await;
    *f.fake.execute.lock().unwrap() = Script::ReferencedLost;
    f.confirm(&op, grant).await.unwrap();
    f.fake.script(Script::Reject);
    let observed = f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
    assert_eq!(observed.state, OperationState::Failed);
    assert_eq!(observed.error.unwrap().code, ErrorCode::UpstreamRejected);
    assert_eq!(f.stored(op.id).await.1, 0);
    f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
    f.fake.script(Script::Reject);
    f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
    assert_eq!(f.stored(op.id).await.1, 0);
    assert_eq!(f.fake.counts().0, 1);
}

#[tokio::test]
async fn reconciliation_list_is_node_scoped_and_capped() {
    let mut f = Fixture::new().await;
    *f.fake.execute.lock().unwrap() = Script::Lost;
    for index in 0..LIST_RECONCILIATION_CAP + 2 {
        let mut input = request(OperationKind::CreateInvoice, f.clock.now());
        if let OperationRequest::CreateInvoice(params) = &mut input {
            params.description = format!("invoice {index}");
        }
        let op = f
            .engine
            .create_review(&f.context, &f.node, Uuid::new_v4(), input)
            .await
            .unwrap();
        let grant = f.authorize(&op).await;
        f.confirm(&op, grant).await.unwrap();
    }
    f.engine.observe_list(&f.context, &f.node).await.unwrap();
    assert_eq!(f.fake.counts().1, LIST_RECONCILIATION_CAP);
    f.engine.observe_list(&f.context, "removed").await.unwrap();
    assert_eq!(f.fake.counts().1, LIST_RECONCILIATION_CAP);
}

struct TestClock(Mutex<DateTime<Utc>>);
impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}
impl TestClock {
    fn advance(&self, seconds: i64) {
        *self.0.lock().unwrap() += chrono::Duration::seconds(seconds);
    }
}

#[derive(Clone, Copy)]
enum Script {
    Success,
    Lost,
    ReferencedLost,
    Absent,
    Partial,
    Pruned,
    Conflict,
    Reject,
    Accepted,
    Confirmations(u64),
    WrongReference,
    OldGroup,
    PaidElsewhere,
}
struct CountingFake {
    mutations: AtomicUsize,
    observations: AtomicUsize,
    preparations: AtomicUsize,
    config: NodeConfig,
    clock: Arc<TestClock>,
    execute: Mutex<Script>,
    scripts: Mutex<VecDeque<Script>>,
    effects: Mutex<HashMap<Uuid, Evidence>>,
    execution_barrier: Mutex<Option<Arc<tokio::sync::Barrier>>>,
    prerequisites: Mutex<Option<ReadFacts>>,
}
impl CountingFake {
    fn counts(&self) -> (usize, usize) {
        (
            self.mutations.load(Ordering::SeqCst),
            self.observations.load(Ordering::SeqCst),
        )
    }
    fn script(&self, script: Script) {
        self.scripts.lock().unwrap().push_back(script);
    }
    fn success(&self, permit: &ClaimPermit) -> Evidence {
        let op = &permit.intent.operation;
        let mut reference = RecoveryReference::planned(&permit.intent);
        let txid = hex::encode(sha256::Hash::hash(op.id.as_bytes()).to_byte_array());
        let facts = match &op.request {
            OperationRequest::CreateInvoice(p) => {
                let preimage = permit.secret.as_ref().map_or([77; 32], |secret| **secret);
                let bolt11 = invoice(
                    p.amount_msat.0.get(),
                    &p.description,
                    op.created_at,
                    p.expiry_seconds,
                    preimage,
                );
                let decoded =
                    lightning_client::validation::decode(&bolt11, Network::Regtest, op.created_at)
                        .unwrap();
                assert_eq!(decoded.amount_msat, Some(p.amount_msat));
                if let Some(hash) = &op.review.payment_hash {
                    assert_eq!(&decoded.payment_hash, hash);
                }
                reference.payment_hash = Some(decoded.payment_hash.clone());
                Facts::Invoice {
                    payment_hash: decoded.payment_hash,
                    bolt11,
                }
            }
            OperationRequest::PayInvoice(_) => {
                reference.attempt = Some(format!("attempt-{}", permit.claim_id));
                Facts::Payment {
                    payment_hash: op.review.payment_hash.clone().unwrap(),
                    amount_msat: op.review.amount_msat.unwrap(),
                    fee_msat: Some(Msat(Decimal::ZERO)),
                    settled: true,
                }
            }
            OperationRequest::ConnectPeer(p) => Facts::Peer {
                pubkey: p.pubkey.clone(),
                connected: true,
                complete: true,
            },
            OperationRequest::DisconnectPeer(p) => Facts::Peer {
                pubkey: p.pubkey.clone(),
                connected: false,
                complete: true,
            },
            OperationRequest::OpenChannel(_) => {
                reference.channel = Some(format!("{txid}:0"));
                Facts::Open {
                    channel_id: Some(format!("channel-{}", op.id)),
                    funding_outpoint: reference.channel.clone(),
                    active: true,
                    published: true,
                }
            }
            OperationRequest::CloseChannel(_) => Facts::Close {
                channel: reference.channel.clone().unwrap(),
                close_type: CloseType::Cooperative,
                txids: vec![txid],
                confirmations: Some(Decimal::ZERO),
                closed: true,
                published: true,
            },
            OperationRequest::NewAddress(_) => {
                let address = test_address();
                reference.address = Some(address.clone());
                Facts::Address { address }
            }
            OperationRequest::SendOnchain(p) => {
                reference.txid = Some(txid.clone());
                Facts::Send {
                    txid,
                    amount_sat: p.amount_sat,
                    fee_sat: None,
                    confirmations: Some(Decimal::ZERO),
                    published: true,
                }
            }
        };
        Evidence {
            operation_id: op.id,
            binding: op.review.node.clone(),
            generation: permit.intent.connection_generation,
            kind: op.request.kind(),
            claim_id: permit.claim_id,
            sequence: 0,
            reference,
            class: Class::Positive,
            facts: Some(facts),
        }
    }
    fn modify(mut evidence: Evidence, script: Script) -> Evidence {
        match script {
            Script::Success => {}
            Script::Lost | Script::ReferencedLost => {
                evidence.class = Class::Lost;
                evidence.facts = None;
            }
            Script::Absent => {
                evidence.class = Class::NotFound;
                evidence.facts = None;
            }
            Script::Partial => {
                evidence.class = Class::Partial;
                evidence.facts = None;
            }
            Script::Pruned => {
                evidence.class = Class::Pruned;
                evidence.facts = None;
            }
            Script::Conflict => {
                evidence.class = Class::Conflict;
                evidence.facts = None;
            }
            Script::Reject => {
                evidence.class = Class::Rejected(Rejection::Refused);
                evidence.facts = None;
            }
            Script::PaidElsewhere => {
                evidence.class = Class::PaidElsewhere;
                evidence.facts = None;
            }
            Script::WrongReference => {
                evidence.reference.txid = Some("ff".repeat(32));
            }
            Script::OldGroup => {
                evidence.reference.attempt = Some("older-unrelated-attempt".into());
                evidence.class = Class::Rejected(Rejection::NoRoute);
                evidence.facts = None;
            }
            Script::Confirmations(count) => match &mut evidence.facts {
                Some(Facts::Send { confirmations, .. } | Facts::Close { confirmations, .. }) => {
                    *confirmations = Some(Decimal::new(count).unwrap())
                }
                _ => panic!("confirmation script on non-chain operation"),
            },
            Script::Accepted => match &mut evidence.facts {
                Some(Facts::Payment { settled, .. }) => *settled = false,
                Some(Facts::Open { active, .. }) => *active = false,
                Some(Facts::Close {
                    closed, close_type, ..
                }) => {
                    *closed = false;
                    *close_type = CloseType::Unknown;
                }
                Some(Facts::Send { published, .. }) => *published = false,
                _ => {}
            },
        }
        evidence
    }
}
impl Adapter for CountingFake {
    fn prepare<'a>(&'a self, _: &'a OperationRequest) -> ResponseFuture<'a, Result<ReadFacts>> {
        self.preparations.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if let Some(facts) = self.prerequisites.lock().unwrap().clone() {
                return Ok(facts);
            }
            Ok(ReadFacts {
                binding: self.config.binding.clone(),
                generation: self.config.generation,
                observed_at: self.clock.now(),
                connection: NodeConnection::Online,
                sync_usable: true,
                permission: true,
                peer_connected: true,
                close_target: Some(format!("{}:1", "ab".repeat(32))),
                close_peer: Some(peer()),
            })
        })
    }
    fn execute_once(&self, permit: ClaimPermit) -> ResponseFuture<'_, Evidence> {
        Box::pin(async move {
            self.mutations.fetch_add(1, Ordering::SeqCst);
            let barrier = self.execution_barrier.lock().unwrap().clone();
            if let Some(barrier) = barrier {
                barrier.wait().await;
            }
            let evidence = self.success(&permit);
            self.effects
                .lock()
                .unwrap()
                .insert(evidence.operation_id, evidence.clone());
            let script = *self.execute.lock().unwrap();
            let mut response = Self::modify(evidence, script);
            // A lost response does not leak the invocation's newly created references to storage.
            if matches!(script, Script::Lost) {
                response.reference = RecoveryReference::planned(&permit.intent);
            }
            response
        })
    }
    fn observe_exact(&self, query: ObservationQuery) -> ResponseFuture<'_, Evidence> {
        Box::pin(async move {
            self.observations.fetch_add(1, Ordering::SeqCst);
            let evidence = self
                .effects
                .lock()
                .unwrap()
                .get(&query.operation_id)
                .cloned();
            let evidence = evidence.unwrap_or_else(|| Evidence {
                operation_id: query.operation_id,
                binding: query.binding.clone(),
                generation: query.generation,
                kind: query.kind,
                claim_id: query.claim_id,
                sequence: query.sequence,
                reference: query.reference.clone(),
                class: Class::NotFound,
                facts: None,
            });
            let script = self
                .scripts
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Script::Success);
            let mut response = Self::modify(evidence, script);
            response.sequence = query.sequence;
            if matches!(
                script,
                Script::Lost
                    | Script::Absent
                    | Script::Partial
                    | Script::Pruned
                    | Script::Conflict
                    | Script::Reject
                    | Script::PaidElsewhere
            ) {
                response.reference = query.reference;
            }
            response
        })
    }
}

fn decimal(n: u64) -> Decimal {
    Decimal::new(n).unwrap()
}
fn emit(name: &str, operation: &Operation) {
    if let Ok(directory) = std::env::var("ENGINE_EVIDENCE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&serde_json::json!({"schema":"Operation","value":operation}))
                .unwrap(),
        )
        .unwrap();
    }
}
fn peer() -> String {
    bitcoin::secp256k1::PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[42; 32]).unwrap(),
    )
    .to_string()
}
fn test_address() -> String {
    let key = bitcoin::CompressedPublicKey(bitcoin::secp256k1::PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[43; 32]).unwrap(),
    ));
    bitcoin::Address::p2wpkh(&key, bitcoin::Network::Regtest).to_string()
}
fn invoice(
    amount: u64,
    description: &str,
    now: DateTime<Utc>,
    expiry: u32,
    preimage: [u8; 32],
) -> String {
    let key = SecretKey::from_slice(&[42; 32]).unwrap();
    InvoiceBuilder::new(Currency::Regtest)
        .description(description.into())
        .payment_hash(sha256::Hash::hash(&preimage))
        .payment_secret(PaymentSecret([44; 32]))
        .duration_since_epoch(std::time::Duration::from_secs(
            u64::try_from(now.timestamp()).unwrap(),
        ))
        .expiry_time(std::time::Duration::from_secs(u64::from(expiry)))
        .min_final_cltv_expiry_delta(18)
        .amount_milli_satoshis(amount)
        .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(hash, &key))
        .unwrap()
        .to_string()
}
fn request(kind: OperationKind, now: DateTime<Utc>) -> OperationRequest {
    match kind {
        OperationKind::CreateInvoice => OperationRequest::CreateInvoice(CreateInvoice {
            amount_msat: Msat(decimal(1001)),
            description: "quoted \" \\ \n café".into(),
            expiry_seconds: 3600,
        }),
        OperationKind::PayInvoice => OperationRequest::PayInvoice(PayInvoice {
            bolt11: invoice(1001, "invoice", now, 3600, [45; 32]),
            amount_msat: None,
            max_fee_msat: Msat(Decimal::ZERO),
            description: None,
        }),
        OperationKind::ConnectPeer => OperationRequest::ConnectPeer(ConnectPeer {
            pubkey: peer(),
            host: "peer.example.invalid".into(),
            port: 9735,
        }),
        OperationKind::DisconnectPeer => {
            OperationRequest::DisconnectPeer(DisconnectPeer { pubkey: peer() })
        }
        OperationKind::OpenChannel => OperationRequest::OpenChannel(OpenChannel {
            peer_pubkey: peer(),
            amount_sat: Sat(decimal(100000)),
            private: true,
            fee_rate_sat_vbyte: decimal(2),
        }),
        OperationKind::CloseChannel => OperationRequest::CloseChannel(CloseChannel {
            channel_id: "channel-alias".into(),
            fee_rate_sat_vbyte: decimal(2),
        }),
        OperationKind::NewAddress => OperationRequest::NewAddress(NewAddress {
            address_type: AddressType::P2wpkh,
        }),
        OperationKind::SendOnchain => OperationRequest::SendOnchain(SendOnchain {
            address: test_address(),
            amount_sat: Sat(decimal(10000)),
            fee_rate_sat_vbyte: decimal(2),
        }),
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    engine: Engine,
    context: Context,
    settings: ApiSettings,
    authenticator: WebauthnAuthenticator<SoftPasskey>,
    fake: Arc<CountingFake>,
    clock: Arc<TestClock>,
    node: String,
}
impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp/opencode")
            .unwrap();
        let settings = ApiSettings {
            bind: "127.0.0.1:8080".parse().unwrap(),
            public_origin: "https://manager.example.invalid".parse().unwrap(),
            rp_id: "manager.example.invalid".into(),
            database: directory.path().join("journal.sqlite"),
            invoice_key_file: directory.path().join("unused.key"),
            allow_insecure_loopback: false,
            client_identity: Default::default(),
            reauth: ReauthPolicy {
                mode: ReauthMode::EveryOperation,
                recent_auth_seconds: None,
            },
            limits: Limits::default(),
        };
        let journal = Journal::open(settings.database.clone()).await.unwrap();
        let auth = AuthManager::new(&settings, journal.clone()).unwrap();
        let clock = Arc::new(TestClock(Mutex::new(
            DateTime::from_timestamp(1800000000, 123456789).unwrap(),
        )));
        let now = clock.now();
        let identity = crate::auth::ClientIdentity::Socket("127.0.0.1".parse().unwrap());
        let anonymous = auth.anonymous(identity, now).await.unwrap();
        let token = journal
            .issue_enrollment(now, std::time::Duration::from_secs(60), false)
            .await
            .unwrap();
        let challenge = auth
            .start_enrollment(&anonymous.context, token, now)
            .await
            .unwrap();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let credential = authenticator
            .do_registration(settings.public_origin.clone(), challenge.options)
            .unwrap();
        let context = auth
            .finish_enrollment(
                &anonymous.context,
                crate::auth::RegistrationFinish {
                    challenge_id: challenge.challenge_id,
                    credential,
                },
                now,
            )
            .await
            .unwrap()
            .context;
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/api-examples.json")).unwrap();
        let mut policy: NodePolicy =
            serde_json::from_value(fixture["fixtures"]["node_policy"]["value"].clone()).unwrap();
        let node = policy.node_id.clone();
        policy.read_only = false;
        let config = NodeConfig {
            binding: NodeBinding {
                node_id: node.clone(),
                network: VerifiedNetwork::Regtest,
                identity_pubkey: peer(),
                identity_revision: "verified-synthetic-connection".into(),
            },
            generation: Uuid::new_v4(),
            backend: Backend::LndGrpc,
            policy,
            peer_policy: PeerPolicy {
                allowed_hosts: vec!["peer.example.invalid".into()],
                allowed_ports: vec![9735],
            },
            reauth_mode: ReauthMode::EveryOperation,
            capabilities: Capabilities::uniform(None),
            review_seconds: 300,
            freshness_seconds: 60,
        };
        let fake = Arc::new(CountingFake {
            mutations: AtomicUsize::new(0),
            observations: AtomicUsize::new(0),
            preparations: AtomicUsize::new(0),
            config: config.clone(),
            clock: clock.clone(),
            execute: Mutex::new(Script::Success),
            scripts: Mutex::new(VecDeque::new()),
            effects: Mutex::new(HashMap::new()),
            execution_barrier: Mutex::new(None),
            prerequisites: Mutex::new(None),
        });
        let nodes = BTreeMap::from([(
            node.clone(),
            Arc::new(Mutex::new(Some(PinnedNode {
                config,
                adapter: fake.clone(),
            }))),
        )]);
        let engine = Engine {
            journal,
            auth,
            nodes: Arc::new(nodes),
            unavailable: Arc::new(BTreeMap::new()),
            clock: clock.clone(),
            key: Arc::new(PendingSecretKey::new([91; 32])),
            tasks: Arc::new(tokio::sync::Semaphore::new(64)),
            faults: Faults::default(),
        };
        Self {
            _directory: directory,
            engine,
            context,
            settings,
            authenticator,
            fake,
            clock,
            node,
        }
    }
    async fn create(&self, kind: OperationKind) -> Operation {
        self.engine
            .create_review(
                &self.context,
                &self.node,
                Uuid::new_v4(),
                request(kind, self.clock.now()),
            )
            .await
            .unwrap()
    }
    async fn authorize(&mut self, operation: &Operation) -> Option<Uuid> {
        if !operation.request.sensitive() {
            return None;
        }
        let response = self
            .engine
            .start_authorization(
                &self.context,
                &self.node,
                operation.id,
                &operation.review.digest,
            )
            .await
            .unwrap();
        let crate::auth::AuthorizationStart::ChallengeRequired { challenge } = response else {
            panic!("strict mode must challenge");
        };
        let credential = self
            .authenticator
            .do_authentication(self.settings.public_origin.clone(), challenge.options)
            .unwrap();
        Some(
            self.engine
                .finish_authorization(
                    &self.context,
                    &self.node,
                    operation.id,
                    &operation.review.digest,
                    crate::auth::AuthenticationFinish {
                        challenge_id: challenge.challenge_id,
                        credential,
                    },
                )
                .await
                .unwrap()
                .authorization_id,
        )
    }
    async fn confirm(&self, operation: &Operation, grant: Option<Uuid>) -> Result<Operation> {
        self.engine
            .confirm_once(
                &self.context,
                &self.node,
                operation.id,
                &operation.review.digest,
                grant,
            )
            .await
    }
    async fn stored(&self, id: Uuid) -> (bool, i64, bool) {
        self.engine.journal.run(move|connection|{
            Ok((connection.query_row("SELECT dispatched FROM operations WHERE id=?1",[id.to_string()],|row|row.get(0))?,
                connection.query_row("SELECT count(*) FROM resource_claims WHERE operation_id=?1",[id.to_string()],|row|row.get(0))?,
                connection.query_row("SELECT EXISTS(SELECT 1 FROM pending_invoice_secrets WHERE operation_id=?1)",[id.to_string()],|row|row.get(0))?))
        }).await.unwrap()
    }
    fn fault(&mut self, point: FaultPoint) {
        self.engine.faults = Faults {
            handler: Some(Arc::new(move |current| current == point)),
        };
    }
    fn clear_fault(&mut self) {
        self.engine.faults = Faults::default();
    }
    async fn reopen(&mut self) {
        self.engine.journal = Journal::open(self.settings.database.clone()).await.unwrap();
        self.engine.auth = AuthManager::new(&self.settings, self.engine.journal.clone()).unwrap();
        self.engine.recover().await.unwrap();
        // A fresh synthetic authenticated session still uses the real software authenticator.
        let anonymous = self
            .engine
            .auth
            .anonymous(
                crate::auth::ClientIdentity::Socket("127.0.0.1".parse().unwrap()),
                self.clock.now(),
            )
            .await
            .unwrap();
        let challenge = self
            .engine
            .auth
            .start_login(&anonymous.context, self.clock.now())
            .await
            .unwrap();
        let credential = self
            .authenticator
            .do_authentication(self.settings.public_origin.clone(), challenge.options)
            .unwrap();
        self.context = self
            .engine
            .auth
            .finish_login(
                &anonymous.context,
                crate::auth::AuthenticationFinish {
                    challenge_id: challenge.challenge_id,
                    credential,
                },
                self.clock.now(),
            )
            .await
            .unwrap()
            .context;
    }
}

#[tokio::test]
async fn all_eight_success_and_duplicate_confirm_execute_exactly_once() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let immutable = serde_json::to_value(&op.review).unwrap();
        emit(&format!("{kind:?}-review"), &op);
        let grant = f.authorize(&op).await;
        assert_eq!(f.fake.counts(), (0, 0));
        let completed = f
            .confirm(&op, grant)
            .await
            .unwrap_or_else(|error| panic!("{kind:?}: {error:?}"));
        assert_eq!(completed.state, OperationState::Succeeded, "{kind:?}");
        assert_eq!(f.fake.counts(), (1, 0));
        emit(&format!("{kind:?}-completed"), &completed);
        assert_eq!(serde_json::to_value(&completed.review).unwrap(), immutable);
        assert_eq!(
            f.confirm(&op, grant).await.unwrap().state,
            OperationState::Succeeded
        );
        assert_eq!(f.fake.counts(), (1, 0));
        assert_eq!(f.stored(op.id).await, (true, 0, false));
    }
}

#[tokio::test]
async fn all_eight_preclaim_denials_have_exactly_zero_mutations() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        let error = f
            .engine
            .confirm_once(&f.context, &f.node, op.id, "wrong digest", grant)
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ReviewMismatch);
        f.engine
            .node(&f.node)
            .unwrap()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .config
            .policy
            .read_only = true;
        assert_eq!(
            f.confirm(&op, grant).await.unwrap_err().code,
            ErrorCode::ReadOnly
        );
        assert_eq!(
            f.engine
                .create_review(
                    &f.context,
                    &f.node,
                    Uuid::new_v4(),
                    request(kind, f.clock.now())
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::ReadOnly
        );
        assert_eq!(
            f.engine
                .start_authorization(&f.context, &f.node, op.id, &op.review.digest)
                .await
                .err()
                .unwrap()
                .code,
            ErrorCode::ReadOnly
        );
        f.engine
            .node(&f.node)
            .unwrap()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .config
            .policy
            .read_only = false;
        f.clock.advance(300);
        assert_eq!(
            f.confirm(&op, grant).await.unwrap_err().code,
            ErrorCode::ReviewExpired
        );
        assert_eq!(f.fake.counts(), (0, 0));
        assert!(!f.stored(op.id).await.0);
    }
}

#[tokio::test]
async fn all_eight_create_rollback_and_same_key_replay_are_atomic() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let key = Uuid::new_v4();
        let req = request(kind, f.clock.now());
        f.fault(FaultPoint::BeforeCreateCommit);
        assert!(f
            .engine
            .create_review(&f.context, &f.node, key, req.clone())
            .await
            .is_err());
        let count = f
            .engine
            .journal
            .run(|connection| {
                Ok(
                    connection.query_row("SELECT count(*) FROM operations", [], |row| {
                        row.get::<_, i64>(0)
                    })?,
                )
            })
            .await
            .unwrap();
        assert_eq!(count, 0);
        f.clear_fault();
        let op = f
            .engine
            .create_review(&f.context, &f.node, key, req.clone())
            .await
            .unwrap();
        assert_eq!(
            f.engine
                .create_review(&f.context, &f.node, key, req.clone())
                .await
                .unwrap()
                .id,
            op.id
        );
        assert_eq!(
            f.engine
                .create_review(&f.context, &f.node, Uuid::new_v4(), req)
                .await
                .unwrap_err()
                .code,
            ErrorCode::ResourceBusy
        );
        let changed = if kind == OperationKind::NewAddress {
            request(OperationKind::CreateInvoice, f.clock.now())
        } else {
            request(OperationKind::NewAddress, f.clock.now())
        };
        assert_eq!(
            f.engine
                .create_review(&f.context, &f.node, key, changed)
                .await
                .unwrap_err()
                .code,
            ErrorCode::IdempotencyConflict
        );
        assert_eq!(f.fake.counts(), (0, 0));
    }
}

#[tokio::test]
async fn all_eight_logout_after_context_lookup_denies_new_claim() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        f.engine.auth.revoke(&f.context).unwrap();
        assert_eq!(
            f.confirm(&op, grant).await.unwrap_err().code,
            ErrorCode::SessionRequired
        );
        assert_eq!(f.fake.counts(), (0, 0));
        assert!(!f.stored(op.id).await.0);
    }
}

#[tokio::test]
async fn all_eight_grant_loss_rollback_requires_fresh_authorization() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        f.fault(FaultPoint::AfterGrantRemoval);
        assert!(f.confirm(&op, grant).await.is_err());
        assert_eq!(f.fake.counts(), (0, 0));
        assert!(!f.stored(op.id).await.0);
        f.clear_fault();
        if op.request.sensitive() {
            assert_eq!(
                f.confirm(&op, grant).await.unwrap_err().code,
                ErrorCode::AuthorizationInvalid
            );
        }
        assert_eq!(f.fake.counts(), (0, 0));
        let grant = f.authorize(&op).await;
        f.confirm(&op, grant).await.unwrap();
        assert_eq!(f.fake.counts(), (1, 0));
    }
}

#[tokio::test]
async fn all_eight_committed_zero_send_crash_and_restart_never_redispatch() {
    for point in [FaultPoint::CommitAcknowledgement, FaultPoint::BeforeAdapter] {
        for kind in KINDS {
            let mut f = Fixture::new().await;
            let op = f.create(kind).await;
            let grant = f.authorize(&op).await;
            f.fault(point);
            let response = f.confirm(&op, grant).await;
            if point == FaultPoint::CommitAcknowledgement {
                assert_eq!(response.unwrap().state, OperationState::Unknown);
            } else {
                assert_eq!(response.unwrap_err().outcome, ErrorOutcome::Unknown);
            }
            assert_eq!(f.fake.counts(), (0, 0));
            let before = f.stored(op.id).await;
            assert!(before.0 && before.1 > 0);
            f.clear_fault();
            f.reopen().await;
            assert_eq!(f.fake.counts(), (0, 0));
            assert_eq!(f.stored(op.id).await, before);
            assert_eq!(
                f.confirm(&op, None).await.unwrap().state,
                OperationState::Unknown
            );
            assert_eq!(
                f.engine
                    .observe(&f.context, &f.node, op.id)
                    .await
                    .unwrap()
                    .state,
                OperationState::Unknown
            );
            assert_eq!(f.fake.counts(), (0, 1));
        }
    }
}

#[tokio::test]
async fn all_eight_lost_response_absence_and_result_write_failure_hold_claims() {
    for kind in KINDS {
        for lost in [true, false] {
            let mut f = Fixture::new().await;
            let op = f.create(kind).await;
            let grant = f.authorize(&op).await;
            if lost {
                *f.fake.execute.lock().unwrap() = Script::Lost;
            } else {
                f.fault(FaultPoint::ObservationCommit);
            }
            let response = f.confirm(&op, grant).await;
            assert_eq!(response.unwrap().state, OperationState::Unknown);
            assert_eq!(f.fake.counts(), (1, 0));
            let before = f.stored(op.id).await;
            assert!(before.0 && before.1 > 0);
            f.clear_fault();
            f.reopen().await;
            f.fake.script(Script::Absent);
            assert_eq!(
                f.engine
                    .observe(&f.context, &f.node, op.id)
                    .await
                    .unwrap()
                    .state,
                OperationState::Unknown
            );
            f.confirm(&op, None).await.unwrap();
            assert_eq!(f.fake.counts(), (1, 1));
            assert_eq!(f.stored(op.id).await, before);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admitted_concurrent_confirms_mint_one_permit() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(33));
        let mut tasks = Vec::new();
        f.engine.journal = f.engine.journal.clone().with_test_capacity(64);
        for _ in 0..32 {
            let engine = f.engine.clone();
            let context = f.context.clone();
            let op = op.clone();
            let node = f.node.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                engine
                    .confirm_once(&context, &node, op.id, &op.review.digest, grant)
                    .await
            }));
        }
        barrier.wait().await;
        let mut admitted = 0;
        for task in tasks {
            match task.await.unwrap() {
                Ok(_) => admitted += 1,
                Err(error) => assert_eq!(error.code, ErrorCode::StorageUnavailable),
            }
        }
        assert_eq!(admitted, 32);
        assert_eq!(f.fake.counts(), (1, 0));
    }
}

#[tokio::test]
async fn exact_txid_confirmation_refresh_keeps_success_and_uses_read_start_order() {
    let mut f = Fixture::new().await;
    let op = f.create(OperationKind::SendOnchain).await;
    let grant = f.authorize(&op).await;
    let sent = f.confirm(&op, grant).await.unwrap();
    assert_eq!(sent.stage, OperationStage::Broadcast);
    let config = f.fake.config.clone();
    let old = storage::observation_query(&f.engine, op.id, &config)
        .await
        .unwrap()
        .unwrap();
    f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
    let newer = storage::observation_query(&f.engine, op.id, &config)
        .await
        .unwrap()
        .unwrap();
    f.fake.script(Script::Confirmations(1));
    let old_evidence = f.fake.observe_exact(old).await;
    f.fake.script(Script::Confirmations(0));
    let new_evidence = f.fake.observe_exact(newer).await;
    let first = storage::apply(&f.engine, op.id, old_evidence.clone(), true)
        .await
        .unwrap();
    assert_eq!(first.stage, OperationStage::Confirmed);
    assert_eq!(
        first.reconciliation.unwrap().last_outcome,
        Some(ReconciliationOutcome::InFlight)
    );
    storage::apply(&f.engine, op.id, new_evidence, true)
        .await
        .unwrap();
    let final_op = storage::apply(&f.engine, op.id, old_evidence, true)
        .await
        .unwrap();
    assert_eq!(final_op.state, OperationState::Succeeded);
    assert_eq!(final_op.stage, OperationStage::Confirmed);
    assert!(
        matches!(final_op.result,Some(OperationResult::SendOnchain{confirmations:Some(value),..}) if value==Decimal::ZERO)
    );
    f.fake.script(Script::WrongReference);
    f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
    assert!(f.engine.observe(&f.context, &f.node, op.id).await.is_err());
    assert_eq!(f.fake.counts(), (1, 3));
    assert_eq!(f.stored(op.id).await, (true, 0, false));
}

#[tokio::test]
async fn all_eight_terminal_outcome_survives_late_rejection_and_absence() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        f.confirm(&op, grant).await.unwrap();
        for script in [Script::Reject, Script::Absent] {
            f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
            f.fake.script(script);
            assert_eq!(
                f.engine
                    .observe(&f.context, &f.node, op.id)
                    .await
                    .unwrap()
                    .state,
                OperationState::Succeeded
            );
        }
        assert_eq!(f.fake.counts(), (1, 2));
    }
}

#[tokio::test]
async fn paid_hash_exclusion_and_old_group_never_credit_or_release_wrong_attempt() {
    let mut f = Fixture::new().await;
    let op = f.create(OperationKind::PayInvoice).await;
    let grant = f.authorize(&op).await;
    *f.fake.execute.lock().unwrap() = Script::Accepted;
    f.confirm(&op, grant).await.unwrap();
    f.fake.script(Script::OldGroup);
    assert!(f.engine.observe(&f.context, &f.node, op.id).await.is_err());
    assert!(f.stored(op.id).await.1 > 0);
    f.fake.script(Script::Accepted);
    f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
    assert_eq!(
        f.engine
            .observe(&f.context, &f.node, op.id)
            .await
            .unwrap()
            .state,
        OperationState::Pending
    );
    f.fake.script(Script::Success);
    f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
    assert_eq!(
        f.engine
            .observe(&f.context, &f.node, op.id)
            .await
            .unwrap()
            .state,
        OperationState::Succeeded
    );
    f.fake.script(Script::OldGroup);
    f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
    assert!(f.engine.observe(&f.context, &f.node, op.id).await.is_err());
    assert_eq!(
        storage::load_local(&f.engine, op.id).await.unwrap().state,
        OperationState::Succeeded
    );
    assert_eq!(
        f.engine
            .create_review(&f.context, &f.node, Uuid::new_v4(), op.request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::AlreadyPaid
    );
    assert_eq!(f.fake.counts(), (1, 4));
}

#[tokio::test]
async fn canonical_arrays_golden_bytes_and_frozen_immutable_review() {
    let f = Fixture::new().await;
    let req = request(OperationKind::CreateInvoice, f.clock.now());
    let bytes = serde_json::to_string(&intent::input("node-a", &req)).unwrap();
    assert_eq!(bytes,"[\"ld-input-v1\",\"node-a\",[\"create_invoice\",[\"1001\",\"quoted \\\" \\\\ \\n café\",3600]]]");
    let op = f.create(OperationKind::CreateInvoice).await;
    let id = op.id;
    let stored = f
        .engine
        .journal
        .run(move |connection| {
            Ok(connection.query_row(
                "SELECT intent FROM operation_intents WHERE operation_id=?1",
                [id.to_string()],
                |row| row.get::<_, String>(0),
            )?)
        })
        .await
        .unwrap();
    let intent: ReviewedIntent = serde_json::from_str(&stored).unwrap();
    intent.validate(&op).unwrap();
    for field in [
        "amount_msat",
        "destination",
        "payment_hash",
        "expires_at",
        "policy_revision",
    ] {
        let mut value = serde_json::to_value(&op).unwrap();
        value["review"][field] = match field {
            "amount_msat" => serde_json::json!("1002"),
            "expires_at" => serde_json::json!("2030-01-01T00:00:00Z"),
            _ => serde_json::json!("changed"),
        };
        let changed: Operation = serde_json::from_value(value).unwrap();
        assert_eq!(
            intent.validate(&changed).unwrap_err().code,
            ErrorCode::ReviewMismatch
        );
    }
    assert_eq!(f.fake.counts(), (0, 0));
}

#[tokio::test]
async fn all_eight_config_policy_removal_and_auth_generation_fail_closed() {
    for kind in KINDS {
        for change in 0..4 {
            let mut f = Fixture::new().await;
            let op = f.create(kind).await;
            let grant = f.authorize(&op).await;
            let expected = match change {
                0 => {
                    f.engine
                        .node(&f.node)
                        .unwrap()
                        .lock()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .config
                        .policy
                        .revision = "changed".into();
                    ErrorCode::PolicyChanged
                }
                1 => {
                    f.engine
                        .node(&f.node)
                        .unwrap()
                        .lock()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .config
                        .generation = Uuid::new_v4();
                    ErrorCode::IdentityChanged
                }
                2 => {
                    *f.engine.node(&f.node).unwrap().lock().unwrap() = None;
                    ErrorCode::NotFound
                }
                _ => {
                    f.engine
                        .journal
                        .issue_enrollment(f.clock.now(), std::time::Duration::from_secs(60), true)
                        .await
                        .unwrap();
                    ErrorCode::SessionRequired
                }
            };
            assert_eq!(
                f.confirm(&op, grant).await.unwrap_err().code,
                expected,
                "{kind:?} change {change}"
            );
            assert_eq!(f.fake.counts(), (0, 0));
            assert!(!f.stored(op.id).await.0);
        }
    }
}

#[tokio::test]
async fn all_eight_wrong_node_grant_null_and_expired_session_are_zero_dispatch() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        assert_eq!(
            f.engine
                .confirm_once(&f.context, "other-node", op.id, &op.review.digest, None)
                .await
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        if op.request.sensitive() {
            assert_eq!(
                f.confirm(&op, None).await.unwrap_err().code,
                ErrorCode::ReauthRequired
            );
        }
        assert_eq!(
            f.confirm(&op, Some(Uuid::new_v4())).await.unwrap_err().code,
            ErrorCode::AuthorizationInvalid
        );
        let grant = f.authorize(&op).await;
        f.clock
            .advance(i64::from(f.settings.limits.session_idle_seconds));
        assert_eq!(
            f.confirm(&op, grant).await.unwrap_err().code,
            ErrorCode::SessionRequired
        );
        assert_eq!(f.fake.counts(), (0, 0));
    }
}

#[tokio::test]
async fn all_eight_definite_rejection_consumes_fence_and_releases_only_transient_claims() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        *f.fake.execute.lock().unwrap() = Script::Reject;
        let failed = f.confirm(&op, grant).await.unwrap();
        assert_eq!(failed.state, OperationState::Failed);
        assert_eq!(failed.stage, OperationStage::Submitted);
        assert_eq!(failed.error.unwrap().outcome, ErrorOutcome::DefiniteFailure);
        assert_eq!(f.stored(op.id).await, (true, 0, false));
        f.confirm(&op, None).await.unwrap();
        assert_eq!(f.fake.counts(), (1, 0));
        // A deliberate different-key review is allowed; there is no automatic queued retry.
        f.engine
            .create_review(&f.context, &f.node, Uuid::new_v4(), op.request.clone())
            .await
            .unwrap();
        assert_eq!(f.fake.counts(), (1, 0));
    }
}

#[tokio::test]
async fn all_eight_uncertainty_sequence_never_releases_or_fabricates_references() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        *f.fake.execute.lock().unwrap() = Script::Lost;
        f.confirm(&op, grant).await.unwrap();
        let before = f.stored(op.id).await;
        for script in [
            Script::Lost,
            Script::Absent,
            Script::Partial,
            Script::Pruned,
            Script::Conflict,
        ] {
            f.fake.script(script);
            let observed = f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
            assert_eq!(observed.state, OperationState::Unknown);
            assert!(observed.result.is_none());
            assert_eq!(f.stored(op.id).await, before);
            f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
        }
        assert_eq!(f.fake.counts(), (1, 5));
    }
}

#[tokio::test]
async fn all_eight_readonly_after_claim_blocks_post_but_not_observation_and_removed_node_is_local()
{
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        f.confirm(&op, grant).await.unwrap();
        f.engine
            .node(&f.node)
            .unwrap()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .config
            .policy
            .read_only = true;
        assert_eq!(
            f.confirm(&op, None).await.unwrap_err().code,
            ErrorCode::ReadOnly
        );
        f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
        assert_eq!(f.fake.counts(), (1, 1));
        *f.engine.node(&f.node).unwrap().lock().unwrap() = None;
        f.confirm(&op, None).await.unwrap();
        f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
        assert_eq!(f.fake.counts(), (1, 1));
    }
}

#[tokio::test]
async fn revoked_before_gate_cannot_claim_but_revoked_after_commit_can_finish() {
    for kind in KINDS {
        for after in [false, true] {
            let mut f = Fixture::new().await;
            let op = f.create(kind).await;
            let grant = f.authorize(&op).await;
            let auth = f.engine.auth.clone();
            let context = f.context.clone();
            let at = if after {
                FaultPoint::BeforeAdapter
            } else {
                FaultPoint::BeforeClaimTransaction
            };
            f.engine.faults = Faults {
                handler: Some(Arc::new(move |point| {
                    if point == at {
                        auth.revoke(&context).unwrap();
                    }
                    false
                })),
            };
            let result = f.confirm(&op, grant).await;
            if after {
                assert_eq!(result.unwrap().state, OperationState::Succeeded);
                assert_eq!(f.fake.counts(), (1, 0));
            } else {
                assert_eq!(result.unwrap_err().code, ErrorCode::SessionRequired);
                assert_eq!(f.fake.counts(), (0, 0));
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_wins_before_claim_and_waiter_loss_after_claim_does_not_cancel_execution() {
    for after in [false, true] {
        let mut f = Fixture::new().await;
        let op = f.create(OperationKind::SendOnchain).await;
        let grant = f.authorize(&op).await;
        let entered = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let entered_worker = entered.clone();
        let resume_worker = resume.clone();
        let point = if after {
            FaultPoint::BeforeAdapter
        } else {
            FaultPoint::BeforeClaimTransaction
        };
        f.engine.faults = Faults {
            handler: Some(Arc::new(move |current| {
                if current == point {
                    entered_worker.wait();
                    resume_worker.wait();
                }
                false
            })),
        };
        let engine = f.engine.clone();
        let context = f.context.clone();
        let node = f.node.clone();
        let digest = op.review.digest.clone();
        let id = op.id;
        let waiter = tokio::spawn(async move {
            engine
                .confirm_once(&context, &node, id, &digest, grant)
                .await
        });
        entered.wait();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        resume.wait();
        let _completed = f.engine.tasks.acquire_many(64).await.unwrap();
        assert_eq!(f.fake.counts(), (usize::from(after), 0));
        assert_eq!(f.stored(op.id).await.0, after);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_nodes_execute_concurrently_without_a_global_rpc_lock() {
    let mut f = Fixture::new().await;
    let mut config = f.fake.config.clone();
    config.binding.node_id = "other-node".into();
    config.policy.node_id = "other-node".into();
    config.generation = Uuid::new_v4();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    *f.fake.execution_barrier.lock().unwrap() = Some(barrier.clone());
    let other = Arc::new(CountingFake {
        mutations: AtomicUsize::new(0),
        observations: AtomicUsize::new(0),
        preparations: AtomicUsize::new(0),
        config: config.clone(),
        clock: f.clock.clone(),
        execute: Mutex::new(Script::Success),
        scripts: Mutex::new(VecDeque::new()),
        effects: Mutex::new(HashMap::new()),
        execution_barrier: Mutex::new(Some(barrier)),
        prerequisites: Mutex::new(None),
    });
    Arc::make_mut(&mut f.engine.nodes).insert(
        "other-node".into(),
        Arc::new(Mutex::new(Some(PinnedNode {
            config,
            adapter: other.clone(),
        }))),
    );
    let first = f.create(OperationKind::SendOnchain).await;
    let first_grant = f.authorize(&first).await;
    let second = f
        .engine
        .create_review(
            &f.context,
            "other-node",
            Uuid::new_v4(),
            request(OperationKind::SendOnchain, f.clock.now()),
        )
        .await
        .unwrap();
    let node = f.node.clone();
    f.node = "other-node".into();
    let second_grant = f.authorize(&second).await;
    f.node = node;
    let (a, b) = tokio::join!(
        f.confirm(&first, first_grant),
        f.engine.confirm_once(
            &f.context,
            "other-node",
            second.id,
            &second.review.digest,
            second_grant
        )
    );
    assert_eq!(a.unwrap().state, OperationState::Succeeded);
    assert_eq!(b.unwrap().state, OperationState::Succeeded);
    assert_eq!(f.fake.counts(), (1, 0));
    assert_eq!(other.counts(), (1, 0));
}

#[tokio::test]
async fn secret_tamper_wrong_key_and_restart_fail_closed_without_dispatch_or_deletion() {
    for tamper in [false, true] {
        let mut f = Fixture::new().await;
        let op = f.create(OperationKind::CreateInvoice).await;
        assert_eq!(f.stored(op.id).await, (false, 1, true));
        if tamper {
            f.engine
                .journal
                .run(move |connection| {
                    connection.execute(
                        "UPDATE pending_invoice_secrets SET ciphertext=x'00' WHERE operation_id=?1",
                        [op.id.to_string()],
                    )?;
                    Ok(())
                })
                .await
                .unwrap();
        } else {
            f.engine.key = Arc::new(PendingSecretKey::new([92; 32]));
        }
        assert_eq!(
            f.confirm(&op, None).await.unwrap_err().code,
            ErrorCode::StorageUnavailable
        );
        assert!(f.engine.recover().await.is_err());
        assert_eq!(f.fake.counts(), (0, 0));
        assert_eq!(f.stored(op.id).await, (false, 1, true));
    }
}

#[tokio::test]
async fn unsupported_cln_open_capability_is_not_a_mutation_probe() {
    let f = Fixture::new().await;
    {
        let gate = f.engine.node(&f.node).unwrap();
        let mut pinned = gate.lock().unwrap();
        let config = &mut pinned.as_mut().unwrap().config;
        config.backend = Backend::ClnRest;
        config.capabilities.open_channel = Capability {
            enabled: false,
            reason: Some(CapabilityReason::Unsupported),
        };
    }
    assert_eq!(
        f.engine
            .create_review(
                &f.context,
                &f.node,
                Uuid::new_v4(),
                request(OperationKind::OpenChannel, f.clock.now())
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::Unsupported
    );
    assert_eq!(f.fake.counts(), (0, 0));
}

#[tokio::test]
async fn all_eight_live_prerequisite_failures_are_not_write_probes() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        let baseline = f.fake.prepare(&op.request).await.unwrap();
        for case in 0..6 {
            let mut facts = baseline.clone();
            let expected = match case {
                0 => {
                    facts.connection = NodeConnection::Offline;
                    ErrorCode::NodeOffline
                }
                1 => {
                    facts.connection = NodeConnection::AuthError;
                    ErrorCode::NodeAuthError
                }
                2 => {
                    facts.sync_usable = false;
                    ErrorCode::NodeSyncing
                }
                3 => {
                    facts.permission = false;
                    ErrorCode::NodeAuthError
                }
                4 => {
                    facts.observed_at -= chrono::Duration::seconds(60);
                    ErrorCode::NodeOffline
                }
                _ => {
                    facts.binding.identity_pubkey = "different".into();
                    ErrorCode::IdentityChanged
                }
            };
            *f.fake.prerequisites.lock().unwrap() = Some(facts);
            assert_eq!(f.confirm(&op, grant).await.unwrap_err().code, expected);
            assert_eq!(f.fake.counts(), (0, 0));
        }
        *f.fake.prerequisites.lock().unwrap() = None;
        f.confirm(&op, grant).await.unwrap();
        assert_eq!(f.fake.counts(), (1, 0));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_eight_concurrent_same_key_creates_share_one_immutable_intent() {
    for kind in KINDS {
        let f = Fixture::new().await;
        let key = Uuid::new_v4();
        let req = request(kind, f.clock.now());
        let (a, b) = tokio::join!(
            f.engine
                .create_review(&f.context, &f.node, key, req.clone()),
            f.engine.create_review(&f.context, &f.node, key, req)
        );
        let a = a.unwrap();
        let b = b.unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(
            serde_json::to_value(a.review).unwrap(),
            serde_json::to_value(b.review).unwrap()
        );
        assert_eq!(f.fake.counts(), (0, 0));
    }
}

#[tokio::test]
async fn close_alias_wallet_and_peer_resources_are_semantic_not_request_keys() {
    let f = Fixture::new().await;
    let first = f.create(OperationKind::CloseChannel).await;
    let mut alias = first.request.clone();
    if let OperationRequest::CloseChannel(p) = &mut alias {
        p.channel_id = "another-alias".into();
    }
    let error = f
        .engine
        .create_review(&f.context, &f.node, Uuid::new_v4(), alias)
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ResourceBusy);
    assert_eq!(error.operation_id, Some(first.id));
    let f = Fixture::new().await;
    let first = f.create(OperationKind::SendOnchain).await;
    let error = f
        .engine
        .create_review(
            &f.context,
            &f.node,
            Uuid::new_v4(),
            request(OperationKind::OpenChannel, f.clock.now()),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ResourceBusy);
    assert_eq!(error.operation_id, Some(first.id));
    let f = Fixture::new().await;
    let first = f.create(OperationKind::ConnectPeer).await;
    let error = f
        .engine
        .create_review(
            &f.context,
            &f.node,
            Uuid::new_v4(),
            request(OperationKind::DisconnectPeer, f.clock.now()),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ResourceBusy);
    assert_eq!(error.operation_id, Some(first.id));
    assert_eq!(f.fake.counts(), (0, 0));
}

#[tokio::test]
async fn invoice_expiry_caps_review_and_same_key_replay_never_renews_it() {
    let f = Fixture::new().await;
    let now = f.clock.now();
    let key = Uuid::new_v4();
    let req = OperationRequest::PayInvoice(PayInvoice {
        bolt11: invoice(1001, "short", now, 60, [79; 32]),
        amount_msat: None,
        max_fee_msat: Msat(Decimal::ZERO),
        description: None,
    });
    let op = f
        .engine
        .create_review(&f.context, &f.node, key, req.clone())
        .await
        .unwrap();
    assert_eq!(op.review.expires_at.timestamp(), now.timestamp() + 60);
    f.clock.advance(60);
    let replay = f
        .engine
        .create_review(&f.context, &f.node, key, req)
        .await
        .unwrap();
    assert_eq!(replay.id, op.id);
    assert_eq!(replay.state, OperationState::Expired);
    assert_eq!(replay.review.expires_at, op.review.expires_at);
    assert_eq!(f.fake.counts(), (0, 0));
    assert_eq!(f.stored(op.id).await, (false, 0, false));
}

#[tokio::test]
async fn status_authorization_is_session_relative_and_encrypted_secret_is_not_public() {
    let mut f = Fixture::new().await;
    let op = f.create(OperationKind::PayInvoice).await;
    f.authorize(&op).await;
    assert_eq!(
        f.engine
            .observe(&f.context, &f.node, op.id)
            .await
            .unwrap()
            .authorization
            .status,
        AuthorizationState::Authorized
    );
    let old = f.context.clone();
    let anonymous = f
        .engine
        .auth
        .anonymous(
            crate::auth::ClientIdentity::Socket("127.0.0.2".parse().unwrap()),
            f.clock.now(),
        )
        .await
        .unwrap();
    let challenge = f
        .engine
        .auth
        .start_login(&anonymous.context, f.clock.now())
        .await
        .unwrap();
    let credential = f
        .authenticator
        .do_authentication(f.settings.public_origin.clone(), challenge.options)
        .unwrap();
    f.context = f
        .engine
        .auth
        .finish_login(
            &anonymous.context,
            crate::auth::AuthenticationFinish {
                challenge_id: challenge.challenge_id,
                credential,
            },
            f.clock.now(),
        )
        .await
        .unwrap()
        .context;
    assert_eq!(
        f.engine
            .observe(&f.context, &f.node, op.id)
            .await
            .unwrap()
            .authorization
            .status,
        AuthorizationState::Required
    );
    assert_eq!(
        f.engine
            .observe(&old, &f.node, op.id)
            .await
            .unwrap()
            .authorization
            .status,
        AuthorizationState::Authorized
    );
    assert_eq!(f.fake.counts(), (0, 0));
    let op = f.create(OperationKind::CreateInvoice).await;
    let ciphertext = f
        .engine
        .journal
        .pending_secret(op.id)
        .await
        .unwrap()
        .unwrap();
    let secret = f.engine.key.decrypt(&op, &ciphertext).unwrap();
    let canary = hex::encode(&secret[..]);
    let mut swapped = op.clone();
    swapped.id = Uuid::new_v4();
    assert!(f.engine.key.decrypt(&swapped, &ciphertext).is_err());
    let completed = f.confirm(&op, None).await.unwrap();
    let json = serde_json::to_string(&completed).unwrap();
    assert!(!json.contains(&canary));
    for private in [
        "ciphertext",
        "preimage",
        "claim_id",
        "attempt",
        "invoice_label",
        "connection_generation",
    ] {
        assert!(!json.contains(private));
    }
    assert_eq!(f.fake.counts(), (1, 0));
}

#[tokio::test]
async fn closed_unknown_type_pending_then_unilateral_is_truthful_terminal_failure() {
    let mut f = Fixture::new().await;
    let op = f.create(OperationKind::CloseChannel).await;
    let grant = f.authorize(&op).await;
    *f.fake.execute.lock().unwrap() = Script::Accepted;
    f.confirm(&op, grant).await.unwrap();
    let config = f.fake.config.clone();
    let query = storage::observation_query(&f.engine, op.id, &config)
        .await
        .unwrap()
        .unwrap();
    let mut evidence = f.fake.observe_exact(query).await;
    if let Some(Facts::Close {
        close_type, closed, ..
    }) = &mut evidence.facts
    {
        *close_type = CloseType::Unknown;
        *closed = true;
    }
    let pending = storage::apply(&f.engine, op.id, evidence, true)
        .await
        .unwrap();
    assert_eq!(pending.state, OperationState::Pending);
    assert_eq!(pending.stage, OperationStage::ChannelClosed);
    assert!(f.stored(op.id).await.1 > 0);
    f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
    let query = storage::observation_query(&f.engine, op.id, &config)
        .await
        .unwrap()
        .unwrap();
    let mut evidence = f.fake.observe_exact(query).await;
    if let Some(Facts::Close {
        close_type, closed, ..
    }) = &mut evidence.facts
    {
        *close_type = CloseType::Unilateral;
        *closed = true;
    }
    let failed = storage::apply(&f.engine, op.id, evidence, true)
        .await
        .unwrap();
    assert_eq!(failed.state, OperationState::Failed);
    assert_eq!(
        failed.error.unwrap().code,
        ErrorCode::UnexpectedUnilateralClose
    );
    assert!(matches!(
        failed.result,
        Some(OperationResult::CloseChannel {
            close_type: CloseType::Unilateral,
            ..
        })
    ));
    assert_eq!(f.stored(op.id).await, (true, 0, false));
    assert_eq!(f.fake.counts(), (1, 2));
}

#[tokio::test]
async fn all_eight_preclaim_storage_failures_and_restart_never_create_authority() {
    for kind in KINDS {
        for point in [
            FaultPoint::BeforeClaimTransaction,
            FaultPoint::AfterGrantRemoval,
            FaultPoint::BeforeClaimCommit,
        ] {
            let mut f = Fixture::new().await;
            let key = Uuid::new_v4();
            let req = request(kind, f.clock.now());
            let op = f
                .engine
                .create_review(&f.context, &f.node, key, req.clone())
                .await
                .unwrap();
            let grant = f.authorize(&op).await;
            f.fault(point);
            assert_eq!(
                f.confirm(&op, grant).await.unwrap_err().code,
                ErrorCode::StorageUnavailable
            );
            assert!(!f.stored(op.id).await.0);
            assert_eq!(f.fake.counts(), (0, 0));
            f.clear_fault();
            f.reopen().await;
            assert_eq!(f.stored(op.id).await, (false, 0, false));
            let replay = f
                .engine
                .create_review(&f.context, &f.node, key, req)
                .await
                .unwrap();
            assert_eq!(replay.id, op.id);
            assert_eq!(replay.state, OperationState::Expired);
            assert_eq!(
                f.engine
                    .observe(&f.context, &f.node, op.id)
                    .await
                    .unwrap()
                    .state,
                OperationState::Expired
            );
            assert_eq!(f.fake.counts(), (0, 0));
        }
    }
}

#[tokio::test]
async fn all_eight_storage_overload_is_zero_dispatch_and_does_not_consume_grant() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        let original = f.engine.journal.clone();
        f.engine.journal = original.clone().with_test_capacity(0);
        assert_eq!(
            f.confirm(&op, grant).await.unwrap_err().code,
            ErrorCode::StorageUnavailable
        );
        f.engine.journal = original;
        assert!(!f.stored(op.id).await.0);
        assert_eq!(f.fake.counts(), (0, 0));
        f.confirm(&op, grant).await.unwrap();
        assert_eq!(f.fake.counts(), (1, 0));
    }
}

#[tokio::test]
async fn all_eight_success_response_lost_before_record_is_observation_only_after_restart() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        f.fault(FaultPoint::BeforeResult);
        assert_eq!(
            f.confirm(&op, grant).await.unwrap_err().outcome,
            ErrorOutcome::Unknown
        );
        let before = f.stored(op.id).await;
        assert!(before.0 && before.1 > 0);
        assert_eq!(f.fake.counts(), (1, 0));
        f.clear_fault();
        f.reopen().await;
        assert_eq!(f.fake.counts(), (1, 0));
        f.fake.script(Script::Absent);
        let observed = f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
        assert_eq!(observed.state, OperationState::Unknown);
        assert!(observed.result.is_none());
        f.confirm(&op, None).await.unwrap();
        assert_eq!(f.stored(op.id).await, before);
        assert_eq!(f.fake.counts(), (1, 1));
    }
}

#[tokio::test]
async fn all_eight_review_expiry_is_rechecked_after_final_refresh() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        let clock = f.clock.clone();
        f.engine.faults = Faults {
            handler: Some(Arc::new(move |point| {
                if point == FaultPoint::BeforeClaimTransaction {
                    clock.advance(300);
                }
                false
            })),
        };
        assert_eq!(
            f.confirm(&op, grant).await.unwrap_err().code,
            ErrorCode::ReviewExpired
        );
        assert!(!f.stored(op.id).await.0);
        assert_eq!(f.fake.counts(), (0, 0));
    }
}

#[tokio::test]
async fn sensitive_grants_expire_at_equality_and_cannot_authorize_other_operations() {
    for kind in KINDS.into_iter().filter(|kind| {
        matches!(
            kind,
            OperationKind::PayInvoice
                | OperationKind::OpenChannel
                | OperationKind::CloseChannel
                | OperationKind::SendOnchain
        )
    }) {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        let other_kind = if kind == OperationKind::PayInvoice {
            OperationKind::SendOnchain
        } else {
            OperationKind::PayInvoice
        };
        let other = f.create(other_kind).await;
        assert_eq!(
            f.confirm(&other, grant).await.unwrap_err().code,
            ErrorCode::AuthorizationInvalid
        );
        f.clock
            .advance(i64::from(f.settings.limits.authorization_seconds));
        assert_eq!(
            f.confirm(&op, grant).await.unwrap_err().code,
            ErrorCode::AuthorizationInvalid
        );
        assert_eq!(f.fake.counts(), (0, 0));
        assert!(!f.stored(op.id).await.0);
        assert!(!f.stored(other.id).await.0);
        let new_grant = f.authorize(&op).await;
        f.confirm(&op, new_grant).await.unwrap();
        assert_eq!(f.fake.counts(), (1, 0));
    }
}

#[tokio::test]
async fn all_eight_readonly_precedes_finish_authorization_even_with_valid_credential() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let sensitive = if op.request.sensitive() {
            op.clone()
        } else {
            f.create(OperationKind::PayInvoice).await
        };
        let response = f
            .engine
            .start_authorization(&f.context, &f.node, sensitive.id, &sensitive.review.digest)
            .await
            .unwrap();
        let crate::auth::AuthorizationStart::ChallengeRequired { challenge } = response else {
            panic!("strict ceremony required");
        };
        let credential = f
            .authenticator
            .do_authentication(f.settings.public_origin.clone(), challenge.options)
            .unwrap();
        f.engine
            .node(&f.node)
            .unwrap()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .config
            .policy
            .read_only = true;
        let error = f
            .engine
            .finish_authorization(
                &f.context,
                &f.node,
                op.id,
                &op.review.digest,
                crate::auth::AuthenticationFinish {
                    challenge_id: challenge.challenge_id,
                    credential,
                },
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::ReadOnly);
        assert_eq!(f.fake.counts(), (0, 0));
    }
}

#[tokio::test]
async fn all_eight_postcommit_retarget_uses_original_pinned_adapter_and_never_observes_replacement()
{
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        let gate = f.engine.node(&f.node).unwrap();
        let original = f.fake.clone();
        let mut config = original.config.clone();
        config.generation = Uuid::new_v4();
        config.binding.identity_revision = "replacement-synthetic-connection".into();
        let replacement = Arc::new(CountingFake {
            mutations: AtomicUsize::new(0),
            observations: AtomicUsize::new(0),
            preparations: AtomicUsize::new(0),
            config: config.clone(),
            clock: f.clock.clone(),
            execute: Mutex::new(Script::Success),
            scripts: Mutex::new(VecDeque::new()),
            effects: Mutex::new(HashMap::new()),
            execution_barrier: Mutex::new(None),
            prerequisites: Mutex::new(None),
        });
        let new_adapter = replacement.clone();
        f.engine.faults = Faults {
            handler: Some(Arc::new(move |point| {
                if point == FaultPoint::BeforeAdapter {
                    *gate.lock().unwrap() = Some(PinnedNode {
                        config: config.clone(),
                        adapter: new_adapter.clone(),
                    });
                }
                false
            })),
        };
        assert_eq!(
            f.confirm(&op, grant).await.unwrap().state,
            OperationState::Succeeded
        );
        f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
        f.confirm(&op, None).await.unwrap();
        assert_eq!(original.counts(), (1, 0));
        assert_eq!(replacement.counts(), (0, 0));
        assert_eq!(replacement.preparations.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn all_eight_cross_identity_observations_cannot_change_public_or_release_claims() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        let completed = f.confirm(&op, grant).await.unwrap();
        let original = serde_json::to_value(&completed).unwrap();
        for case in 0..5 {
            f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
            let query = storage::observation_query(&f.engine, op.id, &f.fake.config)
                .await
                .unwrap()
                .unwrap();
            let mut evidence = f.fake.observe_exact(query).await;
            match case {
                0 => evidence.binding.node_id = "other-node".into(),
                1 => {
                    evidence.kind = if kind == OperationKind::PayInvoice {
                        OperationKind::SendOnchain
                    } else {
                        OperationKind::PayInvoice
                    }
                }
                2 => evidence.generation = Uuid::new_v4(),
                3 => evidence.claim_id = Uuid::new_v4(),
                _ => match kind {
                    OperationKind::CreateInvoice | OperationKind::PayInvoice => {
                        evidence.reference.payment_hash = Some("ff".repeat(32))
                    }
                    OperationKind::ConnectPeer | OperationKind::DisconnectPeer => {
                        evidence.reference.peer = Some("different-peer".into())
                    }
                    OperationKind::OpenChannel | OperationKind::CloseChannel => {
                        evidence.reference.channel = Some(format!("{}:0", "ff".repeat(32)))
                    }
                    OperationKind::NewAddress => {
                        evidence.reference.address = Some("different-address".into())
                    }
                    OperationKind::SendOnchain => evidence.reference.txid = Some("ff".repeat(32)),
                },
            }
            assert_eq!(
                storage::apply(&f.engine, op.id, evidence, true)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::UpstreamInvalidResponse
            );
            let mut observed =
                serde_json::to_value(storage::load_local(&f.engine, op.id).await.unwrap()).unwrap();
            observed.as_object_mut().unwrap().remove("reconciliation");
            assert_eq!(observed, original);
        }
        assert_eq!(f.fake.counts(), (1, 5));
        assert_eq!(f.stored(op.id).await, (true, 0, false));
    }
}

#[tokio::test]
async fn invoice_hash_and_cln_label_recover_lost_response_without_another_create() {
    for cln in [false, true] {
        let f = Fixture::new().await;
        if cln {
            f.engine
                .node(&f.node)
                .unwrap()
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .config
                .backend = Backend::ClnRest;
        }
        let op = f.create(OperationKind::CreateInvoice).await;
        assert_eq!(op.review.payment_hash.is_none(), cln);
        assert_eq!(f.stored(op.id).await.2, !cln);
        assert_eq!(f.fake.counts(), (0, 0));
        *f.fake.execute.lock().unwrap() = Script::Lost;
        f.confirm(&op, None).await.unwrap();
        let mut f = f;
        f.reopen().await;
        assert_eq!(f.fake.counts(), (1, 0));
        let recovered = f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
        assert_eq!(recovered.state, OperationState::Succeeded);
        assert_eq!(f.stored(op.id).await, (true, 0, false));
        assert_eq!(f.fake.counts(), (1, 1));
        emit(
            if cln {
                "cln-invoice-recovered"
            } else {
                "lnd-invoice-recovered"
            },
            &recovered,
        );
    }
}

#[tokio::test]
async fn lost_new_address_open_and_send_references_are_not_recovered_by_plausibility() {
    for kind in [
        OperationKind::NewAddress,
        OperationKind::OpenChannel,
        OperationKind::SendOnchain,
    ] {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        *f.fake.execute.lock().unwrap() = Script::Lost;
        f.confirm(&op, grant).await.unwrap();
        let before = f.stored(op.id).await;
        assert!(f.engine.observe(&f.context, &f.node, op.id).await.is_err());
        assert_eq!(
            storage::load_local(&f.engine, op.id).await.unwrap().state,
            OperationState::Unknown
        );
        f.confirm(&op, None).await.unwrap();
        assert_eq!(f.stored(op.id).await, before);
        assert_eq!(f.fake.counts(), (1, 1));
    }
}

#[tokio::test]
async fn historical_paid_hash_excludes_new_payment_without_crediting_unknown_attempt() {
    let mut f = Fixture::new().await;
    let op = f.create(OperationKind::PayInvoice).await;
    let grant = f.authorize(&op).await;
    *f.fake.execute.lock().unwrap() = Script::Lost;
    f.confirm(&op, grant).await.unwrap();
    let held = f.stored(op.id).await;
    f.fake.script(Script::PaidElsewhere);
    let observed = f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
    assert_eq!(observed.state, OperationState::Unknown);
    assert!(observed.result.is_none());
    assert_eq!(f.stored(op.id).await, held);
    assert_eq!(
        f.engine
            .create_review(&f.context, &f.node, Uuid::new_v4(), op.request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::AlreadyPaid
    );
    assert_eq!(f.fake.counts(), (1, 1));
    emit("historical-paid-unknown", &observed);
}

#[tokio::test]
async fn close_confirmation_refresh_and_observation_rollback_preserve_terminal_facts() {
    let mut f = Fixture::new().await;
    let op = f.create(OperationKind::CloseChannel).await;
    let grant = f.authorize(&op).await;
    f.confirm(&op, grant).await.unwrap();
    let old = storage::observation_query(&f.engine, op.id, &f.fake.config)
        .await
        .unwrap()
        .unwrap();
    f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
    let newer = storage::observation_query(&f.engine, op.id, &f.fake.config)
        .await
        .unwrap()
        .unwrap();
    f.fake.script(Script::Confirmations(1));
    let old = f.fake.observe_exact(old).await;
    f.fake.script(Script::Confirmations(0));
    let newer = f.fake.observe_exact(newer).await;
    let before =
        serde_json::to_value(storage::load_local(&f.engine, op.id).await.unwrap()).unwrap();
    f.fault(FaultPoint::ObservationCommit);
    assert!(storage::apply(&f.engine, op.id, old.clone(), true)
        .await
        .is_err());
    assert_eq!(
        serde_json::to_value(storage::load_local(&f.engine, op.id).await.unwrap()).unwrap(),
        before
    );
    f.clear_fault();
    storage::apply(&f.engine, op.id, old.clone(), true)
        .await
        .unwrap();
    storage::apply(&f.engine, op.id, newer, true).await.unwrap();
    let final_op = storage::apply(&f.engine, op.id, old, true).await.unwrap();
    assert_eq!(final_op.state, OperationState::Succeeded);
    assert_eq!(final_op.stage, OperationStage::ChannelClosed);
    assert!(
        matches!(final_op.result,Some(OperationResult::CloseChannel{confirmations:Some(value),..}) if value==Decimal::ZERO)
    );
    f.fake.script(Script::WrongReference);
    f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
    assert!(f.engine.observe(&f.context, &f.node, op.id).await.is_err());
    assert_eq!(f.fake.counts(), (1, 3));
    assert_eq!(f.stored(op.id).await, (true, 0, false));
}

fn scalar_paths(value: &serde_json::Value, path: &str, paths: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, value) in fields {
                scalar_paths(value, &format!("{path}/{key}"), paths);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                scalar_paths(value, &format!("{path}/{index}"), paths);
            }
        }
        _ => paths.push(path.into()),
    }
}

#[tokio::test]
async fn all_eight_request_and_review_field_tampering_with_original_digest_never_claims() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        let original = serde_json::to_value(&op).unwrap();
        let mut paths = Vec::new();
        scalar_paths(&original["request"], "/request", &mut paths);
        scalar_paths(&original["review"], "/review", &mut paths);
        let expected = paths
            .iter()
            .filter(|path| {
                !path.ends_with("/digest")
                    && !path.ends_with("/kind")
                    && !path.ends_with("/address_type")
            })
            .count();
        let mut exercised = 0;
        for path in paths {
            if path.ends_with("/digest")
                || path.ends_with("/kind")
                || path.ends_with("/address_type")
            {
                continue;
            }
            let mut changed = original.clone();
            let value = changed.pointer_mut(&path).unwrap();
            *value = match value {
                serde_json::Value::Bool(boolean) => serde_json::json!(!*boolean),
                serde_json::Value::Number(number) => {
                    serde_json::json!(number.as_u64().unwrap() + 1)
                }
                serde_json::Value::String(text) => {
                    if path.ends_with("/expires_at") {
                        serde_json::json!(
                            (op.review.expires_at + chrono::Duration::seconds(1)).to_rfc3339()
                        )
                    } else if path.ends_with("/operation_id") {
                        serde_json::json!(Uuid::new_v4())
                    } else if path.ends_with("/network") {
                        serde_json::json!("testnet")
                    } else if path.ends_with("/control") {
                        serde_json::json!(if text == "none" {
                            "requested_onchain_rate"
                        } else {
                            "none"
                        })
                    } else if let Ok(number) = text.parse::<u64>() {
                        serde_json::json!((number + 1).to_string())
                    } else {
                        serde_json::json!(format!("{text}-changed"))
                    }
                }
                serde_json::Value::Null => serde_json::json!("1"),
                _ => unreachable!("scalar paths contain only scalars"),
            };
            let candidate: Operation = serde_json::from_value(changed).unwrap();
            assert_eq!(candidate.review.digest, op.review.digest);
            let body = serde_json::to_string(&candidate).unwrap();
            let id = op.id;
            f.engine
                .journal
                .run(move |connection| {
                    connection.execute(
                        "UPDATE operations SET body=?1 WHERE id=?2",
                        rusqlite::params![body, id.to_string()],
                    )?;
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(
                f.confirm(&op, grant).await.unwrap_err().code,
                ErrorCode::ReviewMismatch,
                "{kind:?} {path}"
            );
            assert_eq!(f.fake.counts(), (0, 0));
            assert!(!f.stored(op.id).await.0);
            exercised += 1;
        }
        assert_eq!(
            exercised, expected,
            "every mutable scalar request/review field"
        );
        // p2wpkh has no alternate value: changing kind is the contract-valid mutation.
        let mut changed = op.clone();
        changed.request = if kind == OperationKind::NewAddress {
            request(OperationKind::CreateInvoice, f.clock.now())
        } else {
            request(OperationKind::NewAddress, f.clock.now())
        };
        let body = serde_json::to_string(&changed).unwrap();
        let id = op.id;
        f.engine
            .journal
            .run(move |connection| {
                connection.execute(
                    "UPDATE operations SET body=?1 WHERE id=?2",
                    rusqlite::params![body, id.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(
            f.confirm(&op, grant).await.unwrap_err().code,
            ErrorCode::ReviewMismatch
        );
        assert_eq!(f.fake.counts(), (0, 0));
        let body = serde_json::to_string(&op).unwrap();
        f.engine
            .journal
            .run(move |connection| {
                connection.execute(
                    "UPDATE operations SET body=?1 WHERE id=?2",
                    rusqlite::params![body, id.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        f.confirm(&op, grant).await.unwrap();
        assert_eq!(f.fake.counts(), (1, 0));
    }
}

#[tokio::test]
async fn exact_linked_rejection_after_unknown_releases_but_missing_derivation_link_does_not() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        let pending_kind = matches!(
            kind,
            OperationKind::PayInvoice
                | OperationKind::OpenChannel
                | OperationKind::CloseChannel
                | OperationKind::SendOnchain
        );
        *f.fake.execute.lock().unwrap() = if pending_kind {
            Script::Accepted
        } else {
            Script::Lost
        };
        f.confirm(&op, grant).await.unwrap();
        f.reopen().await;
        let before = f.stored(op.id).await;
        f.fake.script(Script::Reject);
        let response = f.engine.observe(&f.context, &f.node, op.id).await;
        if kind == OperationKind::NewAddress {
            assert_eq!(
                response.unwrap_err().code,
                ErrorCode::UpstreamInvalidResponse
            );
            assert_eq!(f.stored(op.id).await, before);
            assert_eq!(
                storage::load_local(&f.engine, op.id).await.unwrap().state,
                OperationState::Unknown
            );
        } else {
            let failed = response.unwrap();
            assert_eq!(failed.state, OperationState::Failed);
            assert_eq!(failed.error.unwrap().outcome, ErrorOutcome::DefiniteFailure);
            assert_eq!(f.stored(op.id).await, (true, 0, false));
        }
        f.confirm(&op, None).await.unwrap();
        assert_eq!(f.fake.counts(), (1, 1));
    }
}

#[tokio::test]
async fn positive_pending_facts_survive_later_absence_and_open_requires_active_channel() {
    for kind in [
        OperationKind::PayInvoice,
        OperationKind::OpenChannel,
        OperationKind::CloseChannel,
        OperationKind::SendOnchain,
    ] {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        *f.fake.execute.lock().unwrap() = Script::Accepted;
        let pending = f.confirm(&op, grant).await.unwrap();
        assert_eq!(pending.state, OperationState::Pending);
        let before = f.stored(op.id).await;
        emit(&format!("{kind:?}-pending"), &pending);
        for script in [Script::Lost, Script::Pruned] {
            f.fake.script(script);
            let observed = f.engine.observe(&f.context, &f.node, op.id).await.unwrap();
            assert_eq!(observed.state, OperationState::Pending);
            assert_eq!(observed.stage, pending.stage);
            assert_eq!(f.stored(op.id).await, before);
            f.clock.advance(RECONCILIATION_INTERVAL_SECONDS);
        }
        assert_eq!(
            f.engine
                .observe(&f.context, &f.node, op.id)
                .await
                .unwrap()
                .state,
            OperationState::Succeeded
        );
        assert_eq!(f.fake.counts(), (1, 3));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_eight_host_recovery_after_claim_allows_only_the_committed_execution() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let op = f.create(kind).await;
        let grant = f.authorize(&op).await;
        let entered = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let entered_worker = entered.clone();
        let resume_worker = resume.clone();
        f.engine.faults = Faults {
            handler: Some(Arc::new(move |point| {
                if point == FaultPoint::BeforeAdapter {
                    entered_worker.wait();
                    resume_worker.wait();
                }
                false
            })),
        };
        let engine = f.engine.clone();
        let context = f.context.clone();
        let node = f.node.clone();
        let reviewed = op.clone();
        let task = tokio::spawn(async move {
            engine
                .confirm_once(&context, &node, reviewed.id, &reviewed.review.digest, grant)
                .await
        });
        entered.wait();
        f.engine
            .journal
            .issue_enrollment(f.clock.now(), std::time::Duration::from_secs(60), true)
            .await
            .unwrap();
        resume.wait();
        assert_eq!(
            task.await.unwrap().unwrap().state,
            OperationState::Succeeded
        );
        assert_eq!(
            f.confirm(&op, None).await.unwrap_err().code,
            ErrorCode::SessionRequired
        );
        assert_eq!(f.fake.counts(), (1, 0));
    }
}

#[tokio::test]
async fn invoice_ciphertext_is_bound_to_all_review_identity_components() {
    let f = Fixture::new().await;
    let op = f.create(OperationKind::CreateInvoice).await;
    let ciphertext = f
        .engine
        .journal
        .pending_secret(op.id)
        .await
        .unwrap()
        .unwrap();
    for case in 0..6 {
        let mut swapped = op.clone();
        match case {
            0 => swapped.id = Uuid::new_v4(),
            1 => swapped.review.digest = "different-digest".into(),
            2 => swapped.review.node.node_id = "other-node".into(),
            3 => swapped.review.node.network = VerifiedNetwork::Testnet,
            4 => swapped.review.node.identity_pubkey = "other-identity".into(),
            _ => swapped.review.node.identity_revision = "other-revision".into(),
        }
        assert!(f.engine.key.decrypt(&swapped, &ciphertext).is_err());
    }
    assert_eq!(f.fake.counts(), (0, 0));
    assert_eq!(f.stored(op.id).await, (false, 1, true));
}

#[tokio::test]
async fn all_eight_same_key_changes_to_each_request_parameter_conflict_without_dispatch() {
    for kind in KINDS {
        let mut f = Fixture::new().await;
        let key = Uuid::new_v4();
        let original = request(kind, f.clock.now());
        let op = f
            .engine
            .create_review(&f.context, &f.node, key, original.clone())
            .await
            .unwrap();
        let mut paths = Vec::new();
        scalar_paths(
            &serde_json::to_value(&original).unwrap()["params"],
            "/params",
            &mut paths,
        );
        if kind == OperationKind::NewAddress {
            assert_eq!(
                f.engine
                    .create_review(
                        &f.context,
                        &f.node,
                        key,
                        request(OperationKind::CreateInvoice, f.clock.now())
                    )
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::IdempotencyConflict
            );
        } else {
            for path in paths {
                let mut changed = serde_json::to_value(&original).unwrap();
                let value = changed.pointer_mut(&path).unwrap();
                *value = match path.as_str() {
                    "/params/bolt11" => {
                        serde_json::json!(invoice(1002, "invoice", f.clock.now(), 3600, [45; 32]))
                    }
                    "/params/pubkey" | "/params/peer_pubkey" => {
                        serde_json::json!(bitcoin::secp256k1::PublicKey::from_secret_key(
                            &Secp256k1::new(),
                            &SecretKey::from_slice(&[43; 32]).unwrap()
                        )
                        .to_string())
                    }
                    "/params/address" => {
                        let public = bitcoin::CompressedPublicKey(
                            bitcoin::secp256k1::PublicKey::from_secret_key(
                                &Secp256k1::new(),
                                &SecretKey::from_slice(&[44; 32]).unwrap(),
                            ),
                        );
                        serde_json::json!(bitcoin::Address::p2wpkh(
                            &public,
                            bitcoin::Network::Regtest
                        )
                        .to_string())
                    }
                    _ => match value {
                        serde_json::Value::Bool(boolean) => serde_json::json!(!*boolean),
                        serde_json::Value::Number(number) => {
                            serde_json::json!(number.as_u64().unwrap() + 1)
                        }
                        serde_json::Value::String(text) => {
                            if let Ok(number) = text.parse::<u64>() {
                                serde_json::json!((number + 1).to_string())
                            } else {
                                serde_json::json!(format!("changed-{text}"))
                            }
                        }
                        serde_json::Value::Null => serde_json::json!("1"),
                        _ => unreachable!("only scalar request fields"),
                    },
                };
                let changed: OperationRequest = serde_json::from_value(changed).unwrap();
                assert_eq!(
                    f.engine
                        .create_review(&f.context, &f.node, key, changed)
                        .await
                        .unwrap_err()
                        .code,
                    ErrorCode::IdempotencyConflict,
                    "{kind:?} {path}"
                );
                assert_eq!(f.fake.counts(), (0, 0));
            }
        }
        assert_eq!(
            serde_json::to_value(storage::load_local(&f.engine, op.id).await.unwrap().request)
                .unwrap(),
            serde_json::to_value(original).unwrap()
        );
        let grant = f.authorize(&op).await;
        f.confirm(&op, grant).await.unwrap();
        assert_eq!(f.fake.counts(), (1, 0));
    }
}

#[test]
fn canonical_peer_normalization_preserves_identity_across_wire_key_order_and_case() {
    let lower = request(
        OperationKind::ConnectPeer,
        DateTime::from_timestamp(1800000000, 0).unwrap(),
    );
    let reordered=format!("{{\"params\":{{\"port\":9735,\"host\":\"PEER.EXAMPLE.INVALID\",\"pubkey\":\"{}\"}},\"kind\":\"connect_peer\"}}",peer().to_uppercase());
    let upper: OperationRequest = serde_json::from_str(&reordered).unwrap();
    assert_eq!(
        intent::input("node-a", &intent::normalize(lower).unwrap()),
        intent::input("node-a", &intent::normalize(upper).unwrap())
    );
}
