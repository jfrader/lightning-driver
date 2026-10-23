use super::*;
use crate::{error::ApiError, registry::Registry};
use lightning_client::settings::{read_protected, NodeSettings, Settings};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

const EXECUTION_TASKS: usize = 64;

impl From<EngineError> for ApiError {
    fn from(error: EngineError) -> Self {
        let mut response = Self::new(error.code);
        response.operation_id = error.operation_id;
        response.outcome = error.outcome;
        response
    }
}

impl Engine {
    pub(crate) async fn read_node(
        &self,
        id: &str,
        query: ReadQuery,
    ) -> std::result::Result<(ReadResult, String), ApiError> {
        if let Some((_, code)) = self.unavailable.get(id) {
            return Err(ApiError::new(*code));
        }
        if let Some(monitor) = self.monitors.get(id) {
            let _permit = self
                .tasks
                .try_acquire()
                .map_err(|_| ApiError::new(ErrorCode::RateLimited))?;
            return Ok((monitor.reads.read(query).await?, monitor.revision.clone()));
        }
        let pinned = self.pinned(id)?;
        let _permit = self
            .tasks
            .try_acquire()
            .map_err(|_| ApiError::new(ErrorCode::RateLimited))?;
        let result = pinned.reads.read(query).await?;
        let current = self.pinned(id)?;
        if current.config.generation != pinned.config.generation {
            return Err(ApiError::new(ErrorCode::IdentityChanged));
        }
        Ok((result, pinned.config.binding.identity_revision))
    }
    pub(crate) async fn from_settings(
        settings: &Settings,
        registry: &mut Registry,
        journal: Journal,
        auth: AuthManager,
    ) -> std::result::Result<Self, ApiError> {
        let pending = journal
            .run(|connection| {
                Ok(connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pending_invoice_secrets)",
                    [],
                    |row| row.get::<_, bool>(0),
                )?)
            })
            .await?;
        let key = load_key(&settings.api.invoice_key_file, pending)?;
        let mut nodes = BTreeMap::new();
        let mut unavailable = BTreeMap::new();
        let mut monitors = BTreeMap::new();
        for node in &settings.nodes {
            let entry = registry
                .get(&node.id)
                .ok_or_else(|| failure(ErrorCode::NotConfigured))?;
            if node.kind() == NodeKind::Bitcoin {
                match crate::bitcoin::BitcoinReads::connect(node, &settings.api.limits).await {
                    Ok(reads) => {
                        monitors.insert(
                            node.id.clone(),
                            MonitorNode {
                                reads: Arc::new(reads),
                                revision: entry.binding_revision.clone(),
                            },
                        );
                    }
                    Err(error) => {
                        unavailable.insert(node.id.clone(), (true, error.code()));
                    }
                }
                continue;
            }
            let result = construct(node, &settings.api, entry).await;
            match result {
                Ok(pinned) => {
                    registry.register_availability(&node.id, pinned.reads.availability().await);
                    nodes.insert(node.id.clone(), Arc::new(Mutex::new(Some(pinned))));
                }
                Err(error) => {
                    unavailable.insert(
                        node.id.clone(),
                        (node.read_only.unwrap_or(true), error.code),
                    );
                }
            }
        }
        Ok(Self {
            journal,
            reads: None,
            auth,
            nodes: Arc::new(nodes),
            monitors: Arc::new(monitors),
            unavailable: Arc::new(unavailable),
            clock: Arc::new(WallClock),
            key: Arc::new(key),
            tasks: Arc::new(tokio::sync::Semaphore::new(EXECUTION_TASKS)),
            observations: Arc::default(),
            faults: Faults::default(),
        })
    }

    pub(crate) fn unavailable(&self, id: &str) -> Option<ErrorCode> {
        self.unavailable.get(id).map(|(_, code)| *code)
    }
}

// Bind the connection generation to effective settings AND protected material, never paths alone.
fn material_revision(node: &NodeSettings, binding: &str) -> Result<[u8; 32]> {
    let certificate = read_protected(
        node.certificate_file
            .as_deref()
            .ok_or_else(|| failure(ErrorCode::NotConfigured))?,
        false,
    )
    .map_err(|_| failure(ErrorCode::NotConfigured))?;
    let credential = zeroize::Zeroizing::new(
        read_protected(&node.credential_file, true)
            .map_err(|_| failure(ErrorCode::NotConfigured))?,
    );
    let mut hash = Sha256::new();
    hash.update(binding.as_bytes());
    hash.update(Sha256::digest(&certificate));
    hash.update(Sha256::digest(&credential));
    Ok(hash.finalize().into())
}

async fn construct(
    node: &NodeSettings,
    api: &lightning_client::settings::ApiSettings,
    entry: &crate::registry::Entry,
) -> Result<PinnedNode> {
    let revision = material_revision(node, &entry.binding_revision)?;
    let network = match node.network {
        Network::Mainnet => VerifiedNetwork::Mainnet,
        Network::Testnet => VerifiedNetwork::Testnet,
        Network::Testnet4 => VerifiedNetwork::Testnet4,
        Network::Signet => VerifiedNetwork::Signet,
        Network::Regtest => VerifiedNetwork::Regtest,
        Network::Unknown => return Err(failure(ErrorCode::NotConfigured)),
    };
    let config = NodeConfig {
        binding: NodeBinding {
            node_id: node.id.clone(),
            network,
            identity_pubkey: node
                .expected_pubkey
                .clone()
                .ok_or_else(|| failure(ErrorCode::NotConfigured))?,
            identity_revision: hex::encode(revision),
        },
        generation: Uuid::from_bytes(
            revision[..16]
                .try_into()
                .map_err(|_| failure(ErrorCode::InternalError))?,
        ),
        backend: node.backend,
        policy: entry
            .policy
            .clone()
            .ok_or_else(|| failure(ErrorCode::NotConfigured))?,
        peer_policy: node
            .peer_policy
            .clone()
            .ok_or_else(|| failure(ErrorCode::NotConfigured))?,
        reauth_mode: api.reauth.mode,
        capabilities: Capabilities::uniform(None),
        review_seconds: api.limits.review_ttl_seconds,
        freshness_seconds: api.limits.rpc_seconds,
    };
    let adapter: Arc<dyn Adapter> = match node.backend {
        Backend::LndGrpc => lnd::connect_grpc(node, &api.limits, config.clone()).await?,
        Backend::LndRest => lnd::connect_rest(node, &api.limits, config.clone()).await?,
        Backend::ClnRest => {
            Arc::new(cln::ClnAdapter::connect(node, &api.limits, config.clone()).await?)
        }
        Backend::BitcoinRpc => return Err(failure(ErrorCode::Unsupported)),
    };
    if material_revision(node, &entry.binding_revision)? != revision {
        return Err(failure(ErrorCode::NotConfigured));
    }
    Ok(PinnedNode {
        config,
        reads: adapter.clone(),
        adapter,
    })
}

fn load_key(path: &Path, pending: bool) -> std::result::Result<PendingSecretKey, ApiError> {
    let storage = || ApiError::new(ErrorCode::StorageUnavailable);
    crate::journal::validate_state_directory(path).map_err(|_| storage())?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(|_| storage())?.join(path)
    };
    for ancestor in absolute.parent().ok_or_else(storage)?.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| storage())?;
        let trusted_owner =
            metadata.uid() == 0 || metadata.uid() == rustix::process::geteuid().as_raw();
        let root_sticky = metadata.uid() == 0 && metadata.permissions().mode() & libc::S_ISVTX != 0;
        if !metadata.is_dir()
            || !trusted_owner
            || (metadata.permissions().mode() & 0o022 != 0 && !root_sticky)
        {
            return Err(storage());
        }
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !pending => {
            let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(bytes.as_mut());
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .map_err(|_| storage())?;
            file.write_all(bytes.as_ref()).map_err(|_| storage())?;
            file.sync_all().map_err(|_| storage())?;
            std::fs::File::open(path.parent().ok_or_else(storage)?)
                .and_then(|parent| parent.sync_all())
                .map_err(|_| storage())?;
            options.open(path).map_err(|_| storage())?
        }
        Err(_) => return Err(storage()),
    };
    let metadata = file.metadata().map_err(|_| storage())?;
    if !metadata.is_file()
        || metadata.len() != 32
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(storage());
    }
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    file.read_exact(bytes.as_mut()).map_err(|_| storage())?;
    Ok(PendingSecretKey::new(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_only_adapter_can_override_registration_availability() {
        struct ReadOnly;
        impl Reads for ReadOnly {
            fn availability(&self) -> ResponseFuture<'_, ReadAvailability> {
                Box::pin(async {
                    ReadAvailability {
                        watchtower_client: Capability {
                            enabled: false,
                            reason: Some(CapabilityReason::PermissionDenied),
                        },
                        ..ReadAvailability::lightning()
                    }
                })
            }
        }
        let reads: Arc<dyn Reads> = Arc::new(ReadOnly);
        let availability = reads.availability().await;
        assert!(!availability.watchtower_client.enabled);
        assert_eq!(
            availability.watchtower_client.reason,
            Some(CapabilityReason::PermissionDenied)
        );
        assert!(availability.peers.enabled);
        assert_eq!(
            reads.read(ReadQuery::Peers).await.err().unwrap().code(),
            ErrorCode::Unsupported
        );
    }

    fn directory() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn pending_key_is_stable_and_never_replaced_when_missing_or_unsafe() {
        let directory = directory();
        let path = directory.path().join("invoice.key");
        assert!(load_key(&path, true).is_err());
        assert!(!path.exists());
        load_key(&path, false).unwrap();
        let original = std::fs::read(&path).unwrap();
        assert_eq!(original.len(), 32);
        load_key(&path, true).unwrap();
        assert_eq!(original, std::fs::read(&path).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_key(&path, false).is_err());
        assert_eq!(original, std::fs::read(&path).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, [0; 31]).unwrap();
        assert!(load_key(&path, false).is_err());
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(directory.path().join("missing"), &path).unwrap();
        assert!(load_key(&path, false).is_err());
        assert!(!directory.path().join("missing").exists());
    }

    #[tokio::test]
    async fn production_state_registers_all_adapters_despite_failed_lnd_surface_probes() {
        let directory = directory();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let certificate = directory.path().join("synthetic.pem");
        let credential = directory.path().join("synthetic.credential");
        std::fs::write(
            &certificate,
            include_bytes!("../../tests/fixtures/cln-v25.02/synthetic-ca.pem"),
        )
        .unwrap();
        std::fs::write(&credential, b"SYNTHETIC_CREDENTIAL").unwrap();
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/api-examples.json")).unwrap();
        let policy: NodePolicy =
            serde_json::from_value(fixtures["fixtures"]["node_policy"]["value"].clone()).unwrap();
        let nodes = [Backend::LndGrpc, Backend::LndRest, Backend::ClnRest].into_iter().enumerate().map(|(index, backend)| {
            serde_json::from_value(serde_json::json!({
                "id":format!("synthetic-{index}"),"label":"Synthetic", "backend":backend,
                "endpoint":format!("https://localhost:{}/",listener.local_addr().unwrap().port()),
                "certificate_file":certificate,"credential_file":credential,
                "expected_pubkey":"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                "network":"regtest","read_only":false,"policy":policy.limits,"peer_policy":{"allowed_hosts":[],"allowed_ports":[]}
            })).unwrap()
        }).collect();
        let settings = Settings {
            api: lightning_client::settings::ApiSettings {
                bind: "127.0.0.1:0".parse().unwrap(),
                public_origin: "https://manager.example.invalid".parse().unwrap(),
                rp_id: "manager.example.invalid".into(),
                database: directory.path().join("journal.sqlite"),
                invoice_key_file: directory.path().join("invoice.key"),
                allow_insecure_loopback: false,
                client_identity: Default::default(),
                reauth: Default::default(),
                limits: lightning_client::settings::Limits {
                    rpc_seconds: 1,
                    ..Default::default()
                },
            },
            nodes,
        };
        let state = crate::state::ApplicationState::new(
            &settings,
            Journal::open(settings.api.database.clone()).await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(state.engine.nodes.len(), 3);
        assert!(state.engine.unavailable.is_empty());
        for (id, entry) in state.registry.entries() {
            let mut expected = ReadAvailability::lightning();
            if id != "synthetic-2" {
                let unavailable = Capability {
                    enabled: false,
                    reason: Some(CapabilityReason::NotConfigured),
                };
                expected.watchtower_server = unavailable.clone();
                expected.watchtower_client = unavailable;
            }
            assert_eq!(
                serde_json::to_value(
                    entry
                        .summary(Utc::now(), lightning_client::money::Decimal::ZERO)
                        .read_availability
                )
                .unwrap(),
                serde_json::to_value(expected).unwrap()
            );
        }
        let mut without_policy = settings.clone();
        without_policy.nodes[0].policy = None;
        assert!(matches!(
            Registry::new(&without_policy),
            Err(crate::registry::RegistryError::LightningPolicyRequired)
        ));
        tokio::task::yield_now().await;
        assert!(
            listener.accept().is_ok(),
            "LND registration probes contact the configured endpoint"
        );
    }
}
