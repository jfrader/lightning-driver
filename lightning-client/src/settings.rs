use crate::{
    model::{Backend, Network, NodeKind, ReauthMode},
    money::{Decimal, Msat},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::Read,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use url::Url;

const MAX_SECRET_BYTES: u64 = 65536;
pub const MAX_JSON_REQUEST_BYTES: usize = 128 * 1024;
pub const MAX_BOLT11_BYTES: usize = 16384;
pub const MAX_INVOICE_DESCRIPTION_CHARS: usize = 640;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SettingsError(pub &'static str);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub api: ApiSettings,
    pub nodes: Vec<NodeSettings>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSettings {
    pub bind: SocketAddr,
    pub public_origin: Url,
    pub rp_id: String,
    pub database: PathBuf,
    pub invoice_key_file: PathBuf,
    #[serde(default)]
    pub allow_insecure_loopback: bool,
    #[serde(default)]
    pub client_identity: ClientIdentitySettings,
    #[serde(default)]
    pub reauth: ReauthPolicy,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientIdentitySettings {
    pub mode: ClientIdentityMode,
    pub trusted_proxy_cidrs: Vec<ipnet::IpNet>,
    pub header: Option<ClientIdentityHeader>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdentityMode {
    #[default]
    SocketPeer,
    TrustedSingleProxy,
}

#[derive(Clone, Copy, Deserialize)]
pub enum ClientIdentityHeader {
    #[serde(rename = "x-real-ip")]
    XRealIp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReauthPolicy {
    pub mode: ReauthMode,
    pub recent_auth_seconds: Option<u32>,
}

impl Default for ReauthPolicy {
    fn default() -> Self {
        Self {
            mode: ReauthMode::EveryOperation,
            recent_auth_seconds: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaginationPolicy {
    pub default_limit: usize,
    pub max_limit: usize,
    pub snapshot_ttl_seconds: u32,
    pub snapshot_max_items: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub snapshot_max_entries: usize,
    pub snapshot_per_session: usize,
    pub snapshot_cache_bytes: usize,
    pub session_absolute_seconds: u32,
    pub session_idle_seconds: u32,
    pub preauth_seconds: u32,
    pub challenge_seconds: u32,
    pub authorization_seconds: u32,
    pub review_ttl_seconds: u32,
    pub operation_poll_seconds: u32,
    pub rpc_seconds: u32,
    pub max_sessions: usize,
    pub max_challenges: usize,
    pub max_response_bytes: usize,
    pub login_attempts_per_minute: usize,
    pub pagination: PaginationPolicy,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            snapshot_max_entries: 64,
            snapshot_per_session: 8,
            snapshot_cache_bytes: 16 * 1024 * 1024,
            session_absolute_seconds: 28800,
            session_idle_seconds: 900,
            preauth_seconds: 300,
            challenge_seconds: 60,
            authorization_seconds: 60,
            review_ttl_seconds: 300,
            operation_poll_seconds: 3,
            rpc_seconds: 30,
            max_sessions: 32,
            max_challenges: 64,
            max_response_bytes: 8 * 1024 * 1024,
            login_attempts_per_minute: 20,
            pagination: PaginationPolicy {
                default_limit: 50,
                max_limit: 200,
                snapshot_ttl_seconds: 120,
                snapshot_max_items: 10000,
            },
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSettings {
    pub id: String,
    pub label: String,
    pub backend: Backend,
    pub endpoint: Url,
    pub certificate_file: Option<PathBuf>,
    #[serde(default)]
    pub tls_verification: TlsVerification,
    pub credential_file: PathBuf,
    pub expected_pubkey: Option<String>,
    pub expected_genesis: Option<String>,
    pub network: Network,
    pub read_only: Option<bool>,
    pub policy: Option<MoneyPolicy>,
    pub peer_policy: Option<PeerPolicy>,
}

impl NodeSettings {
    pub fn kind(&self) -> NodeKind {
        self.backend.kind()
    }

    fn validate_kind(&self) -> Result<(), SettingsError> {
        if self.kind() == NodeKind::Bitcoin {
            if self.endpoint.scheme() == "https" && self.certificate_file.is_none() {
                return Err(SettingsError("An HTTPS node requires a certificate file"));
            }
            if self.expected_pubkey.is_some()
                || self.read_only.is_some()
                || self.policy.is_some()
                || self.peer_policy.is_some()
            {
                return Err(SettingsError("Bitcoin nodes cannot configure Lightning fields: expected_pubkey, read_only, policy or peer_policy"));
            }
            let genesis = self
                .expected_genesis
                .as_deref()
                .ok_or(SettingsError("Bitcoin nodes require expected_genesis"))?;
            if genesis.len() != 64 || !genesis.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(SettingsError(
                    "Bitcoin expected_genesis must be a 32-byte hex hash",
                ));
            }
            return Ok(());
        }
        if self.certificate_file.is_none() {
            return Err(SettingsError("Lightning nodes require a certificate file"));
        }
        if self.expected_genesis.is_some() {
            return Err(SettingsError(
                "Lightning nodes cannot configure expected_genesis",
            ));
        }
        let expected_pubkey = self
            .expected_pubkey
            .as_deref()
            .ok_or(SettingsError("Lightning nodes require expected_pubkey"))?;
        let identity = expected_pubkey
            .parse::<bitcoin::secp256k1::PublicKey>()
            .map_err(|_| SettingsError("Invalid expected node identity"))?;
        if identity.to_string() != expected_pubkey {
            return Err(SettingsError(
                "Expected node identity must be canonical compressed hex",
            ));
        }
        self.read_only
            .ok_or(SettingsError("Lightning nodes require read_only"))?;
        self.policy
            .as_ref()
            .ok_or(SettingsError("Lightning nodes require policy"))?
            .validate()?;
        let peers = self
            .peer_policy
            .as_ref()
            .ok_or(SettingsError("Lightning nodes require peer_policy"))?;
        for host in &peers.allowed_hosts {
            validate_peer_host(host)?;
        }
        if peers.allowed_ports.contains(&0) {
            return Err(SettingsError("Invalid P2P port policy"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVerification {
    #[default]
    Ca,
    Pinned,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPolicy {
    pub allowed_hosts: Vec<String>,
    pub allowed_ports: Vec<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmountBounds {
    pub min: Decimal,
    pub max: Decimal,
}

impl AmountBounds {
    pub fn contains(&self, value: Decimal) -> bool {
        value >= self.min && value <= self.max
    }
    fn validate(&self) -> Result<(), SettingsError> {
        if self.min == Decimal::ZERO || self.min > self.max {
            return Err(SettingsError("Invalid positive amount bounds"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiryPolicy {
    pub min: u32,
    pub max: u32,
    pub default: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoneyPolicy {
    pub create_invoice_msat: AmountBounds,
    pub pay_invoice_msat: AmountBounds,
    pub open_channel_sat: AmountBounds,
    pub send_onchain_sat: AmountBounds,
    pub fee_rate_sat_vbyte: AmountBounds,
    pub max_routing_fee_msat: Msat,
    pub default_max_routing_fee_msat: Msat,
    pub invoice_expiry_seconds: ExpiryPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodePolicy {
    pub node_id: String,
    pub revision: String,
    pub read_only: bool,
    #[serde(flatten)]
    pub limits: MoneyPolicy,
}

impl Settings {
    pub fn load(path: &Path) -> Result<Self, SettingsError> {
        let path = path
            .canonicalize()
            .map_err(|_| SettingsError("Cannot locate configuration"))?;
        let base = path
            .parent()
            .ok_or(SettingsError("Configuration has no parent directory"))?;
        let mut settings: Self = config::Config::builder()
            .add_source(config::File::from(path.as_path()))
            .build()
            .map_err(|_| SettingsError("Cannot read configuration"))?
            .try_deserialize()
            .map_err(|_| SettingsError("Invalid typed configuration"))?;
        for reference in [
            &mut settings.api.database,
            &mut settings.api.invoice_key_file,
        ] {
            if reference.is_relative() {
                *reference = base.join(&*reference);
            }
        }
        for node in &mut settings.nodes {
            for reference in node
                .certificate_file
                .iter_mut()
                .chain(std::iter::once(&mut node.credential_file))
            {
                if reference.is_relative() {
                    *reference = base.join(&*reference);
                }
            }
        }
        settings.validate()?;
        Ok(settings)
    }

    pub fn validate(&self) -> Result<(), SettingsError> {
        self.api.validate()?;
        let mut ids = HashSet::new();
        for node in &self.nodes {
            if node.id.is_empty()
                || node.id.len() > 64
                || !node
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
                || !node.id.as_bytes()[0].is_ascii_alphanumeric()
                || !ids.insert(&node.id)
            {
                return Err(SettingsError("Invalid or duplicate node id"));
            }
            if node.label.is_empty() || node.label.chars().count() > 120 {
                return Err(SettingsError("Invalid node label"));
            }
            if node.kind() == NodeKind::Bitcoin && node.endpoint.scheme() == "http" {
                let mut secure = node.endpoint.clone();
                secure
                    .set_scheme("https")
                    .map_err(|_| SettingsError("Invalid Bitcoin endpoint"))?;
                validate_endpoint(&secure)?;
            } else {
                validate_endpoint(&node.endpoint)?;
            }
            if node.tls_verification == TlsVerification::Pinned
                && !matches!(
                    node.backend,
                    Backend::LndGrpc | Backend::LndRest | Backend::BitcoinRpc
                )
            {
                return Err(SettingsError("Pinned TLS requires an LND backend"));
            }
            node.validate_kind()?;
            if node.network == Network::Unknown {
                return Err(SettingsError("Expected node network is required"));
            }
        }
        Ok(())
    }
}

impl ApiSettings {
    pub fn insecure_development(&self) -> bool {
        self.allow_insecure_loopback && self.public_origin.scheme() == "http"
    }
    pub fn validate(&self) -> Result<(), SettingsError> {
        let origin = &self.public_origin;
        let identity = &self.client_identity;
        if identity
            .trusted_proxy_cidrs
            .iter()
            .any(|cidr| cidr.prefix_len() == 0)
            || (identity.mode == ClientIdentityMode::TrustedSingleProxy
                && (identity.trusted_proxy_cidrs.is_empty() || identity.header.is_none()))
        {
            return Err(SettingsError("Invalid trusted client identity policy"));
        }
        let origin_loopback = match origin.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        if origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.host_str() != Some(self.rp_id.as_str())
        {
            return Err(SettingsError("Public origin and exact RP host must match"));
        }
        if self.allow_insecure_loopback && (!origin_loopback || !self.bind.ip().is_loopback()) {
            return Err(SettingsError(
                "Development exception requires loopback bind and origin",
            ));
        }
        if origin.scheme() != "https"
            && !(self.allow_insecure_loopback && origin.scheme() == "http" && origin_loopback)
        {
            return Err(SettingsError("Public origin must use HTTPS"));
        }
        if !matches!(
            (&self.reauth.mode, self.reauth.recent_auth_seconds),
            (ReauthMode::EveryOperation, None) | (ReauthMode::Recent, Some(1..))
        ) {
            return Err(SettingsError("Invalid server reauthentication policy"));
        }
        let l = &self.limits;
        if l.pagination.snapshot_max_items.checked_add(1).is_none()
            || l.snapshot_max_entries == 0
            || l.snapshot_per_session == 0
            || l.snapshot_cache_bytes == 0
        {
            return Err(SettingsError("Invalid snapshot cache bounds"));
        }
        let p = &l.pagination;
        if [
            l.session_absolute_seconds,
            l.session_idle_seconds,
            l.preauth_seconds,
            l.challenge_seconds,
            l.authorization_seconds,
            l.review_ttl_seconds,
            l.operation_poll_seconds,
            l.rpc_seconds,
            p.snapshot_ttl_seconds,
        ]
        .contains(&0)
            || l.session_idle_seconds > l.session_absolute_seconds
            || l.max_sessions == 0
            || l.max_challenges == 0
            || l.login_attempts_per_minute == 0
            || l.max_response_bytes == 0
            || p.default_limit == 0
            || p.default_limit > p.max_limit
            || p.max_limit > 200
            || p.snapshot_max_items == 0
        {
            return Err(SettingsError("Invalid centralized runtime limits"));
        }
        Ok(())
    }
}

impl MoneyPolicy {
    fn validate(&self) -> Result<(), SettingsError> {
        for bounds in [
            &self.create_invoice_msat,
            &self.pay_invoice_msat,
            &self.open_channel_sat,
            &self.send_onchain_sat,
            &self.fee_rate_sat_vbyte,
        ] {
            bounds.validate()?;
        }
        let e = &self.invoice_expiry_seconds;
        if self.default_max_routing_fee_msat > self.max_routing_fee_msat
            || e.min == 0
            || e.min > e.default
            || e.default > e.max
        {
            return Err(SettingsError("Invalid fee/expiry policy"));
        }
        Ok(())
    }
}

fn validate_endpoint(endpoint: &Url) -> Result<(), SettingsError> {
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
    {
        return Err(SettingsError(
            "Node endpoint must be an HTTPS origin without userinfo or path",
        ));
    }
    Ok(())
}

pub fn validate_peer_host(host: &str) -> Result<(), SettingsError> {
    if host.is_empty()
        || host.len() > 253
        || host
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '/' | '@' | '?' | '#' | '%' | '\\'))
    {
        return Err(SettingsError("Invalid P2P host"));
    }
    if host.parse::<IpAddr>().is_err() {
        url::Host::parse(host).map_err(|_| SettingsError("Invalid P2P host"))?;
    }
    Ok(())
}

pub fn read_protected(path: &Path, secret: bool) -> Result<Vec<u8>, SettingsError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| SettingsError("Cannot open protected material"))?;
    validate_permissions(&file, secret)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_SECRET_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SettingsError("Cannot read protected material"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_SECRET_BYTES {
        return Err(SettingsError("Invalid protected material size"));
    }
    Ok(bytes)
}

fn validate_permissions(file: &File, secret: bool) -> Result<(), SettingsError> {
    let metadata = file
        .metadata()
        .map_err(|_| SettingsError("Cannot inspect protected material"))?;
    let mask = if secret { 0o077 } else { 0o022 };
    if !metadata.is_file() || metadata.permissions().mode() & mask != 0 {
        return Err(SettingsError("Protected material has unsafe permissions"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn api(origin: &str, development: bool) -> ApiSettings {
        let public_origin = Url::parse(origin).unwrap();
        ApiSettings {
            bind: "127.0.0.1:8080".parse().unwrap(),
            rp_id: public_origin.host_str().unwrap().into(),
            public_origin,
            database: PathBuf::from("unused.sqlite"),
            invoice_key_file: PathBuf::from("unused.key"),
            allow_insecure_loopback: development,
            client_identity: Default::default(),
            reauth: ReauthPolicy::default(),
            limits: Limits::default(),
        }
    }
    #[test]
    fn public_origin_never_inherits_security_from_bind() {
        assert!(api("https://manager.example.invalid", false)
            .validate()
            .is_ok());
        assert!(api("http://manager.example.invalid", false)
            .validate()
            .is_err());
        assert!(api("http://manager.example.invalid", true)
            .validate()
            .is_err());
        assert!(api("http://localhost:8080", true).validate().is_ok());
        assert!(api("http://localhost:8080", false).validate().is_err());
        assert!(api("https://manager.example.invalid/path", false)
            .validate()
            .is_err());
        let mut settings = api("https://manager.example.invalid", false);
        settings.rp_id = "example.invalid".into();
        assert!(settings.validate().is_err());
        let mut settings = api("https://manager.example.invalid", false);
        settings.reauth = ReauthPolicy {
            mode: ReauthMode::Recent,
            recent_auth_seconds: Some(0),
        };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn trusted_identity_requires_explicit_bounded_cidrs_and_fixed_header() {
        let mut settings = api("https://manager.example.invalid", false);
        settings.client_identity.mode = ClientIdentityMode::TrustedSingleProxy;
        assert!(settings.validate().is_err());
        settings.client_identity.trusted_proxy_cidrs = vec!["192.0.2.10/32".parse().unwrap()];
        assert!(settings.validate().is_err());
        settings.client_identity.header = Some(ClientIdentityHeader::XRealIp);
        assert!(settings.validate().is_ok());
        for cidr in ["0.0.0.0/0", "::/0"] {
            settings.client_identity.trusted_proxy_cidrs = vec![cidr.parse().unwrap()];
            assert!(settings.validate().is_err());
        }
        for value in [
            serde_json::json!({"mode":"auto"}),
            serde_json::json!({"header":"x-forwarded-for"}),
            serde_json::json!({"trusted_proxy_cidrs":["not a cidr"]}),
            serde_json::json!({"hops":2}),
        ] {
            assert!(serde_json::from_value::<ClientIdentitySettings>(value).is_err());
        }
    }
    #[test]
    fn peer_input_is_not_a_url_or_credentials() {
        for host in ["peer.example.invalid", "127.0.0.1", "::1"] {
            assert!(validate_peer_host(host).is_ok());
        }
        for host in [
            "https://host",
            "user@host",
            "host/path",
            "host\n",
            "host?query",
            "host%00",
        ] {
            assert!(validate_peer_host(host).is_err(), "{host}");
        }
    }

    #[test]
    fn credential_reads_are_bounded_permission_checked_and_do_not_follow_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("synthetic-secret");
        std::fs::write(&path, b"SYNTHETIC_ONLY").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_protected(&path, true).unwrap(), b"SYNTHETIC_ONLY");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_protected(&path, true).is_err());
        assert!(read_protected(&path, false).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o622)).unwrap();
        assert!(read_protected(&path, false).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let alias = directory.path().join("symlink");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(read_protected(&alias, true).is_err());
        std::fs::write(
            &path,
            vec![0u8; usize::try_from(MAX_SECRET_BYTES + 1).unwrap()],
        )
        .unwrap();
        assert!(read_protected(&path, true).is_err());
        assert!(read_protected(&directory.path().join("missing"), true).is_err());
    }

    #[test]
    fn duplicate_identity_network_and_policy_errors_fail_closed() {
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(
            "../../api-server/tests/fixtures/api-examples.json"
        ))
        .unwrap();
        let policy: NodePolicy =
            serde_json::from_value(fixtures["fixtures"]["node_policy"]["value"].clone()).unwrap();
        let key = bitcoin::secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
        let identity = bitcoin::secp256k1::PublicKey::from_secret_key(
            &bitcoin::secp256k1::Secp256k1::new(),
            &key,
        )
        .to_string();
        let node = NodeSettings {
            id: "synthetic".into(),
            label: "Synthetic".into(),
            backend: Backend::LndGrpc,
            endpoint: "https://node.example.invalid".parse().unwrap(),
            certificate_file: Some(PathBuf::from("UNUSED_CERT")),
            tls_verification: TlsVerification::Ca,
            credential_file: PathBuf::from("UNUSED_CREDENTIAL"),
            expected_pubkey: Some(identity),
            expected_genesis: None,
            network: Network::Regtest,
            read_only: Some(false),
            policy: Some(policy.limits),
            peer_policy: Some(PeerPolicy::default()),
        };
        let mut settings = Settings {
            api: api("https://manager.example.invalid", false),
            nodes: vec![node.clone()],
        };
        assert!(settings.validate().is_ok());
        for (field, message) in [
            (
                "certificate_file",
                "Lightning nodes require a certificate file",
            ),
            ("expected_pubkey", "Lightning nodes require expected_pubkey"),
            ("read_only", "Lightning nodes require read_only"),
            ("policy", "Lightning nodes require policy"),
            ("peer_policy", "Lightning nodes require peer_policy"),
        ] {
            let mut missing = node.clone();
            match field {
                "certificate_file" => missing.certificate_file = None,
                "expected_pubkey" => missing.expected_pubkey = None,
                "read_only" => missing.read_only = None,
                "policy" => missing.policy = None,
                "peer_policy" => missing.peer_policy = None,
                _ => unreachable!(),
            }
            assert_eq!(missing.validate_kind().unwrap_err().0, message);
        }
        let mut stray = node.clone();
        stray.expected_genesis = Some("ab".repeat(32));
        assert_eq!(
            stray.validate_kind().unwrap_err().0,
            "Lightning nodes cannot configure expected_genesis"
        );
        settings.nodes.push(node.clone());
        assert!(settings.validate().is_err());
        settings.nodes.pop();
        settings.nodes[0].tls_verification = TlsVerification::Pinned;
        assert!(settings.validate().is_ok());
        settings.nodes[0].backend = Backend::LndRest;
        assert!(settings.validate().is_ok());
        settings.nodes[0].backend = Backend::ClnRest;
        assert!(settings.validate().is_err());
        settings.nodes[0] = node.clone();
        settings.nodes[0].network = Network::Unknown;
        assert!(settings.validate().is_err());
        settings.nodes[0] = node.clone();
        settings.nodes[0].expected_pubkey = Some("not-a-key".into());
        assert!(settings.validate().is_err());
        settings.nodes[0] = node.clone();
        settings.nodes[0].endpoint = "http://node.example.invalid".parse().unwrap();
        assert!(settings.validate().is_err());
        settings.nodes[0] = node.clone();
        settings.nodes[0]
            .policy
            .as_mut()
            .unwrap()
            .default_max_routing_fee_msat = Msat("9223372036854775807".parse().unwrap());
        assert!(settings.validate().is_err());
        settings.nodes[0] = node;
        settings.nodes[0]
            .policy
            .as_mut()
            .unwrap()
            .send_onchain_sat
            .min = Decimal::ZERO;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn bitcoin_settings_validate_identity_and_reject_lightning_fields() {
        let base = serde_json::json!({
            "id":"bitcoin-lab", "label":"Bitcoin Core lab", "backend":"bitcoin_rpc",
            "endpoint":"https://bitcoin.example.invalid", "certificate_file":"UNUSED_CERT",
            "credential_file":"UNUSED_CREDENTIAL", "network":"testnet4",
            "expected_genesis":"0000000000000000000000000000000000000000000000000000000000000001"
        });
        let check = |value| {
            let node: NodeSettings = serde_json::from_value(value).unwrap();
            assert_eq!(node.kind(), NodeKind::Bitcoin);
            Settings {
                api: api("https://manager.example.invalid", false),
                nodes: vec![node],
            }
            .validate()
        };
        assert!(check(base.clone()).is_ok());
        let mut value = base.clone();
        value.as_object_mut().unwrap().remove("expected_genesis");
        assert_eq!(
            check(value).unwrap_err().0,
            "Bitcoin nodes require expected_genesis"
        );
        for invalid in ["", "not-a-hash", &"ab".repeat(31), &"ab".repeat(33)] {
            let mut value = base.clone();
            value["expected_genesis"] = invalid.into();
            assert_eq!(
                check(value).unwrap_err().0,
                "Bitcoin expected_genesis must be a 32-byte hex hash"
            );
        }
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(
            "../../api-server/tests/fixtures/api-examples.json"
        ))
        .unwrap();
        let policy = &fixtures["fixtures"]["node_policy"]["value"];
        let mut money = policy.clone();
        for key in ["node_id", "revision", "read_only"] {
            money.as_object_mut().unwrap().remove(key);
        }
        for (key, field) in [
            (
                "expected_pubkey",
                serde_json::json!(
                    "021111111111111111111111111111111111111111111111111111111111111111"
                ),
            ),
            ("read_only", serde_json::json!(false)),
            ("policy", money),
            (
                "peer_policy",
                serde_json::json!({"allowed_hosts":[],"allowed_ports":[]}),
            ),
        ] {
            let mut value = base.clone();
            value[key] = field;
            assert_eq!(check(value).unwrap_err().0, "Bitcoin nodes cannot configure Lightning fields: expected_pubkey, read_only, policy or peer_policy");
        }
        let mut value = base;
        value["unexpected"] = true.into();
        assert!(serde_json::from_value::<NodeSettings>(value).is_err());
    }

    #[test]
    fn bitcoin_http_loopback_loads_without_certificate() {
        let (directory, settings) = load_node_configuration(bitcoin_node_configuration());
        let settings = settings.unwrap();
        assert!(settings.nodes[0].certificate_file.is_none());
        assert_eq!(
            settings.nodes[0].credential_file,
            directory.path().join("cookie")
        );
        assert_eq!(
            settings.api.database,
            directory.path().join("manager.sqlite")
        );
    }

    #[test]
    fn bitcoin_https_requires_certificate() {
        let mut node = bitcoin_node_configuration();
        node["endpoint"] = "https://bitcoin.example.invalid/".into();
        let (_, result) = load_node_configuration(node.clone());
        assert_eq!(
            result.err().unwrap().0,
            "An HTTPS node requires a certificate file"
        );
        node["certificate_file"] = "ca.pem".into();
        let (directory, result) = load_node_configuration(node);
        assert_eq!(
            result.unwrap().nodes[0].certificate_file,
            Some(directory.path().join("ca.pem"))
        );
    }

    #[test]
    fn lightning_requires_certificate() {
        let (_, result) = load_node_configuration(lightning_node_configuration());
        assert_eq!(
            result.err().unwrap().0,
            "Lightning nodes require a certificate file"
        );
    }

    #[test]
    fn lightning_with_certificate_loads_and_resolves_paths() {
        let directory = tempfile::tempdir().unwrap();
        for certificate in [PathBuf::from("tls.cert"), directory.path().join("tls.cert")] {
            let mut node = lightning_node_configuration();
            node["certificate_file"] = serde_json::to_value(&certificate).unwrap();
            let (config_directory, result) = load_node_configuration(node);
            let settings = result.unwrap();
            assert_eq!(
                settings.nodes[0].certificate_file,
                Some(if certificate.is_relative() {
                    config_directory.path().join(certificate)
                } else {
                    certificate
                })
            );
        }
    }

    fn bitcoin_node_configuration() -> serde_json::Value {
        serde_json::json!({
            "id":"bitcoin-lab", "label":"Bitcoin Core lab", "backend":"bitcoin_rpc",
            "endpoint":"http://127.0.0.1:18443/", "credential_file":"cookie",
            "network":"regtest", "expected_genesis":"ab".repeat(32)
        })
    }

    fn lightning_node_configuration() -> serde_json::Value {
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(
            "../../api-server/tests/fixtures/api-examples.json"
        ))
        .unwrap();
        let mut policy = fixtures["fixtures"]["node_policy"]["value"].clone();
        for key in ["node_id", "revision", "read_only"] {
            policy.as_object_mut().unwrap().remove(key);
        }
        serde_json::json!({
            "id":"lightning-lab", "label":"Lightning lab", "backend":"lnd_grpc",
            "endpoint":"https://localhost:10009/", "credential_file":"macaroon",
            "network":"regtest",
            "expected_pubkey":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "read_only":false, "policy":policy,
            "peer_policy":{"allowed_hosts":[],"allowed_ports":[]}
        })
    }

    fn load_node_configuration(
        node: serde_json::Value,
    ) -> (tempfile::TempDir, Result<Settings, SettingsError>) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let config = serde_json::json!({
            "api": {
                "bind":"127.0.0.1:8080", "public_origin":"https://manager.example.invalid",
                "rp_id":"manager.example.invalid", "database":"manager.sqlite",
                "invoice_key_file":"invoice.key"
            },
            "nodes":[node]
        });
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let result = Settings::load(&path);
        (directory, result)
    }

    #[test]
    fn tls_verification_is_closed_and_defaults_to_ca() {
        assert_eq!(TlsVerification::default(), TlsVerification::Ca);
        assert_eq!(
            serde_json::from_str::<TlsVerification>("\"ca\"").unwrap(),
            TlsVerification::Ca
        );
        assert_eq!(
            serde_json::from_str::<TlsVerification>("\"pinned\"").unwrap(),
            TlsVerification::Pinned
        );
        for invalid in ["\"insecure\"", "\"Pinned\"", "null", "true", "{}"] {
            assert!(serde_json::from_str::<TlsVerification>(invalid).is_err());
        }
    }
}
