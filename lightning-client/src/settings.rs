use crate::{
    model::{Backend, Network, ReauthMode},
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
    pub reauth: ReauthPolicy,
    #[serde(default)]
    pub limits: Limits,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
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
    pub certificate_file: PathBuf,
    pub credential_file: PathBuf,
    pub expected_pubkey: String,
    pub network: Network,
    pub read_only: bool,
    pub policy: MoneyPolicy,
    #[serde(default)]
    pub peer_policy: PeerPolicy,
}

#[derive(Clone, Debug, Default, Deserialize)]
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
            for reference in [&mut node.certificate_file, &mut node.credential_file] {
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
            validate_endpoint(&node.endpoint)?;
            let identity = node
                .expected_pubkey
                .parse::<bitcoin::secp256k1::PublicKey>()
                .map_err(|_| SettingsError("Invalid expected node identity"))?;
            if identity.to_string() != node.expected_pubkey {
                return Err(SettingsError(
                    "Expected node identity must be canonical compressed hex",
                ));
            }
            if node.network == Network::Unknown {
                return Err(SettingsError("Expected node network is required"));
            }
            node.policy.validate()?;
            for host in &node.peer_policy.allowed_hosts {
                validate_peer_host(host)?;
            }
            if node.peer_policy.allowed_ports.contains(&0) {
                return Err(SettingsError("Invalid P2P port policy"));
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
            certificate_file: PathBuf::from("UNUSED_CERT"),
            credential_file: PathBuf::from("UNUSED_CREDENTIAL"),
            expected_pubkey: identity,
            network: Network::Regtest,
            read_only: false,
            policy: policy.limits,
            peer_policy: PeerPolicy::default(),
        };
        let mut settings = Settings {
            api: api("https://manager.example.invalid", false),
            nodes: vec![node.clone()],
        };
        assert!(settings.validate().is_ok());
        settings.nodes.push(node.clone());
        assert!(settings.validate().is_err());
        settings.nodes.pop();
        settings.nodes[0].network = Network::Unknown;
        assert!(settings.validate().is_err());
        settings.nodes[0] = node.clone();
        settings.nodes[0].expected_pubkey = "not-a-key".into();
        assert!(settings.validate().is_err());
        settings.nodes[0] = node.clone();
        settings.nodes[0].endpoint = "http://node.example.invalid".parse().unwrap();
        assert!(settings.validate().is_err());
        settings.nodes[0] = node.clone();
        settings.nodes[0].policy.default_max_routing_fee_msat =
            Msat("9223372036854775807".parse().unwrap());
        assert!(settings.validate().is_err());
        settings.nodes[0] = node;
        settings.nodes[0].policy.send_onchain_sat.min = Decimal::ZERO;
        assert!(settings.validate().is_err());
    }
}
