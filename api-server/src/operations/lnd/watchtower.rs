use super::*;
use transport::CallError;

const MAX_SESSIONS_PER_TOWER: usize = 256;
const POLICY_TYPES: [(i32, WatchtowerPolicyType); 3] = [
    (0, WatchtowerPolicyType::Legacy),
    (1, WatchtowerPolicyType::Anchor),
    (2, WatchtowerPolicyType::Taproot),
];

pub(super) struct Probe {
    pub availability: ReadAvailability,
    policies: Vec<(i32, WatchtowerPolicyType)>,
}

fn capability(result: Result<()>) -> Capability {
    let reason = result.err().map(|e| match e.code() {
        ErrorCode::Unsupported => CapabilityReason::Unsupported,
        ErrorCode::NodeAuthError => CapabilityReason::PermissionDenied,
        _ => CapabilityReason::NotConfigured,
    });
    Capability {
        enabled: reason.is_none(),
        reason,
    }
}

impl<T: Wire> LndAdapter<T> {
    pub(super) async fn watchtower_probe(&self) -> &Probe {
        self.watchtower
            .get_or_init(|| async {
                let server = self
                    .probe_call(Rpc::TowerInfo, json!({}))
                    .await
                    .and_then(|v| server(&v, &self.config.binding.node_id).map(|_| ()));
                let mut policies = Vec::new();
                let client = async {
                    stats(&self.probe_call(Rpc::TowerStats, json!({})).await?)?;
                    for (number, kind) in POLICY_TYPES {
                        let reply = self
                            .policy_call(number, &mut self.transport.byte_budget())
                            .await?;
                        if let Some(value) = reply {
                            policy(&value, kind)?;
                            policies.push((number, kind));
                        }
                    }
                    Ok(())
                }
                .await;
                Probe {
                    availability: ReadAvailability {
                        watchtower_server: capability(server),
                        watchtower_client: capability(client),
                        ..ReadAvailability::lightning()
                    },
                    policies,
                }
            })
            .await
    }

    async fn probe_call(&self, rpc: Rpc, params: Value) -> Result<Value> {
        let mut budget = self.transport.byte_budget();
        tokio::time::timeout(
            self.transport.deadline(),
            self.call(rpc, params, &mut budget),
        )
        .await
        .map_err(|_| failure(ErrorCode::NodeOffline))?
    }

    async fn policy_call(&self, number: i32, budget: &mut usize) -> Result<Option<Value>> {
        let reply = tokio::time::timeout(
            self.transport.deadline(),
            self.transport
                .call(Rpc::TowerPolicy, json!({"policy_type":number}), *budget),
        )
        .await
        .map_err(|_| failure(ErrorCode::NodeOffline))?;
        *budget = budget
            .checked_sub(reply.bytes)
            .ok_or_else(|| failure(ErrorCode::NodeOffline))?;
        if matches!(reply.error, Some(CallError::UnregisteredPolicy)) {
            return Ok(None);
        }
        reply.unary().map(|(value, _)| Some(value))
    }

    pub(super) async fn read_watchtower(&self, q: ReadQuery) -> Result<ReadResult> {
        let mut budget = self.transport.byte_budget();
        self.info(&mut budget).await?;
        let node = &self.config.binding.node_id;
        Ok(match q {
            ReadQuery::WatchtowerServer => ReadResult::WatchtowerServer(server(
                &self.call(Rpc::TowerInfo, json!({}), &mut budget).await?,
                node,
            )?),
            ReadQuery::WatchtowerClient => {
                let stats = stats(&self.call(Rpc::TowerStats, json!({}), &mut budget).await?)?;
                let mut policies = Vec::new();
                for (number, kind) in &self.watchtower_probe().await.policies {
                    if let Some(value) = self.policy_call(*number, &mut budget).await? {
                        policies.push(policy(&value, *kind)?);
                    }
                }
                ReadResult::WatchtowerClient(WatchtowerClientInfo {
                    node_id: node.clone(),
                    stats,
                    policies,
                    observed_at: Utc::now(),
                    stale: false,
                })
            }
            ReadQuery::WatchtowerTowers => {
                let v = self
                    .call(
                        Rpc::Towers,
                        json!({"include_sessions":false,"exclude_exhausted_sessions":false}),
                        &mut budget,
                    )
                    .await?;
                let rows = rows(&v, "towers")?;
                let mut items = rows.iter().map(tower).collect::<Result<Vec<_>>>()?;
                items.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
                if items
                    .windows(2)
                    .any(|pair| pair[0].pubkey == pair[1].pubkey)
                {
                    return Err(reads::invalid());
                }
                let truncated = items.len() > self.max_items;
                items.truncate(self.max_items);
                ReadResult::WatchtowerTowers(Collection { items, truncated })
            }
            ReadQuery::WatchtowerTower(key) => {
                let v = self.call(Rpc::Tower, json!({"pubkey":base64::engine::general_purpose::STANDARD.encode(key),"include_sessions":true,"exclude_exhausted_sessions":false}), &mut budget).await?;
                let detail = tower_detail(&v, self.max_items.min(MAX_SESSIONS_PER_TOWER))?;
                if detail.pubkey != hex::encode(key) {
                    return Err(reads::invalid());
                }
                ReadResult::WatchtowerTower(detail)
            }
            _ => return Err(failure(ErrorCode::Unsupported)),
        })
    }
}

fn number(v: &Value, key: &str) -> Result<Decimal> {
    let n = reads::small(v, key)?.unwrap_or(Decimal::ZERO);
    if n.get() > u64::from(u32::MAX) {
        return Err(reads::invalid());
    }
    Ok(n)
}
fn rows<'a>(v: &'a Value, key: &str) -> Result<&'a [Value]> {
    match v.get(key) {
        None => Ok(&[]),
        Some(Value::Array(rows)) => Ok(rows),
        _ => Err(reads::invalid()),
    }
}
fn strings(v: &Value, key: &str) -> Result<Vec<String>> {
    rows(v, key)?
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or_else(reads::invalid))
        .collect()
}
fn key(v: &Value) -> Result<String> {
    let bytes = reads::bytes(v, "pubkey")?;
    let key = bitcoin::secp256k1::PublicKey::from_slice(&bytes).map_err(|_| reads::invalid())?;
    if bytes.len() != 33 {
        return Err(reads::invalid());
    }
    Ok(key.to_string())
}
fn policy_type(v: &Value) -> Result<WatchtowerPolicyType> {
    match v {
        Value::Null => Ok(WatchtowerPolicyType::Legacy),
        Value::String(s) => match s.as_str() {
            "LEGACY" => Ok(WatchtowerPolicyType::Legacy),
            "ANCHOR" => Ok(WatchtowerPolicyType::Anchor),
            "TAPROOT" => Ok(WatchtowerPolicyType::Taproot),
            _ => Err(reads::invalid()),
        },
        _ => POLICY_TYPES
            .iter()
            .find(|(n, _)| v.as_i64() == Some(i64::from(*n)))
            .map(|(_, k)| *k)
            .ok_or_else(reads::invalid),
    }
}
fn server(v: &Value, node: &str) -> Result<WatchtowerServerInfo> {
    Ok(WatchtowerServerInfo {
        node_id: node.into(),
        pubkey: key(v)?,
        listeners: strings(v, "listeners")?,
        uris: strings(v, "uris")?,
        observed_at: Utc::now(),
        stale: false,
    })
}
fn stats(v: &Value) -> Result<WatchtowerStats> {
    Ok(WatchtowerStats {
        num_backups: number(v, "num_backups")?,
        num_pending_backups: number(v, "num_pending_backups")?,
        num_ineligible_backups: number(v, "num_failed_backups")?,
        num_sessions_acquired: number(v, "num_sessions_acquired")?,
        num_sessions_exhausted: number(v, "num_sessions_exhausted")?,
        scope: WatchtowerStatsScope::SinceStartup,
    })
}
fn policy(v: &Value, policy_type: WatchtowerPolicyType) -> Result<WatchtowerPolicy> {
    Ok(WatchtowerPolicy {
        policy_type,
        max_updates: number(v, "max_updates")?,
        sweep_sat_per_vbyte: number(v, "sweep_sat_per_vbyte")?,
    })
}
fn tower(v: &Value) -> Result<WatchtowerTower> {
    Ok(WatchtowerTower {
        pubkey: key(v)?,
        addresses: strings(v, "addresses")?,
        session_info: rows(v, "session_info")?
            .iter()
            .map(|i| {
                if !i.is_object() {
                    return Err(reads::invalid());
                }
                Ok(WatchtowerSessionInfo {
                    policy_type: policy_type(&i["policy_type"])?,
                    active_session_candidate: reads::boolean(i, "active_session_candidate")?
                        .unwrap_or(false),
                    num_sessions: number(i, "num_sessions")?,
                })
            })
            .collect::<Result<_>>()?,
    })
}
fn tower_detail(v: &Value, max: usize) -> Result<WatchtowerTowerDetail> {
    let summary = tower(v)?;
    let mut remaining = max;
    let mut session_info = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (info, raw) in summary
        .session_info
        .into_iter()
        .zip(rows(v, "session_info")?)
    {
        let mut sessions = rows(raw, "sessions")?
            .iter()
            .map(|s| {
                let id = reads::bytes(s, "id")?;
                if id.len() != 33 {
                    return Err(reads::invalid());
                }
                let id = base64::engine::general_purpose::STANDARD.encode(id);
                if !seen.insert(id.clone()) {
                    return Err(reads::invalid());
                }
                Ok(WatchtowerSession {
                    id,
                    num_backups: number(s, "num_backups")?,
                    num_pending_backups: number(s, "num_pending_backups")?,
                    max_backups: number(s, "max_backups")?,
                    sweep_sat_per_vbyte: number(s, "sweep_sat_per_vbyte")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        sessions.sort_by(|a, b| a.id.cmp(&b.id));
        let sessions_truncated =
            sessions.len() > remaining || info.num_sessions.get() > sessions.len() as u64;
        sessions.truncate(remaining);
        remaining -= sessions.len();
        session_info.push(WatchtowerSessionInfoDetail {
            policy_type: info.policy_type,
            active_session_candidate: info.active_session_candidate,
            num_sessions: info.num_sessions,
            sessions_truncated,
            sessions,
        });
    }
    Ok(WatchtowerTowerDetail {
        pubkey: summary.pubkey,
        addresses: summary.addresses,
        session_info,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tower_with_sessions() -> Value {
        let session = |byte| json!({"id":base64::engine::general_purpose::STANDARD.encode([byte;33]),"num_backups":1,"num_pending_backups":0,"max_backups":1024,"sweep_sat_per_vbyte":5});
        json!({"pubkey":base64::engine::general_purpose::STANDARD.encode(hex::decode(synthetic_node_harness::PEER).unwrap()),"addresses":[],"session_info":[
            {"policy_type":"ANCHOR","num_sessions":1,"sessions":[session(1)]},
            {"policy_type":"TAPROOT","num_sessions":1,"sessions":[session(2)]}
        ]})
    }

    #[test]
    fn session_limit_is_shared_by_all_policy_groups_in_a_tower() {
        let detail = tower_detail(&tower_with_sessions(), 1).unwrap();
        assert_eq!(detail.session_info[0].sessions.len(), 1);
        assert!(!detail.session_info[0].sessions_truncated);
        assert!(detail.session_info[1].sessions.is_empty());
        assert!(detail.session_info[1].sessions_truncated);
        assert_eq!(detail.session_info[1].num_sessions.get(), 1);
    }

    #[test]
    fn invalid_session_groups_and_duplicate_or_invalid_ids_are_rejected() {
        let mut raw = tower_with_sessions();
        raw["session_info"][1]["sessions"][0]["id"] =
            raw["session_info"][0]["sessions"][0]["id"].clone();
        assert_eq!(
            tower_detail(&raw, 1).err().unwrap().code(),
            ErrorCode::UpstreamInvalidResponse
        );
        raw["session_info"][1]["sessions"][0]["id"] =
            json!(base64::engine::general_purpose::STANDARD.encode([0; 32]));
        assert_eq!(
            tower_detail(&raw, 1).err().unwrap().code(),
            ErrorCode::UpstreamInvalidResponse
        );
        raw["session_info"] = json!([true]);
        assert_eq!(
            tower_detail(&raw, 1).err().unwrap().code(),
            ErrorCode::UpstreamInvalidResponse
        );
    }
}
