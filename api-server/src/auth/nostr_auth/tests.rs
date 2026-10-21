use super::*;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};

fn key(seed: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[seed; 32]).unwrap(),
    )
}

fn sign(challenge: &NostrChallenge, seed: u8) -> Event {
    let key = key(seed);
    let mut event = Event {
        pubkey: key.x_only_public_key().0.to_string(),
        id: String::new(),
        sig: String::new(),
        kind: challenge.event.kind,
        created_at: challenge.event.created_at,
        tags: challenge.event.tags.clone(),
        content: challenge.event.content.clone(),
    };
    resign(&mut event, seed);
    event
}

fn resign(event: &mut Event, seed: u8) {
    let id = event.computed_id().unwrap();
    event.id = hex::encode(id);
    event.sig = Secp256k1::new()
        .sign_schnorr_no_aux_rand(&Message::from_digest(id), &key(seed))
        .to_string();
}

async fn setup() -> (tempfile::TempDir, AuthManager, DateTime<Utc>) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp/opencode")
        .unwrap();
    let settings = ApiSettings {
        bind: "127.0.0.1:8080".parse().unwrap(),
        public_origin: "https://manager.example.invalid".parse().unwrap(),
        rp_id: "manager.example.invalid".into(),
        database: dir.path().join("auth.sqlite"),
        invoice_key_file: dir.path().join("key"),
        allow_insecure_loopback: false,
        client_identity: Default::default(),
        reauth: Default::default(),
        limits: Default::default(),
    };
    let journal = Journal::open(settings.database.clone()).await.unwrap();
    (
        dir,
        AuthManager::new(&settings, journal).unwrap(),
        Utc::now(),
    )
}

async fn guest(manager: &AuthManager, now: DateTime<Utc>) -> NewContext {
    manager
        .anonymous(ClientIdentity::Socket("192.0.2.1".parse().unwrap()), now)
        .await
        .unwrap()
}

async fn start(
    manager: &AuthManager,
    context: &Context,
    purpose: &str,
    token: Option<String>,
    pubkey: Option<String>,
    now: DateTime<Utc>,
) -> NostrChallenge {
    manager
        .start_nostr(
            context,
            NostrStart {
                purpose: purpose.into(),
                token,
                pubkey,
            },
            now,
        )
        .await
        .unwrap()
}

async fn enroll(manager: &AuthManager, now: DateTime<Utc>, seed: u8) -> NewContext {
    let guest = guest(manager, now).await;
    let token = manager
        .journal
        .issue_enrollment(now, std::time::Duration::from_secs(300), false)
        .await
        .unwrap();
    let challenge = start(
        manager,
        &guest.context,
        "enrollment",
        Some(token.to_string()),
        None,
        now,
    )
    .await;
    let NostrOutcome::Session(session) = manager
        .finish_nostr(
            &guest.context,
            NostrFinish {
                challenge_id: challenge.challenge_id,
                event: sign(&challenge, seed),
            },
            now,
        )
        .await
        .unwrap()
    else {
        panic!("session");
    };
    session
}

#[tokio::test]
async fn enrollment_failure_keeps_token_and_five_attempts_consume() {
    let (_dir, manager, now) = setup().await;
    let guest = guest(&manager, now).await;
    let token = manager
        .journal
        .issue_enrollment(now, std::time::Duration::from_secs(300), false)
        .await
        .unwrap();
    let challenge = start(
        &manager,
        &guest.context,
        "enrollment",
        Some(token.to_string()),
        None,
        now,
    )
    .await;
    let mut invalid = sign(&challenge, 1);
    invalid.sig = "00".repeat(64);
    for _ in 0..5 {
        assert!(matches!(
            manager
                .finish_nostr(
                    &guest.context,
                    NostrFinish {
                        challenge_id: challenge.challenge_id,
                        event: invalid.clone()
                    },
                    now
                )
                .await,
            Err(AuthError::Authentication)
        ));
        assert!(manager.journal.enrollment_available(now).await.unwrap());
    }
    assert!(matches!(
        manager
            .finish_nostr(
                &guest.context,
                NostrFinish {
                    challenge_id: challenge.challenge_id,
                    event: sign(&challenge, 1)
                },
                now
            )
            .await,
        Err(AuthError::Challenge)
    ));
    let challenge = start(
        &manager,
        &guest.context,
        "enrollment",
        Some(token.to_string()),
        None,
        now,
    )
    .await;
    assert!(manager
        .finish_nostr(
            &guest.context,
            NostrFinish {
                challenge_id: challenge.challenge_id,
                event: sign(&challenge, 1)
            },
            now
        )
        .await
        .is_ok());
    assert_eq!(manager.journal.credential_counts().await.unwrap(), (0, 1));
    assert!(!manager.journal.enrollment_available(now).await.unwrap());
}

#[tokio::test]
async fn concurrent_enrollment_finishes_have_exactly_one_success() {
    let (_dir, manager, now) = setup().await;
    let first = guest(&manager, now).await;
    let second = guest(&manager, now).await;
    let token = manager
        .journal
        .issue_enrollment(now, std::time::Duration::from_secs(300), false)
        .await
        .unwrap();
    let a = start(
        &manager,
        &first.context,
        "enrollment",
        Some(token.to_string()),
        None,
        now,
    )
    .await;
    let b = start(
        &manager,
        &second.context,
        "enrollment",
        Some(token.to_string()),
        None,
        now,
    )
    .await;
    let (a, b) = tokio::join!(
        manager.finish_nostr(
            &first.context,
            NostrFinish {
                challenge_id: a.challenge_id,
                event: sign(&a, 1)
            },
            now
        ),
        manager.finish_nostr(
            &second.context,
            NostrFinish {
                challenge_id: b.challenge_id,
                event: sign(&b, 2)
            },
            now
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(
        matches!(a, Err(AuthError::Authentication)) || matches!(b, Err(AuthError::Authentication))
    );
    assert_eq!(manager.journal.credential_counts().await.unwrap(), (0, 1));
}

#[tokio::test]
async fn concurrent_reuse_of_same_enrollment_challenge_is_authentication_failed() {
    let (_dir, manager, now) = setup().await;
    let guest = guest(&manager, now).await;
    let token = manager
        .journal
        .issue_enrollment(now, std::time::Duration::from_secs(300), false)
        .await
        .unwrap();
    let challenge = start(
        &manager,
        &guest.context,
        "enrollment",
        Some(token.to_string()),
        None,
        now,
    )
    .await;
    let finish = || NostrFinish {
        challenge_id: challenge.challenge_id,
        event: sign(&challenge, 1),
    };
    let (a, b) = tokio::join!(
        manager.finish_nostr(&guest.context, finish(), now),
        manager.finish_nostr(&guest.context, finish(), now)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(
        matches!(a, Err(AuthError::Authentication)) || matches!(b, Err(AuthError::Authentication))
    );
}

#[tokio::test]
async fn login_expiry_foreign_context_consumption_and_replay() {
    let (_dir, manager, now) = setup().await;
    enroll(&manager, now, 1).await;
    let a = guest(&manager, now).await;
    let b = guest(&manager, now).await;
    let challenge = start(&manager, &a.context, "login", None, None, now).await;
    let event = sign(&challenge, 1);
    assert!(matches!(
        manager
            .finish_nostr(
                &b.context,
                NostrFinish {
                    challenge_id: challenge.challenge_id,
                    event: event.clone()
                },
                now
            )
            .await,
        Err(AuthError::Challenge)
    ));
    assert!(manager
        .finish_nostr(
            &a.context,
            NostrFinish {
                challenge_id: challenge.challenge_id,
                event: event.clone()
            },
            now
        )
        .await
        .is_ok());
    assert!(manager
        .finish_nostr(
            &a.context,
            NostrFinish {
                challenge_id: challenge.challenge_id,
                event: event.clone()
            },
            now
        )
        .await
        .is_err());
    let challenge = start(&manager, &b.context, "login", None, None, now).await;
    // Direct replay-cache injection isolates reuse from the independently enforced nonce binding.
    let signed = sign(&challenge, 1);
    let id = signed.id.clone();
    manager
        .journal
        .run(move |c| {
            c.execute(
                "INSERT INTO nostr_replays VALUES(?1,?2)",
                params![id, (now + Duration::seconds(120)).timestamp()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(matches!(
        manager
            .finish_nostr(
                &b.context,
                NostrFinish {
                    challenge_id: challenge.challenge_id,
                    event: signed.clone()
                },
                now
            )
            .await,
        Err(AuthError::Authentication)
    ));
    assert!(matches!(
        manager
            .finish_nostr(
                &b.context,
                NostrFinish {
                    challenge_id: challenge.challenge_id,
                    event: signed
                },
                now + Duration::seconds(120)
            )
            .await,
        Err(AuthError::Expired)
    ));
}

#[tokio::test]
async fn unlink_requires_target_signature_and_preserves_last_credential() {
    let (_dir, manager, now) = setup().await;
    let session = enroll(&manager, now, 1).await;
    let first = key(1).x_only_public_key().0.to_string();
    assert!(matches!(
        manager
            .start_nostr(
                &session.context,
                NostrStart {
                    purpose: "unlink".into(),
                    token: None,
                    pubkey: Some(first.clone())
                },
                now
            )
            .await,
        Err(AuthError::LastCredential)
    ));
    let link = start(&manager, &session.context, "link", None, None, now).await;
    assert!(matches!(
        manager
            .finish_nostr(
                &session.context,
                NostrFinish {
                    challenge_id: link.challenge_id,
                    event: sign(&link, 2)
                },
                now
            )
            .await,
        Ok(NostrOutcome::Identity(_))
    ));
    let unlink = start(&manager, &session.context, "unlink", None, Some(first), now).await;
    assert!(matches!(
        manager
            .finish_nostr(
                &session.context,
                NostrFinish {
                    challenge_id: unlink.challenge_id,
                    event: sign(&unlink, 2)
                },
                now
            )
            .await,
        Err(AuthError::Authentication)
    ));
    assert!(matches!(
        manager
            .finish_nostr(
                &session.context,
                NostrFinish {
                    challenge_id: unlink.challenge_id,
                    event: sign(&unlink, 1)
                },
                now
            )
            .await,
        Ok(NostrOutcome::Removed)
    ));
    assert!(manager.context(&session.cookie, true, now).await.is_err());
    assert_eq!(manager.journal.credential_counts().await.unwrap(), (0, 1));
}

#[tokio::test]
async fn unknown_key_and_per_identity_failure_budget_fail_closed() {
    let (_dir, mut manager, now) = setup().await;
    enroll(&manager, now, 1).await;
    manager.admission.starts_per_minute = 2;
    for n in 0..MAX_RATE_BUCKETS {
        manager
            .memory
            .lock()
            .unwrap()
            .nostr_failures
            .insert(format!("unknown-key-{n}"), VecDeque::from([now]));
    }
    let guest = guest(&manager, now).await;
    let challenge = start(&manager, &guest.context, "login", None, None, now).await;
    for _ in 0..2 {
        assert!(matches!(
            manager
                .finish_nostr(
                    &guest.context,
                    NostrFinish {
                        challenge_id: challenge.challenge_id,
                        event: sign(&challenge, 2)
                    },
                    now
                )
                .await,
            Err(AuthError::Authentication)
        ));
    }
    assert!(matches!(
        manager
            .finish_nostr(
                &guest.context,
                NostrFinish {
                    challenge_id: challenge.challenge_id,
                    event: sign(&challenge, 2)
                },
                now
            )
            .await,
        Err(AuthError::Limited)
    ));
    assert!(manager
        .finish_nostr(
            &guest.context,
            NostrFinish {
                challenge_id: challenge.challenge_id,
                event: sign(&challenge, 1)
            },
            now
        )
        .await
        .is_ok());
    assert!(manager.memory.lock().unwrap().nostr_failures.len() <= MAX_RATE_BUCKETS);
}

#[tokio::test]
async fn identity_cap_and_host_recovery_cover_both_authenticators() {
    let (_dir, manager, now) = setup().await;
    let session = enroll(&manager, now, 1).await;
    for seed in 2..=8 {
        let challenge = start(&manager, &session.context, "link", None, None, now).await;
        assert!(manager
            .finish_nostr(
                &session.context,
                NostrFinish {
                    challenge_id: challenge.challenge_id,
                    event: sign(&challenge, seed)
                },
                now
            )
            .await
            .is_ok());
    }
    let challenge = start(&manager, &session.context, "link", None, None, now).await;
    assert!(matches!(
        manager
            .finish_nostr(
                &session.context,
                NostrFinish {
                    challenge_id: challenge.challenge_id,
                    event: sign(&challenge, 9)
                },
                now
            )
            .await,
        Err(AuthError::Limited)
    ));
    manager
        .journal
        .issue_enrollment(now, std::time::Duration::from_secs(60), true)
        .await
        .unwrap();
    assert_eq!(manager.journal.credential_counts().await.unwrap(), (0, 0));
    assert!(manager.context(&session.cookie, true, now).await.is_err());
}

#[test]
fn all_event_field_rejections_use_real_signatures() {
    let now = 1770000000;
    let nonce = "01".repeat(32);
    let tags = vec![
        vec![
            "u".into(),
            "https://[::1]:8443/api/v1/auth/nostr/finish".into(),
        ],
        vec!["method".into(), "POST".into()],
        vec!["challenge".into(), nonce.clone()],
        vec!["purpose".into(), "login".into()],
    ];
    let challenge = NostrChallenge {
        challenge_id: Uuid::new_v4(),
        nonce: nonce.clone(),
        expires_at: DateTime::from_timestamp(now + 120, 0).unwrap(),
        url: tags[0][1].clone(),
        event: EventTemplate {
            kind: 27235,
            created_at: now,
            tags: tags.clone(),
            content: String::new(),
        },
    };
    let event = sign(&challenge, 1);
    let hash = token_hash(nonce.as_bytes());
    assert!(event.verify(&tags, &hash, now).is_ok());
    for mutation in 0..15 {
        let mut bad = event.clone();
        match mutation {
            0 => bad.kind = 1,
            1 => bad.content = "x".into(),
            2..=5 => bad.tags[mutation - 2][1] = "wrong".into(),
            6 => bad.tags.push(bad.tags[0].clone()),
            7 => {
                bad.tags[0].push("extra".into());
            }
            8 => {
                bad.tags.remove(0);
            }
            9 => bad.created_at = now - 121,
            10 => bad.created_at = now + 121,
            11 => bad.tags.push(vec!["unknown".into(), "x".into()]),
            12 => bad.pubkey = "g".repeat(64),
            13 | 14 => {}
            _ => unreachable!(),
        }
        resign(&mut bad, 1);
        if mutation == 13 {
            bad.id = "00".repeat(32);
        }
        if mutation == 14 {
            bad.sig = "00".repeat(64);
        }
        assert!(
            bad.verify(&tags, &hash, now).is_err(),
            "mutation {mutation}"
        );
    }
}

#[tokio::test]
async fn operation_binding_tampering_recent_auth_and_grant_consumption() {
    let (_dir, mut manager, now) = setup().await;
    let session = enroll(&manager, now, 1).await;
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/api-examples.json")).unwrap();
    let mut operation: Operation =
        serde_json::from_value(fixtures["fixtures"]["operation_review"]["value"].clone()).unwrap();
    operation.id = Uuid::new_v4();
    operation.review.operation_id = operation.id;
    operation.review.expires_at = now + Duration::minutes(5);
    assert!(operation.binding_is_valid());
    let NostrAuthorizationStart::ChallengeRequired { challenge } = manager
        .start_nostr_authorization(&session.context, &operation, now)
        .await
        .unwrap()
    else {
        panic!("challenge");
    };
    for index in [0, 4, 5] {
        let mut event = sign(&challenge, 1);
        event.tags[index][1] = "tampered".into();
        resign(&mut event, 1);
        assert!(matches!(
            manager
                .finish_nostr_authorization(
                    &session.context,
                    &operation,
                    NostrFinish {
                        challenge_id: challenge.challenge_id,
                        event
                    },
                    now
                )
                .await,
            Err(AuthError::Authorization)
        ));
    }
    let grant = manager
        .finish_nostr_authorization(
            &session.context,
            &operation,
            NostrFinish {
                challenge_id: challenge.challenge_id,
                event: sign(&challenge, 1),
            },
            now,
        )
        .await
        .unwrap();
    manager
        .consume_grant(
            &session.context,
            &operation,
            Some(grant.authorization_id),
            now,
        )
        .unwrap();
    assert!(manager
        .consume_grant(
            &session.context,
            &operation,
            Some(grant.authorization_id),
            now
        )
        .is_err());
    manager.policy.mode = ReauthMode::Recent;
    manager.policy.recent_auth_seconds = Some(60);
    assert!(matches!(
        manager
            .start_nostr_authorization(&session.context, &operation, now)
            .await,
        Ok(NostrAuthorizationStart::Authorized { .. })
    ));
    assert!(matches!(
        manager
            .start_authorization(&session.context, &operation, now)
            .await,
        Err(AuthError::Authentication)
    ));
}

#[tokio::test]
async fn allocation_failure_and_expiry_do_not_consume_enrollment_token() {
    let (_dir, mut manager, now) = setup().await;
    let guest = guest(&manager, now).await;
    let token = manager
        .journal
        .issue_enrollment(now, std::time::Duration::from_secs(300), false)
        .await
        .unwrap();
    let challenge = start(
        &manager,
        &guest.context,
        "enrollment",
        Some(token.to_string()),
        None,
        now,
    )
    .await;
    let nonce = challenge.nonce.clone();
    manager
        .journal
        .run(move |c| {
            let (binding, hash): (String, Vec<u8>) = c.query_row(
                "SELECT binding,nonce_hash FROM nostr_challenges",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert!(!binding.contains(&nonce));
            assert_eq!(hash, token_hash(nonce.as_bytes()));
            Ok(())
        })
        .await
        .unwrap();
    manager.limits.max_sessions = 0;
    assert!(matches!(
        manager
            .finish_nostr(
                &guest.context,
                NostrFinish {
                    challenge_id: challenge.challenge_id,
                    event: sign(&challenge, 1)
                },
                now
            )
            .await,
        Err(AuthError::Limited)
    ));
    assert!(manager.journal.enrollment_available(now).await.unwrap());
    assert!(matches!(
        manager
            .finish_nostr(
                &guest.context,
                NostrFinish {
                    challenge_id: challenge.challenge_id,
                    event: sign(&challenge, 1)
                },
                now + Duration::seconds(120)
            )
            .await,
        Err(AuthError::Expired)
    ));
    assert!(manager.journal.enrollment_available(now).await.unwrap());
}
