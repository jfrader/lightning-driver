use super::*;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};

fn signed(template: &Value, seed: u8) -> Value {
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap());
    let mut value = template.clone();
    value["pubkey"] = json!(key.x_only_public_key().0.to_string());
    value["id"] = json!("00".repeat(32));
    value["sig"] = json!("00".repeat(64));
    let event: crate::nostr::Event = serde_json::from_value(value.clone()).unwrap();
    let id = event.computed_id().unwrap();
    value["id"] = json!(hex::encode(id));
    value["sig"] = json!(secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(id), &key)
        .to_string());
    value
}

async fn nostr_login(state: &ApplicationState, enrollment: bool) -> Browser {
    let (status, bootstrap, cookie) =
        call(state, get("/api/v1/auth/bootstrap"), "AuthBootstrap").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bootstrap["passkey_login_available"], false);
    assert_eq!(bootstrap["nostr_login_available"], !enrollment);
    assert_eq!(bootstrap["login_available"], !enrollment);
    let guest = cookie.unwrap();
    let csrf = bootstrap["csrf_token"].as_str().unwrap();
    let body = if enrollment {
        let token = state
            .journal
            .issue_enrollment(Utc::now(), std::time::Duration::from_secs(300), false)
            .await
            .unwrap();
        json!({"purpose":"enrollment","token":token.as_str()})
    } else {
        json!({"purpose":"login"})
    };
    let (status, challenge, _) = call(
        state,
        post("/api/v1/auth/nostr/start")
            .cookie(guest.clone())
            .insert_header(("X-CSRF-Token", csrf))
            .set_json(body),
        "NostrChallenge",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    let event = signed(&challenge["event"], 1);
    if enrollment {
        let mut invalid = event.clone();
        invalid["sig"] = json!("00".repeat(64));
        let (status, error, _) = call(
            state,
            post("/api/v1/auth/nostr/finish")
                .cookie(guest.clone())
                .insert_header(("X-CSRF-Token", csrf))
                .set_json(json!({"challenge_id":challenge["challenge_id"],"event":invalid})),
            "Session",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(error["error"]["code"], "authentication_failed");
        assert!(state
            .journal
            .enrollment_available(Utc::now())
            .await
            .unwrap());
    }
    let (status, session, cookie) = call(
        state,
        post("/api/v1/auth/nostr/finish")
            .cookie(guest)
            .insert_header(("X-CSRF-Token", csrf))
            .set_json(json!({"challenge_id":challenge["challenge_id"],"event":event})),
        "Session",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["auth_method"], "nostr");
    assert_eq!(session["nostr_pubkey"], event["pubkey"]);
    assert_eq!(state.journal.credential_counts().await.unwrap(), (0, 1));
    let cookie = cookie.unwrap();
    assert_eq!(cookie.name(), "__Host-ld_session");
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.http_only(), Some(true));
    Browser {
        cookie,
        csrf: session["csrf_token"].as_str().unwrap().into(),
        authenticator: WebauthnAuthenticator::new(SoftPasskey::new(true)),
    }
}

#[actix_web::test]
async fn zero_passkey_nostr_enrollment_login_stepup_confirm_and_unlink() {
    let f = HttpFixture::new().await;
    let enrolled = nostr_login(&f.state, true).await;
    let browser = nostr_login(&f.state, false).await;
    let (status, session, _) = call(
        &f.state,
        authenticated(get("/api/v1/session"), &browser),
        "Session",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(session["auth_method"], "nostr");
    let first_key = session["nostr_pubkey"].clone();
    for kind in [OperationKind::SendOnchain, OperationKind::NewAddress] {
        let operation = create(&f, &browser, kind, Uuid::new_v4()).await;
        let digest = operation["review"]["digest"].clone();
        let (status, error, _) = call(
            &f.state,
            authenticated(post(&path(&operation, "/authorize")), &browser)
                .set_json(json!({"review_digest":digest})),
            "AuthorizationStart",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(error["error"]["code"], "authentication_failed");
        let (status, start, _) = call(
            &f.state,
            authenticated(post(&path(&operation, "/authorize/nostr")), &browser)
                .set_json(json!({"review_digest":digest})),
            "NostrAuthorizationStart",
        )
        .await;
        let authorization = if kind == OperationKind::SendOnchain {
            assert_eq!(status, StatusCode::OK, "{start}");
            let challenge = &start["challenge"];
            let mut wrong = challenge["event"].clone();
            wrong["tags"][5][1] = json!("00".repeat(32));
            let (status,error,_) = call(&f.state,authenticated(post(&path(&operation,"/authorize/nostr/finish")),&browser).set_json(json!({"review_digest":digest,"challenge_id":challenge["challenge_id"],"event":signed(&wrong,1)})),"OperationAuthorization").await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(error["error"]["code"], "authorization_invalid");
            let (status, grant, _) = call(&f.state,authenticated(post(&path(&operation,"/authorize/nostr/finish")),&browser).set_json(json!({"review_digest":digest,"challenge_id":challenge["challenge_id"],"event":signed(&challenge["event"],1)})),"OperationAuthorization").await;
            assert_eq!(status, StatusCode::OK, "{grant}");
            grant["authorization_id"].clone()
        } else {
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(start["error"]["code"], "authorization_not_required");
            Value::Null
        };
        let before = f.fake.counts().0;
        assert_eq!(
            confirm(&f.state, &browser, &operation, authorization.clone())
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            confirm(&f.state, &browser, &operation, authorization)
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(f.fake.counts().0, before + 1);
    }
    let (status, error, _) = call(
        &f.state,
        authenticated(post("/api/v1/auth/nostr/start"), &browser)
            .set_json(json!({"purpose":"unlink","pubkey":first_key})),
        "NostrChallenge",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"]["code"], "last_credential");
    let (status, challenge, _) = call(
        &f.state,
        authenticated(post("/api/v1/auth/nostr/start"), &browser)
            .set_json(json!({"purpose":"link"})),
        "NostrChallenge",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, error, _) = call(
        &f.state,
        authenticated(post("/api/v1/auth/nostr/finish"), &browser)
            .insert_header(("X-CSRF-Token", "wrong"))
            .set_json(json!({"challenge_id":challenge["challenge_id"],"event":signed(&challenge["event"],2)})),
        "NostrIdentityResponse",
    ).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error["error"]["code"], "csrf");
    let (status, linked, _) = call(
        &f.state,
        authenticated(post("/api/v1/auth/nostr/finish"), &browser).set_json(
            json!({"challenge_id":challenge["challenge_id"],"event":signed(&challenge["event"],2)}),
        ),
        "NostrIdentityResponse",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{linked}");
    assert!(linked["identity"]["npub"]
        .as_str()
        .unwrap()
        .starts_with("npub1"));
    let (status, _, _) = call(
        &f.state,
        authenticated(get("/api/v1/session"), &enrolled),
        "Session",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, challenge, _) = call(
        &f.state,
        authenticated(post("/api/v1/auth/nostr/start"), &browser)
            .set_json(json!({"purpose":"unlink","pubkey":linked["identity"]["pubkey"]})),
        "NostrChallenge",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, removed, _) = call(
        &f.state,
        authenticated(post("/api/v1/auth/nostr/finish"), &browser).set_json(
            json!({"challenge_id":challenge["challenge_id"],"event":signed(&challenge["event"],2)}),
        ),
        "NostrRemoved",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(removed, json!({"removed":true}));
    let (status, _, _) = call(
        &f.state,
        authenticated(get("/api/v1/session"), &enrolled),
        "Session",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
