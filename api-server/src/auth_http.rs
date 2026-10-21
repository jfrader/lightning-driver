use crate::{
    auth::{
        AuthManager, AuthenticationFinish, ClientIdentity, Context, NewContext, NostrFinish,
        NostrOutcome, NostrStart, RegistrationFinish,
    },
    error::ApiError,
    journal::Journal,
};
use actix_web::{
    cookie::{time::Duration as CookieDuration, Cookie, SameSite},
    http::header,
    middleware::DefaultHeaders,
    web, HttpMessage, HttpRequest, HttpResponse,
};
use chrono::Utc;
use lightning_client::{
    model::ErrorCode,
    settings::{
        ApiSettings, ClientIdentityMode, PaginationPolicy, ReauthPolicy, MAX_JSON_REQUEST_BYTES,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};
use zeroize::Zeroizing;

const SESSION_COOKIE: &str = "__Host-ld_session";
const PREAUTH_COOKIE: &str = "__Host-ld_preauth";
const DEV_SESSION_COOKIE: &str = "ld_dev_session";
const DEV_PREAUTH_COOKIE: &str = "ld_dev_preauth";
const MAX_IDENTITY_HEADER_BYTES: usize = 45;

#[derive(Clone)]
pub struct AuthHttp {
    pub manager: AuthManager,
    settings: Arc<ApiSettings>,
}

#[derive(Serialize)]
struct Bootstrap {
    csrf_token: String,
    expires_at: chrono::DateTime<Utc>,
    login_available: bool,
    passkey_login_available: bool,
    nostr_login_available: bool,
    enrollment_available: bool,
    public_origin: String,
    rp_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentStart {
    enrollment_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Serialize)]
struct PublicPolicy {
    reauth: ReauthPolicy,
    pagination: PaginationPolicy,
    review_ttl_seconds: u32,
    operation_poll_seconds: u32,
    session_absolute_seconds: u32,
    session_idle_seconds: u32,
}

impl AuthHttp {
    pub fn new(settings: ApiSettings, journal: Journal) -> Result<Self, ApiError> {
        settings
            .validate()
            .map_err(|_| ApiError::new(ErrorCode::NotConfigured))?;
        Ok(Self {
            manager: AuthManager::new(&settings, journal.clone())?,
            settings: Arc::new(settings),
        })
    }

    pub(crate) fn limits(&self) -> &lightning_client::settings::Limits {
        &self.settings.limits
    }

    pub fn headers() -> DefaultHeaders {
        DefaultHeaders::new()
            .add((header::CACHE_CONTROL, "no-store"))
            .add((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
            .add((header::X_FRAME_OPTIONS, "DENY"))
    }

    fn cookie_name(&self, authenticated: bool) -> &'static str {
        match (self.settings.insecure_development(), authenticated) {
            (false, true) => SESSION_COOKIE,
            (false, false) => PREAUTH_COOKIE,
            (true, true) => DEV_SESSION_COOKIE,
            (true, false) => DEV_PREAUTH_COOKIE,
        }
    }

    fn cookie(&self, name: &'static str, value: String, seconds: i64) -> Cookie<'static> {
        Cookie::build(name, value)
            .path("/")
            .secure(!self.settings.insecure_development())
            .http_only(true)
            .same_site(SameSite::Strict)
            .max_age(CookieDuration::seconds(seconds))
            .finish()
    }

    pub fn validate_request(&self, request: &HttpRequest, mutation: bool) -> Result<(), ApiError> {
        self.identity(request)?;
        let expected_host =
            &self.settings.public_origin[url::Position::BeforeHost..url::Position::AfterPort];
        if request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            != Some(expected_host)
        {
            return Err(ApiError::new(ErrorCode::Origin));
        }
        let origin = request
            .headers()
            .get(header::ORIGIN)
            .map(|value| value.to_str().map_err(|_| ApiError::new(ErrorCode::Origin)))
            .transpose()?;
        let expected_origin = self.settings.public_origin.origin().ascii_serialization();
        if (mutation && origin.is_none()) || origin.is_some_and(|origin| origin != expected_origin)
        {
            return Err(ApiError::new(ErrorCode::Origin));
        }
        if let Some(site) = request.headers().get("Sec-Fetch-Site") {
            if !matches!(site.to_str(), Ok("same-origin" | "none")) {
                return Err(ApiError::new(ErrorCode::Origin));
            }
        }
        if request.method() == actix_web::http::Method::POST
            && request.content_type() != "application/json"
        {
            return Err(ApiError::new(ErrorCode::UnsupportedMediaType));
        }
        Ok(())
    }

    pub async fn context(
        &self,
        request: &HttpRequest,
        authenticated: bool,
        mutation: bool,
    ) -> Result<Context, ApiError> {
        self.validate_request(request, mutation)?;
        let cookie = request
            .cookie(self.cookie_name(authenticated))
            .ok_or_else(|| ApiError::new(ErrorCode::SessionRequired))?;
        let context = self
            .manager
            .context(cookie.value(), authenticated, Utc::now())
            .await?;
        if mutation {
            let csrf = request
                .headers()
                .get("X-CSRF-Token")
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| ApiError::new(ErrorCode::Csrf))?;
            AuthManager::verify_csrf(&context, csrf)?;
        }
        Ok(context)
    }

    fn identity(&self, request: &HttpRequest) -> Result<ClientIdentity, ApiError> {
        if let Some(identity) = request.extensions().get::<ClientIdentity>() {
            return Ok(*identity);
        }
        let peer = request
            .peer_addr()
            .map(|address| address.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let normalized_peer = normalize_ip(peer);
        let policy = &self.settings.client_identity;
        let identity = if policy.mode == ClientIdentityMode::TrustedSingleProxy
            && policy.trusted_proxy_cidrs.iter().any(|cidr| {
                let address = match (cidr.network(), normalized_peer) {
                    (IpAddr::V6(network), IpAddr::V4(address))
                        if network.to_ipv4_mapped().is_some() =>
                    {
                        IpAddr::V6(address.to_ipv6_mapped())
                    }
                    _ => normalized_peer,
                };
                cidr.contains(&peer) || cidr.contains(&address)
            }) {
            let mut values = request.headers().get_all("X-Real-IP");
            let value = values
                .next()
                .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest))?;
            if values.next().is_some() || value.as_bytes().len() > MAX_IDENTITY_HEADER_BYTES {
                return Err(ApiError::new(ErrorCode::InvalidRequest));
            }
            let text = value
                .to_str()
                .map_err(|_| ApiError::new(ErrorCode::InvalidRequest))?;
            let ip: IpAddr = text
                .parse()
                .map_err(|_| ApiError::new(ErrorCode::InvalidRequest))?;
            if ip.to_string() != text {
                return Err(ApiError::new(ErrorCode::InvalidRequest));
            }
            ClientIdentity::Forwarded(normalize_ip(ip))
        } else {
            ClientIdentity::Socket(normalized_peer)
        };
        request.extensions_mut().insert(identity);
        Ok(identity)
    }

    pub(crate) fn admit_start(&self, request: &HttpRequest) -> Result<(), ApiError> {
        self.manager
            .admit_start(self.identity(request)?, Utc::now())?;
        Ok(())
    }

    fn completed(&self, context: NewContext) -> Result<HttpResponse, ApiError> {
        let session = self.manager.session(&context.context)?;
        let remaining = (session.expires_at - Utc::now()).num_seconds().max(0);
        Ok(HttpResponse::Ok()
            .cookie(self.cookie(
                self.cookie_name(true),
                context.cookie.to_string(),
                remaining,
            ))
            .cookie(self.cookie(self.cookie_name(false), String::new(), 0))
            .json(session))
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .app_data(
            web::JsonConfig::default()
                .limit(MAX_JSON_REQUEST_BYTES)
                .error_handler(|error, _| {
                    let code = if matches!(error, actix_web::error::JsonPayloadError::ContentType) {
                        ErrorCode::UnsupportedMediaType
                    } else {
                        ErrorCode::InvalidRequest
                    };
                    ApiError::new(code).into()
                }),
        )
        .route("/auth/bootstrap", web::get().to(bootstrap))
        .route("/auth/passkey/start", web::post().to(start_login))
        .route("/auth/nostr/start", web::post().to(start_nostr))
        .route("/auth/nostr/finish", web::post().to(finish_nostr))
        .route("/auth/nostr/identities", web::get().to(nostr_identities))
        .route("/auth/passkey/finish", web::post().to(finish_login))
        .route("/auth/enrollment/start", web::post().to(start_enrollment))
        .route("/auth/enrollment/finish", web::post().to(finish_enrollment))
        .route("/session", web::get().to(session))
        .route("/session", web::delete().to(logout))
        .route("/config", web::get().to(public_policy));
}

async fn bootstrap(
    request: HttpRequest,
    application: web::Data<crate::state::ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    let state = &application.auth;
    state.validate_request(&request, false)?;
    if let Some(cookie) = request.cookie(state.cookie_name(false)) {
        if let Ok(old) = state
            .manager
            .context(cookie.value(), false, Utc::now())
            .await
        {
            state.manager.revoke(&old)?;
        }
    }
    let context = state
        .manager
        .anonymous(state.identity(&request)?, Utc::now())
        .await?;
    let body = Bootstrap {
        csrf_token: AuthManager::csrf(&context.context).into(),
        expires_at: context.context.expires_at,
        login_available: state.manager.login_available().await?,
        passkey_login_available: state.manager.passkey_login_available().await?,
        nostr_login_available: state.manager.nostr_login_available().await?,
        enrollment_available: application.journal.enrollment_available(Utc::now()).await?,
        public_origin: state.settings.public_origin.origin().ascii_serialization(),
        rp_id: state.settings.rp_id.clone(),
    };
    Ok(HttpResponse::Ok()
        .cookie(state.cookie(
            state.cookie_name(false),
            context.cookie.to_string(),
            i64::from(state.settings.limits.preauth_seconds),
        ))
        .json(body))
}

async fn start_login(
    request: HttpRequest,
    application: web::Data<crate::state::ApplicationState>,
    _body: web::Json<Empty>,
) -> Result<HttpResponse, ApiError> {
    let state = &application.auth;
    let context = state.context(&request, false, true).await?;
    state.admit_start(&request)?;
    Ok(HttpResponse::Ok().json(state.manager.start_login(&context, Utc::now()).await?))
}

async fn start_nostr(
    request: HttpRequest,
    application: web::Data<crate::state::ApplicationState>,
    body: web::Json<NostrStart>,
) -> Result<HttpResponse, ApiError> {
    let state = &application.auth;
    let authenticated = matches!(body.purpose.as_str(), "link" | "unlink");
    let context = state.context(&request, authenticated, true).await?;
    state.admit_start(&request)?;
    Ok(HttpResponse::Ok().json(
        state
            .manager
            .start_nostr(&context, body.into_inner(), Utc::now())
            .await?,
    ))
}

async fn finish_nostr(
    request: HttpRequest,
    application: web::Data<crate::state::ApplicationState>,
    body: web::Json<NostrFinish>,
) -> Result<HttpResponse, ApiError> {
    let state = &application.auth;
    state.admit_start(&request)?;
    // Pick the bound context from the cookie that matches the CSRF token. A stale
    // preauth cookie must not hide the operator's authenticated context.
    let context = match state.context(&request, true, true).await {
        Ok(context) => context,
        Err(error) if request.cookie(state.cookie_name(false)).is_none() => return Err(error),
        Err(_) => state.context(&request, false, true).await?,
    };
    match state
        .manager
        .finish_nostr(&context, body.into_inner(), Utc::now())
        .await?
    {
        NostrOutcome::Session(context) => state.completed(context),
        NostrOutcome::Identity(identity) => {
            Ok(HttpResponse::Ok().json(serde_json::json!({"identity":identity})))
        }
        NostrOutcome::Removed => Ok(HttpResponse::Ok()
            .cookie(state.cookie(state.cookie_name(true), String::new(), 0))
            .json(serde_json::json!({"removed":true}))),
    }
}

async fn nostr_identities(
    request: HttpRequest,
    application: web::Data<crate::state::ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    application.auth.context(&request, true, false).await?;
    let (passkeys, _) = application.journal.credential_counts().await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"identities": application.journal.nostr_identities().await?, "passkey_count":passkeys})))
}
async fn finish_login(
    request: HttpRequest,
    application: web::Data<crate::state::ApplicationState>,
    body: web::Json<AuthenticationFinish>,
) -> Result<HttpResponse, ApiError> {
    let state = &application.auth;
    let context = state.context(&request, false, true).await?;
    state.completed(
        state
            .manager
            .finish_login(&context, body.into_inner(), Utc::now())
            .await?,
    )
}
async fn start_enrollment(
    request: HttpRequest,
    application: web::Data<crate::state::ApplicationState>,
    body: web::Json<EnrollmentStart>,
) -> Result<HttpResponse, ApiError> {
    let state = &application.auth;
    let context = state.context(&request, false, true).await?;
    state.admit_start(&request)?;
    Ok(HttpResponse::Ok().json(
        state
            .manager
            .start_enrollment(
                &context,
                Zeroizing::new(body.into_inner().enrollment_token),
                Utc::now(),
            )
            .await?,
    ))
}
async fn finish_enrollment(
    request: HttpRequest,
    application: web::Data<crate::state::ApplicationState>,
    body: web::Json<RegistrationFinish>,
) -> Result<HttpResponse, ApiError> {
    let state = &application.auth;
    let context = state.context(&request, false, true).await?;
    state.completed(
        state
            .manager
            .finish_enrollment(&context, body.into_inner(), Utc::now())
            .await?,
    )
}
async fn session(
    request: HttpRequest,
    application: web::Data<crate::state::ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    let state = &application.auth;
    let context = state.context(&request, true, false).await?;
    Ok(HttpResponse::Ok().json(state.manager.session(&context)?))
}
async fn logout(
    request: HttpRequest,
    application: web::Data<crate::state::ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    let state = &application.auth;
    let context = state.context(&request, true, true).await?;
    state.manager.revoke(&context)?;
    Ok(HttpResponse::NoContent()
        .cookie(state.cookie(state.cookie_name(true), String::new(), 0))
        .finish())
}
async fn public_policy(
    request: HttpRequest,
    application: web::Data<crate::state::ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    let state = &application.auth;
    state.context(&request, true, false).await?;
    let limits = &state.settings.limits;
    Ok(HttpResponse::Ok().json(PublicPolicy {
        reauth: state.settings.reauth.clone(),
        pagination: limits.pagination.clone(),
        review_ttl_seconds: limits.review_ttl_seconds,
        operation_poll_seconds: limits.operation_poll_seconds,
        session_absolute_seconds: limits.session_absolute_seconds,
        session_idle_seconds: limits.session_idle_seconds,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test};
    use lightning_client::settings::Limits;
    use serde_json::{json, Value};
    use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
    use webauthn_rs::prelude::CreationChallengeResponse;

    async fn state() -> (tempfile::TempDir, crate::state::ApplicationState) {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp/opencode")
            .unwrap();
        let settings = ApiSettings {
            bind: "127.0.0.1:8080".parse().unwrap(),
            public_origin: "https://manager.example.invalid".parse().unwrap(),
            rp_id: "manager.example.invalid".into(),
            database: directory.path().join("auth.sqlite"),
            invoice_key_file: directory.path().join("unused.key"),
            allow_insecure_loopback: false,
            client_identity: Default::default(),
            reauth: ReauthPolicy::default(),
            limits: Limits::default(),
        };
        let journal = Journal::open(settings.database.clone()).await.unwrap();
        (
            directory,
            crate::state::ApplicationState::new(
                &lightning_client::settings::Settings {
                    api: settings,
                    nodes: vec![],
                },
                journal,
            )
            .await
            .unwrap(),
        )
    }

    fn browser_json<T: Serialize>(credential: T) -> Value {
        let mut value = serde_json::to_value(credential).unwrap();
        let object = value.as_object_mut().unwrap();
        if let Some(extensions) = object.remove("extensions") {
            object.insert("clientExtensionResults".into(), extensions);
        }
        value
    }

    #[actix_web::test]
    async fn client_identity_is_opt_in_single_canonical_ip_and_cached_per_request() {
        use lightning_client::settings::{ClientIdentityHeader, ClientIdentitySettings};
        let (_directory, state) = state().await;
        let peer = "192.0.2.10:1234".parse().unwrap();
        let request = test::TestRequest::get()
            .peer_addr(peer)
            .append_header(("X-Real-IP", "not an ip"))
            .append_header(("X-Real-IP", "198.51.100.1"))
            .to_http_request();
        assert_eq!(
            state.auth.identity(&request).unwrap(),
            ClientIdentity::Socket(peer.ip())
        );
        let mut settings = (*state.auth.settings).clone();
        settings.client_identity = ClientIdentitySettings {
            mode: ClientIdentityMode::TrustedSingleProxy,
            trusted_proxy_cidrs: vec![
                "192.0.2.10/32".parse().unwrap(),
                "2001:db8::10/128".parse().unwrap(),
            ],
            header: Some(ClientIdentityHeader::XRealIp),
        };
        let trusted = crate::state::ApplicationState::new(
            &lightning_client::settings::Settings {
                api: settings,
                nodes: vec![],
            },
            state.journal.clone(),
        )
        .await
        .unwrap();
        let mut mapped_settings = (*trusted.auth.settings).clone();
        mapped_settings.client_identity.trusted_proxy_cidrs =
            vec!["::ffff:192.0.2.10/128".parse().unwrap()];
        let mapped = crate::state::ApplicationState::new(
            &lightning_client::settings::Settings {
                api: mapped_settings,
                nodes: vec![],
            },
            state.journal.clone(),
        )
        .await
        .unwrap();
        let mapped_request = test::TestRequest::get()
            .peer_addr(peer)
            .insert_header(("X-Real-IP", "198.51.100.1"))
            .to_http_request();
        assert_eq!(
            mapped.auth.identity(&mapped_request).unwrap(),
            ClientIdentity::Forwarded("198.51.100.1".parse().unwrap())
        );
        // Resolution is stable even if another consumer asks for it again.
        assert_eq!(
            trusted.auth.identity(&request).unwrap(),
            ClientIdentity::Socket(peer.ip())
        );
        for (peer, value, expected) in [
            ("192.0.2.10:1234", "198.51.100.1", "198.51.100.1"),
            ("[2001:db8::10]:1234", "2001:db8::1", "2001:db8::1"),
            (
                "[::ffff:192.0.2.10]:1234",
                "::ffff:198.51.100.1",
                "198.51.100.1",
            ),
        ] {
            let request = test::TestRequest::get()
                .peer_addr(peer.parse().unwrap())
                .insert_header(("x-ReAl-Ip", value))
                .to_http_request();
            assert_eq!(
                trusted.auth.identity(&request).unwrap(),
                ClientIdentity::Forwarded(expected.parse().unwrap())
            );
        }
        let app = test::init_service(crate::app::application(trusted.clone())).await;
        let oversized = "a".repeat(MAX_IDENTITY_HEADER_BYTES + 1);
        for values in [
            vec![],
            vec!["198.51.100.1", "198.51.100.2"],
            vec!["198.51.100.1, 198.51.100.2"],
            vec!["198.51.100.1:1234"],
            vec!["[2001:db8::1]"],
            vec!["fe80::1%eth0"],
            vec!["unknown"],
            vec!["host.invalid"],
            vec![" 198.51.100.1"],
            vec!["2001:0db8::1"],
            vec![oversized.as_str()],
        ] {
            let mut request = test::TestRequest::get()
                .uri("/api/v1/auth/bootstrap")
                .peer_addr(peer)
                .insert_header((header::HOST, "manager.example.invalid"));
            for value in values {
                request = request.append_header(("X-Real-IP", value));
            }
            let response = test::call_service(&app, request.to_request()).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(response.response().cookies().next().is_none());
            let body: Value = test::read_body_json(response).await;
            assert_eq!(body["error"]["code"], "invalid_request");
        }
        let request = test::TestRequest::get()
            .peer_addr(peer)
            .insert_header((
                "X-Real-IP",
                header::HeaderValue::from_bytes(&[0xff]).unwrap(),
            ))
            .to_http_request();
        assert!(trusted.auth.identity(&request).is_err());
        let untrusted = test::TestRequest::get()
            .peer_addr("192.0.2.11:1234".parse().unwrap())
            .append_header(("X-Real-IP", "bad"))
            .append_header(("X-Real-IP", "198.51.100.1"))
            .to_http_request();
        assert_eq!(
            trusted.auth.identity(&untrusted).unwrap(),
            ClientIdentity::Socket("192.0.2.11".parse().unwrap())
        );
        let now = Utc::now();
        let first = ClientIdentity::Forwarded("198.51.100.1".parse().unwrap());
        for _ in 0..trusted.limits().login_attempts_per_minute {
            trusted.auth.manager.admit_start(first, now).unwrap();
        }
        assert!(trusted.auth.manager.admit_start(first, now).is_err());
        assert!(trusted
            .auth
            .manager
            .admit_start(
                ClientIdentity::Forwarded("198.51.100.2".parse().unwrap()),
                now
            )
            .is_ok());
    }

    #[actix_web::test]
    async fn http_bootstrap_enrollment_session_and_logout_use_real_passkey_and_safe_cookies() {
        let (_directory, state) = state().await;
        let app = test::init_service(crate::app::application(state.clone())).await;
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/api/v1/session")
                .insert_header((header::HOST, "manager.example.invalid"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/api/v1/auth/bootstrap")
                .insert_header((header::HOST, "manager.example.invalid"))
                .insert_header(("Sec-Fetch-Site", "same-origin"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let guest = response
            .response()
            .cookies()
            .find(|cookie| cookie.name() == PREAUTH_COOKIE)
            .unwrap()
            .into_owned();
        assert_eq!(guest.secure(), Some(true));
        assert_eq!(guest.http_only(), Some(true));
        assert_eq!(guest.same_site(), Some(SameSite::Strict));
        assert_eq!(guest.domain(), None);
        assert_eq!(guest.path(), Some("/"));
        let bootstrap: Value = test::read_body_json(response).await;
        let csrf = bootstrap["csrf_token"].as_str().unwrap();
        assert_eq!(bootstrap["login_available"], false);
        assert_eq!(bootstrap["enrollment_available"], false);
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/v1/auth/enrollment/start")
                .insert_header((header::HOST, "manager.example.invalid"))
                .insert_header((header::ORIGIN, "https://manager.example.invalid"))
                .insert_header(("X-CSRF-Token", csrf))
                .cookie(guest.clone())
                .set_json(json!({"enrollment_token":"NO_PUBLIC_FIRST_VISITOR_ENROLLMENT_TOKEN"}))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let token = state
            .journal
            .issue_enrollment(Utc::now(), std::time::Duration::from_secs(60), false)
            .await
            .unwrap();
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/v1/auth/enrollment/start")
                .insert_header((header::HOST, "manager.example.invalid"))
                .insert_header((header::ORIGIN, "https://manager.example.invalid"))
                .insert_header(("X-CSRF-Token", csrf))
                .cookie(guest.clone())
                .set_json(json!({"enrollment_token":token.as_str()}))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let challenge: Value = test::read_body_json(response).await;
        let options: CreationChallengeResponse =
            serde_json::from_value(challenge["options"].clone()).unwrap();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let credential = authenticator
            .do_registration(state.auth.settings.public_origin.clone(), options)
            .unwrap();
        let source = ClientIdentity::Socket(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        for _ in 0..state.limits().login_attempts_per_minute {
            let _ = state.auth.manager.admit_start(source, Utc::now());
        }
        assert!(state.auth.manager.admit_start(source, Utc::now()).is_err());
        let response=test::call_service(&app,test::TestRequest::post().uri("/api/v1/auth/enrollment/finish").insert_header((header::HOST,"manager.example.invalid")).insert_header((header::ORIGIN,"https://manager.example.invalid")).insert_header(("X-CSRF-Token",csrf)).cookie(guest).set_json(json!({"challenge_id":challenge["challenge_id"],"credential":browser_json(credential)})).to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let session_cookie = response
            .response()
            .cookies()
            .find(|cookie| cookie.name() == SESSION_COOKIE)
            .unwrap()
            .into_owned();
        assert_eq!(session_cookie.secure(), Some(true));
        assert_eq!(session_cookie.http_only(), Some(true));
        let session: Value = test::read_body_json(response).await;
        assert_eq!(session["authenticated"], true);
        assert_eq!(session["reauth"]["mode"], "every_operation");
        assert!(session.get("password").is_none());
        assert!(session.get("credential").is_none());
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/api/v1/config")
                .insert_header((header::HOST, "manager.example.invalid"))
                .cookie(session_cookie.clone())
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let policy: Value = test::read_body_json(response).await;
        assert_eq!(policy["pagination"]["max_limit"], 200);
        assert!(policy.get("invoice_key_file").is_none());
        let response = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri("/api/v1/session")
                .insert_header((header::HOST, "manager.example.invalid"))
                .insert_header((header::ORIGIN, "https://manager.example.invalid"))
                .cookie(session_cookie.clone())
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let error: Value = test::read_body_json(response).await;
        assert_eq!(error["error"]["code"], "csrf");
        let response = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri("/api/v1/session")
                .insert_header((header::HOST, "manager.example.invalid"))
                .insert_header((header::ORIGIN, "https://manager.example.invalid"))
                .insert_header(("X-CSRF-Token", session["csrf_token"].as_str().unwrap()))
                .cookie(session_cookie.clone())
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(test::read_body(response).await.is_empty());
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/api/v1/session")
                .insert_header((header::HOST, "manager.example.invalid"))
                .cookie(session_cookie)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn allocation_limit_uses_existing_error_shape_and_eviction_horizon() {
        use actix_web::ResponseError;
        let response =
            ApiError::from(crate::auth::AuthError::AllocationLimited(58)).error_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "58");
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "rate_limited");
        assert_eq!(
            body["error"]["message"],
            "Too many requests. Wait before starting again."
        );
        assert!(body["error"].get("retry_after").is_none());
    }

    #[actix_web::test]
    async fn request_boundaries_reject_spoofed_origin_host_cross_site_and_media_type() {
        let (_directory, state) = state().await;
        let app = test::init_service(crate::app::application(state.clone())).await;
        for (host, origin, site) in [
            ("evil.example.invalid", None, None),
            (
                "manager.example.invalid",
                Some("https://evil.example.invalid"),
                None,
            ),
            ("manager.example.invalid", None, Some("cross-site")),
        ] {
            let mut request = test::TestRequest::get()
                .uri("/api/v1/auth/bootstrap")
                .insert_header((header::HOST, host));
            if let Some(origin) = origin {
                request = request.insert_header((header::ORIGIN, origin));
            }
            if let Some(site) = site {
                request = request.insert_header(("Sec-Fetch-Site", site));
            }
            let response = test::call_service(&app, request.to_request()).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/v1/auth/passkey/start")
                .insert_header((header::HOST, "manager.example.invalid"))
                .insert_header((header::ORIGIN, "https://manager.example.invalid"))
                .set_payload("{}")
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/v1/auth/passkey/start")
                .insert_header((header::HOST, "manager.example.invalid"))
                .set_json(json!({}))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/v1/auth/passkey/start")
                .insert_header((header::HOST, "manager.example.invalid"))
                .insert_header((header::ORIGIN, "https://manager.example.invalid"))
                .set_json(json!({"password":"DO_NOT_ECHO_THIS_VALUE"}))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error = test::read_body(response).await;
        assert!(!std::str::from_utf8(&error)
            .unwrap()
            .contains("DO_NOT_ECHO_THIS_VALUE"));
    }

    #[actix_web::test]
    async fn development_cookie_exception_is_explicit_and_loopback_only() {
        let (_directory, state) = state().await;
        let mut settings = (*state.auth.settings).clone();
        settings.public_origin = "http://localhost:5173".parse().unwrap();
        settings.rp_id = "localhost".into();
        assert!(AuthHttp::new(settings.clone(), state.journal.clone()).is_err());
        settings.allow_insecure_loopback = true;
        let dev = AuthHttp::new(settings.clone(), state.journal.clone()).unwrap();
        let cookie = dev.cookie(dev.cookie_name(true), "SYNTHETIC_ONLY".into(), 60);
        assert_eq!(cookie.name(), DEV_SESSION_COOKIE);
        assert_eq!(cookie.secure(), Some(false));
        assert_eq!(cookie.http_only(), Some(true));
        settings.public_origin = "http://manager.example.invalid".parse().unwrap();
        settings.rp_id = "manager.example.invalid".into();
        assert!(AuthHttp::new(settings, state.journal.clone()).is_err());
    }
}
