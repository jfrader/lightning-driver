// api-server/src/main.rs
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{
    delete, get,
    middleware::Logger,
    post,
    web::{self, Data, Json},
    App, HttpResponse, HttpServer, Responder,
};
use anyhow::Result;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use lightning_client::{connect_from_config, LightningClientDyn};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

// ---------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------
#[derive(Deserialize)]
struct LoginReq {
    password: String,
}

#[derive(Deserialize)]
struct InvoiceReq {
    msat: u64,
    #[serde(default)]
    desc: Option<String>,
}

#[derive(Serialize)]
struct InvoiceResp {
    bolt11: String,
}

// ---------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------
#[derive(Deserialize, Clone)]
struct ApiConfig {
    password_hash: String,
    #[serde(default = "default_host")]
    host: String,
    #[serde(default = "default_port")]
    port: u16,
}

fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    8080
}

// ---------------------------------------------------------------------
// Session key: load from file or generate once
// ---------------------------------------------------------------------
fn load_or_create_session_key() -> Result<actix_web::cookie::Key> {
    let path = Path::new("session_key.bin");
    if path.exists() {
        let data = fs::read(path)?;
        if data.len() != 32 {
            anyhow::bail!("session_key.bin must be 32 bytes");
        }
        Ok(actix_web::cookie::Key::from(&data))
    } else {
        let key = actix_web::cookie::Key::generate();
        fs::write(path, key.master())?;
        eprintln!("Generated new session key -> session_key.bin");
        Ok(key)
    }
}

// ---------------------------------------------------------------------
// Login / Logout
// ---------------------------------------------------------------------
#[post("/login")]
async fn login(payload: Json<LoginReq>, session: Session, cfg: Data<ApiConfig>) -> impl Responder {
    let parsed = match PasswordHash::new(&cfg.password_hash) {
        Ok(p) => p,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let ok = Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed)
        .is_ok();

    if ok {
        let _ = session.insert("logged_in", true);
        HttpResponse::Ok().json(json!({ "status": "success" }))
    } else {
        HttpResponse::Unauthorized().json(json!({ "error": "invalid password" }))
    }
}

#[delete("/logout")]
async fn logout(session: Session) -> impl Responder {
    session.purge(); // <-- Fixed: was `spy()`
    HttpResponse::Ok().json(json!({ "status": "logged out" }))
}

// ---------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------
async fn require_auth(session: &mut Session) -> Result<(), HttpResponse> {
    session.renew();
    match session.get::<bool>("logged_in") {
        Ok(Some(true)) => Ok(()),
        _ => Err(HttpResponse::Unauthorized().json(json!({ "error": "login required" }))),
    }
}

// ---------------------------------------------------------------------
// Protected routes
// ---------------------------------------------------------------------
#[get("/info")]
async fn get_info(driver: Data<LightningClientDyn>, mut session: Session) -> impl Responder {
    if require_auth(&mut session).await.is_err() {
        return HttpResponse::Unauthorized().json(json!({ "error": "login required" }));
    }

    let mut guard = driver.lock().unwrap();
    match guard.get_info().await {
        Ok(info) => HttpResponse::Ok().json(info),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/invoice")]
async fn create_invoice(
    driver: Data<LightningClientDyn>,
    payload: Json<InvoiceReq>,
    mut session: Session,
) -> impl Responder {
    if require_auth(&mut session).await.is_err() {
        return HttpResponse::Unauthorized().json(json!({ "error": "login required" }));
    }

    let mut guard = driver.lock().unwrap();
    let desc = payload.desc.as_deref();
    match guard.create_invoice(payload.msat, None, desc).await {
        Ok(bolt11) => HttpResponse::Ok().json(InvoiceResp { bolt11 }),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// ---------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------
#[actix_web::main]
async fn main() -> Result<()> {
    let settings = config::Config::builder()
        .add_source(config::File::with_name("config.toml"))
        .build()?
        .try_deserialize::<serde_json::Value>()?;

    let api_cfg = settings
        .get("api")
        .and_then(|v| serde_json::from_value::<ApiConfig>(v.clone()).ok())
        .unwrap_or(ApiConfig {
            password_hash: "".into(),
            host: default_host(),
            port: default_port(),
        });

    if api_cfg.password_hash.is_empty() {
        eprintln!("WARNING: No password_hash → API is open!");
    }

    let driver = connect_from_config().await?;

    let port = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(api_cfg.port);
    let addr: SocketAddr = (api_cfg.host.parse::<std::net::IpAddr>()?, port).into();

    let session_key = load_or_create_session_key()?;
    let is_local = api_cfg.host == "127.0.0.1" || api_cfg.host == "localhost";
    let cookie_secure = !is_local;

    println!("API → http://{}", addr);
    println!("Login: POST /login {{ \"password\": \"...\" }}");

    HttpServer::new(move || {
        let session_mw =
            SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                .cookie_name("session".to_string())
                .cookie_secure(cookie_secure)
                .cookie_http_only(true)
                .cookie_same_site(actix_web::cookie::SameSite::Lax)
                .build();

        App::new()
            .app_data(Data::new(driver.clone()))
            .app_data(Data::new(api_cfg.clone()))
            .wrap(Logger::default())
            .wrap(session_mw)
            .service(login)
            .service(logout)
            .service(web::scope("/api").service(get_info).service(create_invoice))
    })
    .bind(addr)?
    .run()
    .await
    .map_err(|e| anyhow::anyhow!("server error: {}", e))
}
