use super::*;
use crate::{
    error::ApiError,
    reads::{no_query, node_id},
    state::ApplicationState,
};
use actix_web::{web, HttpRequest, HttpResponse};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewDigest {
    review_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationFinish {
    review_digest: String,
    challenge_id: Uuid,
    credential: webauthn_rs::prelude::PublicKeyCredential,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NostrAuthorizationFinish {
    review_digest: String,
    challenge_id: Uuid,
    event: crate::nostr::Event,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirm {
    review_digest: String,
    #[serde(deserialize_with = "required_authorization")]
    authorization_id: Option<Uuid>,
}
fn required_authorization<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Uuid>, D::Error> {
    Option::<Uuid>::deserialize(d)
}

pub(crate) fn configure(config: &mut web::ServiceConfig) {
    config
        .route(
            "/nodes/{node_id}/operations/{operation_id}/authorize/nostr",
            web::post().to(authorize_nostr),
        )
        .route(
            "/nodes/{node_id}/operations/{operation_id}/authorize/nostr/finish",
            web::post().to(finish_nostr),
        )
        .route(
            "/nodes/{node_id}/operations/{operation_id}/authorize",
            web::post().to(authorize),
        )
        .route(
            "/nodes/{node_id}/operations/{operation_id}/authorize/finish",
            web::post().to(finish),
        )
        .route(
            "/nodes/{node_id}/operations/{operation_id}/confirm",
            web::post().to(confirm),
        );
}

fn invalid() -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest)
}
fn uuid(text: &str) -> std::result::Result<Uuid, ApiError> {
    let id = Uuid::parse_str(text).map_err(|_| invalid())?;
    if id.is_nil() || id.to_string() != text {
        return Err(invalid());
    }
    Ok(id)
}
fn target(request: &HttpRequest, digest: &str) -> std::result::Result<(String, Uuid), ApiError> {
    no_query(request)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok((
        node_id(request)?,
        uuid(
            request
                .match_info()
                .get("operation_id")
                .ok_or_else(invalid)?,
        )?,
    ))
}

pub(crate) async fn create(
    request: HttpRequest,
    state: web::Data<ApplicationState>,
    body: web::Json<OperationRequest>,
) -> std::result::Result<HttpResponse, ApiError> {
    let context = state.auth.context(&request, true, true).await?;
    no_query(&request)?;
    let node = node_id(&request)?;
    let mut keys = request.headers().get_all("Idempotency-Key");
    let key = uuid(
        keys.next()
            .ok_or_else(invalid)?
            .to_str()
            .map_err(|_| invalid())?,
    )?;
    if keys.next().is_some() {
        return Err(invalid());
    }
    let (operation, created) = state
        .engine
        .create_review_outcome(&context, &node, key, body.into_inner())
        .await?;
    Ok(if created {
        HttpResponse::Created()
    } else {
        HttpResponse::Ok()
    }
    .json(operation))
}

async fn authorize(
    request: HttpRequest,
    state: web::Data<ApplicationState>,
    body: web::Json<ReviewDigest>,
) -> std::result::Result<HttpResponse, ApiError> {
    let context = state.auth.context(&request, true, true).await?;
    let (node, id) = target(&request, &body.review_digest)?;
    Ok(HttpResponse::Ok().json(
        state
            .engine
            .start_authorization(&context, &node, id, &body.review_digest)
            .await?,
    ))
}

async fn authorize_nostr(
    request: HttpRequest,
    state: web::Data<ApplicationState>,
    body: web::Json<ReviewDigest>,
) -> std::result::Result<HttpResponse, ApiError> {
    let context = state.auth.context(&request, true, true).await?;
    state.auth.admit_start(&request)?;
    let (node, id) = target(&request, &body.review_digest)?;
    let operation = state
        .engine
        .reviewable(&context, &node, id, &body.review_digest)
        .await?;
    let response = state
        .auth
        .manager
        .start_nostr_authorization(&context, &operation, state.engine.clock.now())
        .await?;
    state
        .engine
        .reviewable(&context, &node, id, &body.review_digest)
        .await?;
    Ok(HttpResponse::Ok().json(response))
}

async fn finish_nostr(
    request: HttpRequest,
    state: web::Data<ApplicationState>,
    body: web::Json<NostrAuthorizationFinish>,
) -> std::result::Result<HttpResponse, ApiError> {
    let context = state.auth.context(&request, true, true).await?;
    let (node, id) = target(&request, &body.review_digest)?;
    let operation = state
        .engine
        .reviewable(&context, &node, id, &body.review_digest)
        .await?;
    let body = body.into_inner();
    let response = state
        .auth
        .manager
        .finish_nostr_authorization(
            &context,
            &operation,
            crate::auth::NostrFinish {
                challenge_id: body.challenge_id,
                event: body.event,
            },
            state.engine.clock.now(),
        )
        .await?;
    state
        .engine
        .reviewable(&context, &node, id, &body.review_digest)
        .await?;
    Ok(HttpResponse::Ok().json(response))
}

async fn finish(
    request: HttpRequest,
    state: web::Data<ApplicationState>,
    body: web::Json<AuthorizationFinish>,
) -> std::result::Result<HttpResponse, ApiError> {
    let context = state.auth.context(&request, true, true).await?;
    let (node, id) = target(&request, &body.review_digest)?;
    let body = body.into_inner();
    Ok(HttpResponse::Ok().json(
        state
            .engine
            .finish_authorization(
                &context,
                &node,
                id,
                &body.review_digest,
                crate::auth::AuthenticationFinish {
                    challenge_id: body.challenge_id,
                    credential: body.credential,
                },
            )
            .await?,
    ))
}

async fn confirm(
    request: HttpRequest,
    state: web::Data<ApplicationState>,
    body: web::Json<Confirm>,
) -> std::result::Result<HttpResponse, ApiError> {
    let context = state.auth.context(&request, true, true).await?;
    let (node, id) = target(&request, &body.review_digest)?;
    let (operation, claimed) = state
        .engine
        .confirm_once_outcome(
            &context,
            &node,
            id,
            &body.review_digest,
            body.authorization_id,
        )
        .await?;
    let nonterminal = matches!(
        operation.state,
        OperationState::Dispatching | OperationState::Pending | OperationState::Unknown
    );
    Ok(if claimed && nonterminal {
        HttpResponse::Accepted()
    } else {
        HttpResponse::Ok()
    }
    .json(operation))
}
