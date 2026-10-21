use crate::{
    auth_http::AuthHttp,
    error::ApiError,
    pagination::{Paged, Query, Rows, Selector},
};
use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use lightning_client::{
    model::{ErrorCode, Network, OperationKind, OperationState},
    money::Decimal,
    settings::{MAX_BOLT11_BYTES, MAX_INVOICE_DESCRIPTION_CHARS},
    validation,
};
use serde::Deserialize;
use uuid::Uuid;

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .route("/nodes", web::get().to(nodes))
        .route("/nodes/{node_id}", web::get().to(node))
        .route("/nodes/{node_id}/status", web::get().to(status))
        .route("/nodes/{node_id}/policy", web::get().to(policy))
        .route("/nodes/{node_id}/decode", web::post().to(decode))
        .route("/nodes/{node_id}/operations", web::get().to(operations))
        .route(
            "/nodes/{node_id}/operations/{operation_id}",
            web::get().to(operation),
        );
}

fn node_id(request: &HttpRequest) -> Result<String, ApiError> {
    let id = request.match_info().get("node_id").ok_or_else(invalid)?;
    if id.is_empty()
        || id.len() > 64
        || !id.as_bytes()[0].is_ascii_alphanumeric()
        || !id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(invalid());
    }
    Ok(id.to_string())
}
fn invalid() -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest)
}
fn no_query(request: &HttpRequest) -> Result<(), ApiError> {
    if request.query_string().is_empty() {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn enum_value<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ApiError> {
    serde_json::from_value(serde_json::Value::String(text.into())).map_err(|_| invalid())
}
fn response(page: Paged) -> HttpResponse {
    match page {
        Paged::Nodes(page) => HttpResponse::Ok().json(page),
        Paged::Operations(page) => HttpResponse::Ok().json(page),
    }
}

async fn nodes(request: HttpRequest, auth: web::Data<AuthHttp>) -> Result<HttpResponse, ApiError> {
    let context = auth.context(&request, true, false).await?;
    let query = Query::parse(
        request.query_string(),
        &["limit", "cursor", "network"],
        auth.limits(),
    )?;
    let network = query
        .filters
        .iter()
        .find(|(key, _)| key == "network")
        .map(|(_, value)| enum_value::<Network>(value))
        .transpose()?;
    let selector = Selector {
        resource: "nodes",
        node: None,
        scope: auth.registry.scope(),
        filters: query.filters,
        limit: query.limit,
    };
    let now = Utc::now();
    if let Some(cursor) = query.cursor {
        return Ok(response(
            auth.snapshots.next(&context, &selector, &cursor, now)?,
        ));
    }
    let counts = auth.journal.unresolved_counts().await?;
    let mut rows: Vec<_> = auth
        .registry
        .entries()
        .map(|(id, entry)| entry.summary(now, counts.get(id).copied().unwrap_or(Decimal::ZERO)))
        .filter(|node| network.is_none_or(|network| node.network == network))
        .take(auth.limits().pagination.snapshot_max_items + 1)
        .collect();
    let truncated = rows.len() > auth.limits().pagination.snapshot_max_items;
    rows.truncate(auth.limits().pagination.snapshot_max_items);
    Ok(response(auth.snapshots.begin(
        &context,
        selector,
        Rows::Nodes(rows),
        None,
        truncated,
        now,
    )?))
}
async fn summary(
    request: &HttpRequest,
    auth: &AuthHttp,
) -> Result<lightning_client::model::NodeSummary, ApiError> {
    no_query(request)?;
    let id = node_id(request)?;
    let entry = auth
        .registry
        .get(&id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    let counts = auth.journal.unresolved_counts().await?;
    Ok(entry.summary(
        Utc::now(),
        counts.get(&id).copied().unwrap_or(Decimal::ZERO),
    ))
}
async fn node(request: HttpRequest, auth: web::Data<AuthHttp>) -> Result<HttpResponse, ApiError> {
    auth.context(&request, true, false).await?;
    Ok(HttpResponse::Ok().json(summary(&request, &auth).await?))
}
async fn status(request: HttpRequest, auth: web::Data<AuthHttp>) -> Result<HttpResponse, ApiError> {
    auth.context(&request, true, false).await?;
    Ok(HttpResponse::Ok().json(summary(&request, &auth).await?.status))
}
async fn policy(request: HttpRequest, auth: web::Data<AuthHttp>) -> Result<HttpResponse, ApiError> {
    auth.context(&request, true, false).await?;
    no_query(&request)?;
    let id = node_id(&request)?;
    let entry = auth
        .registry
        .get(&id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    Ok(HttpResponse::Ok().json(&entry.policy))
}
async fn operations(
    request: HttpRequest,
    auth: web::Data<AuthHttp>,
) -> Result<HttpResponse, ApiError> {
    let context = auth.context(&request, true, false).await?;
    let id = node_id(&request)?;
    let query = Query::parse(
        request.query_string(),
        &["limit", "cursor", "state", "kind"],
        auth.limits(),
    )?;
    let filter = |name: &str| {
        query
            .filters
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let state = filter("state");
    let kind = filter("kind");
    if let Some(state) = &state {
        if state != "nonterminal" {
            enum_value::<OperationState>(state)?;
        }
    }
    if let Some(kind) = &kind {
        enum_value::<OperationKind>(kind)?;
    }
    let (scope, rows, truncated) = if query.cursor.is_some() {
        (auth.journal.history_scope(id.clone()).await?, None, false)
    } else {
        let observation = auth
            .journal
            .history_observation(
                id.clone(),
                state,
                kind,
                auth.limits().pagination.snapshot_max_items,
            )
            .await?;
        (
            observation.scope,
            Some(observation.operations),
            observation.truncated,
        )
    };
    let configured = auth.registry.get(&id);
    if configured.is_none() && !scope.exists {
        return Err(ApiError::new(ErrorCode::NotFound));
    }
    let revision = format!(
        "{}:{}",
        configured
            .map(|entry| entry.binding_revision.as_str())
            .unwrap_or("removed"),
        scope.revision
    );
    let selector = Selector {
        resource: "operations",
        node: Some(id.clone()),
        scope: revision,
        filters: query.filters,
        limit: query.limit,
    };
    let now = Utc::now();
    if let Some(cursor) = query.cursor {
        return Ok(response(
            auth.snapshots.next(&context, &selector, &cursor, now)?,
        ));
    }
    let rows = rows.ok_or_else(|| ApiError::new(ErrorCode::InternalError))?;
    Ok(response(auth.snapshots.begin(
        &context,
        selector,
        Rows::Operations(rows),
        Some(scope.network),
        truncated,
        now,
    )?))
}
async fn operation(
    request: HttpRequest,
    auth: web::Data<AuthHttp>,
) -> Result<HttpResponse, ApiError> {
    auth.context(&request, true, false).await?;
    no_query(&request)?;
    let node = node_id(&request)?;
    let text = request
        .match_info()
        .get("operation_id")
        .ok_or_else(invalid)?;
    let id = Uuid::parse_str(text).map_err(|_| invalid())?;
    if id.to_string() != text {
        return Err(invalid());
    }
    let operation = auth.journal.get(id).await?;
    if operation.node_id != node {
        return Err(ApiError::new(ErrorCode::NotFound));
    }
    Ok(HttpResponse::Ok().json(operation))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decode {
    bolt11: String,
}
async fn decode(
    request: HttpRequest,
    auth: web::Data<AuthHttp>,
    body: web::Json<Decode>,
) -> Result<HttpResponse, ApiError> {
    auth.context(&request, true, true).await?;
    no_query(&request)?;
    let id = node_id(&request)?;
    let entry = auth
        .registry
        .get(&id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    if body.bolt11.is_empty() || body.bolt11.len() > MAX_BOLT11_BYTES {
        return Err(invalid());
    }
    let decoded = validation::decode(&body.bolt11, entry.observed_network(), Utc::now())
        .map_err(|_| ApiError::new(ErrorCode::InvalidInvoice))?;
    if decoded
        .description
        .as_ref()
        .is_some_and(|description| description.chars().count() > MAX_INVOICE_DESCRIPTION_CHARS)
    {
        return Err(ApiError::new(ErrorCode::InvalidInvoice));
    }
    Ok(HttpResponse::Ok().json(decoded))
}
