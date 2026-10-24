use crate::{
    error::ApiError,
    pagination::{Paged, Query, Rows, Selector},
    state::ApplicationState,
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
        .route("/nodes/{node_id}/info", web::get().to(info))
        .route("/nodes/{node_id}/bitcoin", web::get().to(bitcoin))
        .route("/nodes/{node_id}/bitcoin/peers", web::get().to(collection))
        .route("/nodes/{node_id}/watchtower/server", web::get().to(watchtower))
        .route("/nodes/{node_id}/watchtower/client", web::get().to(watchtower))
        .route("/nodes/{node_id}/watchtower/client/towers", web::get().to(collection))
        .route("/nodes/{node_id}/watchtower/client/towers/{pubkey}", web::get().to(watchtower))
        .route("/nodes/{node_id}/{collection:balances|invoices|payments|peers|channels|transactions|fee-estimates}", web::get().to(collection))
        .route("/nodes/{node_id}/policy", web::get().to(policy))
        .route("/nodes/{node_id}/decode", web::post().to(decode))
        .service(
            web::resource("/nodes/{node_id}/operations")
                .route(web::get().to(operations))
                .route(web::post().to(crate::operations::http::create))
                .default_service(web::to(crate::app::not_found)),
        )
        .route(
            "/nodes/{node_id}/operations/{operation_id}",
            web::get().to(operation),
        );
}

pub(crate) fn node_id(request: &HttpRequest) -> Result<String, ApiError> {
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
pub(crate) fn no_query(request: &HttpRequest) -> Result<(), ApiError> {
    if request.query_string().is_empty() {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn enum_value<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ApiError> {
    serde_json::from_value(serde_json::Value::String(text.into())).map_err(|_| invalid())
}
fn response(page: Paged, max_bytes: usize) -> Result<HttpResponse, ApiError> {
    let bytes = match page {
        Paged::Nodes(page) => crate::pagination::bounded_json(&page, max_bytes)?,
        Paged::Operations(page) => crate::pagination::bounded_json(&page, max_bytes)?,
        Paged::Collection(page) => crate::pagination::bounded_json(&page, max_bytes)?,
    };
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(bytes))
}

async fn nodes(
    request: HttpRequest,
    auth: web::Data<ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    let context = auth.auth.context(&request, true, false).await?;
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
    if let Some(cursor) = query.cursor {
        return response(
            auth.snapshots
                .next(&context, &selector, &cursor, Utc::now())?,
            auth.limits().max_response_bytes,
        );
    }
    // One failed observation is recorded on that node and shown as its status; it must not fail the
    // whole fleet page, and a rate-limited refresh is retried on the next request.
    for (id, _) in auth.registry.entries() {
        let _ = auth.refresh_node(id).await;
    }
    let now = Utc::now();
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
    response(
        auth.snapshots
            .begin(&context, selector, Rows::Nodes(rows), None, truncated, now)?,
        auth.limits().max_response_bytes,
    )
}
async fn summary(
    request: &HttpRequest,
    auth: &ApplicationState,
) -> Result<lightning_client::model::NodeSummary, ApiError> {
    no_query(request)?;
    let id = node_id(request)?;
    let entry = auth
        .registry
        .get(&id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    auth.refresh_node(&id).await?;
    let counts = auth.journal.unresolved_counts().await?;
    Ok(entry.summary(
        Utc::now(),
        counts.get(&id).copied().unwrap_or(Decimal::ZERO),
    ))
}
async fn node(
    request: HttpRequest,
    auth: web::Data<ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    auth.auth.context(&request, true, false).await?;
    Ok(HttpResponse::Ok().json(summary(&request, &auth).await?))
}
async fn status(
    request: HttpRequest,
    auth: web::Data<ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    auth.auth.context(&request, true, false).await?;
    Ok(HttpResponse::Ok().json(summary(&request, &auth).await?.status))
}
async fn policy(
    request: HttpRequest,
    auth: web::Data<ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    auth.auth.context(&request, true, false).await?;
    no_query(&request)?;
    let id = node_id(&request)?;
    let entry = auth
        .registry
        .get(&id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    let policy = entry
        .policy
        .as_ref()
        .ok_or_else(|| ApiError::new(ErrorCode::Unsupported))?;
    Ok(HttpResponse::Ok().json(policy))
}

async fn info(
    request: HttpRequest,
    auth: web::Data<ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    auth.auth.context(&request, true, false).await?;
    let node = summary(&request, &auth).await?;
    let entry = auth
        .registry
        .get(&node.id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    let observation = entry
        .observation
        .lock()
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    let (info, _) = observation
        .as_ref()
        .ok_or_else(|| ApiError::new(ErrorCode::NodeOffline))?;
    let value = lightning_client::model::NodeInfo {
        observed_at: info
            .status
            .observed_at
            .ok_or_else(|| ApiError::new(ErrorCode::InternalError))?,
        stale: node.status.stale,
        node,
        alias: info.alias.clone(),
        version: info.version.clone(),
    };
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(crate::pagination::bounded_json(
            &value,
            auth.limits().max_response_bytes,
        )?))
}

async fn collection(
    request: HttpRequest,
    auth: web::Data<ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    use crate::operations::ReadQuery;
    use lightning_client::model::{ChannelState, InvoiceState, PaymentState};
    let context = auth.auth.context(&request, true, false).await?;
    let id = node_id(&request)?;
    let entry = auth
        .registry
        .get(&id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    let (resource, read, filter) = match request.match_info().get("collection") {
        None if request.path().ends_with("/bitcoin/peers") => {
            ("bitcoin-peers", ReadQuery::BitcoinPeers, None)
        }
        None if request.path().ends_with("/watchtower/client/towers") => {
            ("watchtower-towers", ReadQuery::WatchtowerTowers, None)
        }
        Some("balances") => ("balances", ReadQuery::Balances, None),
        Some("fee-estimates") => ("fee-estimates", ReadQuery::Fees, None),
        Some("invoices") => ("invoices", ReadQuery::Invoices, Some("status")),
        Some("payments") => ("payments", ReadQuery::Payments, Some("status")),
        Some("peers") => ("peers", ReadQuery::Peers, None),
        Some("channels") => ("channels", ReadQuery::Channels, Some("state")),
        Some("transactions") => ("transactions", ReadQuery::Transactions, None),
        _ => return Err(ApiError::new(ErrorCode::NotFound)),
    };
    if resource == "bitcoin-peers" {
        require_surface(&entry.read_availability.bitcoin_peers)?;
    }
    if resource == "watchtower-towers" {
        require_surface(&entry.read_availability.watchtower_client)?;
    }
    if matches!(resource, "balances" | "fee-estimates") {
        no_query(&request)?;
        let observed = auth.observed(&id, resource, read).await?;
        let mut value = observed.value;
        value["stale"] = observed.stale.into();
        return Ok(HttpResponse::Ok().content_type("application/json").body(
            crate::pagination::bounded_json(&value, auth.limits().max_response_bytes)?,
        ));
    }
    let allowed = if let Some(filter) = filter {
        vec!["limit", "cursor", filter]
    } else {
        vec!["limit", "cursor"]
    };
    let query = Query::parse(request.query_string(), &allowed, auth.limits())?;
    let state = query.filters.first().map(|(_, value)| value.clone());
    if let Some(value) = &state {
        match resource {
            "invoices" => {
                enum_value::<InvoiceState>(value)?;
            }
            "payments" => {
                enum_value::<PaymentState>(value)?;
            }
            "channels" => {
                enum_value::<ChannelState>(value)?;
            }
            _ => return Err(invalid()),
        }
    }
    let selector = Selector {
        resource,
        node: Some(id.clone()),
        scope: entry.binding_revision.clone(),
        filters: query.filters,
        limit: query.limit,
    };
    if let Some(cursor) = query.cursor {
        return response(
            auth.snapshots
                .next(&context, &selector, &cursor, Utc::now())?,
            auth.limits().max_response_bytes,
        );
    }
    let observed = auth.observed(&id, resource, read).await.map_err(|error| {
        if resource == "watchtower-towers" {
            watchtower_error(error)
        } else {
            error
        }
    })?;
    let mut rows = observed
        .value
        .as_array()
        .ok_or_else(|| ApiError::new(ErrorCode::InternalError))?
        .clone();
    if let Some(state) = state {
        rows.retain(|row| row["state"].as_str() == Some(&state));
    }
    let truncated = observed.truncated || rows.len() > auth.limits().pagination.snapshot_max_items;
    rows.truncate(auth.limits().pagination.snapshot_max_items);
    response(
        auth.snapshots.begin_observed(
            &context,
            selector,
            Rows::Collection(rows),
            crate::pagination::Observation {
                network: Some(entry.observed_network()),
                at: observed.at,
                stale: observed.stale,
                truncated,
            },
            Utc::now(),
        )?,
        auth.limits().max_response_bytes,
    )
}
fn require_surface(capability: &lightning_client::model::Capability) -> Result<(), ApiError> {
    if capability.enabled {
        Ok(())
    } else {
        Err(ApiError::unsupported(capability.reason))
    }
}
async fn watchtower(
    request: HttpRequest,
    auth: web::Data<ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    use crate::operations::ReadQuery;
    auth.auth.context(&request, true, false).await?;
    no_query(&request)?;
    let id = node_id(&request)?;
    let entry = auth
        .registry
        .get(&id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    let (resource, query, surface) = if let Some(key) = request.match_info().get("pubkey") {
        let pubkey = key
            .parse::<bitcoin::secp256k1::PublicKey>()
            .map_err(|_| invalid())?;
        if pubkey.to_string() != key {
            return Err(invalid());
        }
        (
            "watchtower-tower",
            ReadQuery::WatchtowerTower(pubkey.serialize()),
            &entry.read_availability.watchtower_client,
        )
    } else if request.path().ends_with("/server") {
        (
            "watchtower-server",
            ReadQuery::WatchtowerServer,
            &entry.read_availability.watchtower_server,
        )
    } else {
        (
            "watchtower-client",
            ReadQuery::WatchtowerClient,
            &entry.read_availability.watchtower_client,
        )
    };
    require_surface(surface)?;
    let observed = auth
        .observed(&id, resource, query)
        .await
        .map_err(watchtower_error)?;
    let mut value = observed.value;
    // The frozen tower detail has no freshness fields.
    if !matches!(query, ReadQuery::WatchtowerTower(_)) {
        value["stale"] = observed.stale.into();
    }
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(crate::pagination::bounded_json(
            &value,
            auth.limits().max_response_bytes,
        )?))
}
fn watchtower_error(error: ApiError) -> ApiError {
    use lightning_client::model::CapabilityReason;
    let reason = match error.code {
        ErrorCode::NodeAuthError => CapabilityReason::PermissionDenied,
        ErrorCode::NotConfigured => CapabilityReason::NotConfigured,
        ErrorCode::Unsupported => CapabilityReason::Unsupported,
        _ => return error,
    };
    ApiError::unsupported(Some(reason))
}
async fn bitcoin(
    request: HttpRequest,
    auth: web::Data<ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    auth.auth.context(&request, true, false).await?;
    no_query(&request)?;
    let id = node_id(&request)?;
    let entry = auth
        .registry
        .get(&id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    require_surface(&entry.read_availability.bitcoin)?;
    let observed = auth
        .observed(&id, "bitcoin", crate::operations::ReadQuery::Bitcoin)
        .await?;
    let mut value = observed.value;
    value["stale"] = observed.stale.into();
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(crate::pagination::bounded_json(
            &value,
            auth.limits().max_response_bytes,
        )?))
}
async fn operations(
    request: HttpRequest,
    auth: web::Data<ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    let context = auth.auth.context(&request, true, false).await?;
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
        auth.engine.observe_list(&context, &id).await?;
        let observation = auth
            .journal
            .history_observation_bounded(
                id.clone(),
                state,
                kind,
                auth.limits().pagination.snapshot_max_items,
                auth.limits().max_response_bytes,
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
        return response(
            auth.snapshots.next(&context, &selector, &cursor, now)?,
            auth.limits().max_response_bytes,
        );
    }
    let rows = rows.ok_or_else(|| ApiError::new(ErrorCode::InternalError))?;
    response(
        auth.snapshots.begin(
            &context,
            selector,
            Rows::Operations(rows),
            Some(scope.network),
            truncated,
            now,
        )?,
        auth.limits().max_response_bytes,
    )
}
async fn operation(
    request: HttpRequest,
    auth: web::Data<ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    let context = auth.auth.context(&request, true, false).await?;
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
    let operation = auth.engine.observe(&context, &node, id).await?;
    Ok(HttpResponse::Ok().json(operation))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decode {
    bolt11: String,
}
async fn decode(
    request: HttpRequest,
    auth: web::Data<ApplicationState>,
    body: web::Json<Decode>,
) -> Result<HttpResponse, ApiError> {
    auth.auth.context(&request, true, true).await?;
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
