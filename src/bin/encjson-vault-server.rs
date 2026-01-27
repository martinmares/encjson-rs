use std::net::SocketAddr;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, QueryBuilder};
use tracing::{error, info};

#[derive(Clone)]
struct AppState {
    db: PgPool,
    auth_required: bool,
    jwt_issuer: Option<String>,
    jwt_audience: Option<String>,
    jwks: std::collections::HashMap<String, DecodingKey>,
}

#[derive(Deserialize)]
struct KeyQuery {
    tenant: Option<String>,
    status: Option<String>,
    q: Option<String>,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
struct KeyRow {
    public_hex: String,
    tenant: String,
    status: String,
    note: Option<String>,
    tags: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct KeyPatch {
    tenant: Option<String>,
    status: Option<String>,
    note: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(Serialize, sqlx::FromRow)]
struct TenantRow {
    id: i64,
    name: String,
    created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct TenantCreate {
    name: String,
}

#[derive(Deserialize)]
struct TenantRename {
    name: String,
}

#[derive(Deserialize)]
struct RequestCreate {
    public_hex: String,
    private_hex: String,
    tenant: String,
    note: String,
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RequestApprove {
    tenant: Option<String>,
    status: Option<String>,
    note: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RequestReject {
    reason: String,
}

#[derive(Deserialize)]
struct RequestPatch {
    tenant: Option<String>,
    note: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(Serialize, sqlx::FromRow)]
struct RequestRow {
    id: i64,
    public_hex: String,
    tenant: String,
    note: String,
    tags: Vec<String>,
    status: String,
    requested_by: Option<String>,
    requested_at: DateTime<Utc>,
    decided_by: Option<String>,
    decided_at: Option<DateTime<Utc>>,
    decision_note: Option<String>,
}

#[derive(sqlx::FromRow)]
struct RequestRowSecret {
    public_hex: String,
    private_hex: Option<String>,
    tenant: String,
    note: String,
    tags: Vec<String>,
}

#[derive(sqlx::FromRow)]
struct KeyPrivateRow {
    public_hex: String,
    tenant: String,
    private_hex: Option<String>,
}

#[derive(Serialize)]
struct KeyPrivateResponse {
    public_hex: String,
    private_hex: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?;
    let addr: SocketAddr = std::env::var("ENCJSON_VAULT_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .map_err(|err| anyhow::anyhow!("Invalid ENCJSON_VAULT_ADDR: {err}"))?;
    let auth_required = std::env::var("ENCJSON_VAULT_AUTH")
        .ok()
        .map(|v| v == "required")
        .unwrap_or(false);
    let jwt_issuer = std::env::var("ENCJSON_JWT_ISSUER").ok();
    let jwks_url = std::env::var("ENCJSON_JWKS_URL").ok();
    let jwt_audience = std::env::var("ENCJSON_JWT_AUDIENCE").ok();

    let db = PgPool::connect(&database_url).await?;
    sqlx::migrate!().run(&db).await?;

    let jwks = if auth_required {
        let issuer = jwt_issuer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ENCJSON_JWT_ISSUER is required when auth is enabled"))?;
        let url = jwks_url
            .clone()
            .unwrap_or_else(|| format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/')));
        info!("loading JWKS from {}", url);
        load_jwks(&url).await?
    } else {
        std::collections::HashMap::new()
    };

    let state = AppState {
        db,
        auth_required,
        jwt_issuer,
        jwt_audience,
        jwks,
    };

    let app = Router::new()
        .route("/v1/keys", get(list_keys))
        .route("/v1/keys/{public_hex}", get(get_key).patch(patch_key))
        .route("/v1/keys/{public_hex}/private", get(get_private_key))
        .route("/v1/me", get(get_me))
        .route("/v1/tenants", get(list_tenants).post(create_tenant))
        .route("/v1/tenants/{name}", patch(rename_tenant).delete(delete_tenant))
        .route("/v1/statuses", get(list_statuses))
        .route("/v1/requests", get(list_requests).post(create_request))
        .route("/v1/requests/{id}", patch(update_request))
        .route("/v1/requests/{id}/approve", post(approve_request))
        .route("/v1/requests/{id}/reject", post(reject_request))
        .with_state(state);

    info!("listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn list_keys(
    State(state): State<AppState>,
    Query(query): Query<KeyQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    let mut builder = QueryBuilder::<Postgres>::new(
        "select public_hex, tenant, status, note, tags, created_at, updated_at from keys",
    );
    let mut has_where = false;
    let tenant_filter = if auth.is_admin {
        query.tenant
    } else {
        if let Some(tenant) = query.tenant {
            if !auth.tenants.contains(&tenant) {
                return (StatusCode::FORBIDDEN, "tenant not allowed").into_response();
            }
            Some(tenant)
        } else {
            None
        }
    };

    if let Some(tenant) = tenant_filter {
        builder.push(if has_where { " and " } else { " where " });
        has_where = true;
        builder.push("tenant = ").push_bind(tenant);
    } else if !auth.is_admin {
        if auth.tenants.is_empty() {
            return (StatusCode::FORBIDDEN, "no tenant access").into_response();
        }
        builder.push(if has_where { " and " } else { " where " });
        has_where = true;
        builder.push("tenant = any(")
            .push_bind(auth.tenants.clone())
            .push(")");
    }
    if let Some(status) = query.status {
        builder.push(if has_where { " and " } else { " where " });
        has_where = true;
        builder.push("status = ").push_bind(status);
    }
    if let Some(q) = query.q.filter(|s| !s.trim().is_empty()) {
        let like = format!("%{}%", q.trim());
        let like_note = like.clone();
        builder.push(if has_where { " and " } else { " where " });
        builder.push("(public_hex like ");
        builder.push_bind(like);
        builder.push(" or coalesce(note, '') like ");
        builder.push_bind(like_note);
        builder.push(")");
    }
    builder.push(" order by created_at desc");

    let query = builder.build_query_as::<KeyRow>();
    let rows = match query.fetch_all(&state.db).await {
        Ok(rows) => rows,
        Err(err) => return server_error(err),
    };
    Json(rows).into_response()
}

async fn get_key(
    State(state): State<AppState>,
    Path(public_hex): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    let row = sqlx::query_as::<_, KeyRow>(
        "select public_hex, tenant, status, note, tags, created_at, updated_at from keys where public_hex = $1",
    )
    .bind(public_hex)
    .fetch_optional(&state.db)
    .await;
    match row {
        Ok(Some(row)) => {
            if !auth.is_admin && !auth.tenants.contains(&row.tenant) {
                return (StatusCode::FORBIDDEN, "tenant not allowed").into_response();
            }
            Json(row).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(err) => server_error(err),
    }
}

async fn get_private_key(
    State(state): State<AppState>,
    Path(public_hex): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    let row = sqlx::query_as::<_, KeyPrivateRow>(
        "select public_hex, tenant, private_hex from keys where public_hex = $1",
    )
    .bind(public_hex)
    .fetch_optional(&state.db)
    .await;

    match row {
        Ok(Some(row)) => {
            if !auth.is_admin && !auth.tenants.contains(&row.tenant) {
                return (StatusCode::FORBIDDEN, "tenant not allowed").into_response();
            }
            let Some(private_hex) = row.private_hex else {
                return (StatusCode::NOT_FOUND, "private key not available").into_response();
            };
            Json(KeyPrivateResponse {
                public_hex: row.public_hex,
                private_hex,
            })
            .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(err) => server_error(err),
    }
}

async fn patch_key(
    State(state): State<AppState>,
    Path(public_hex): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<KeyPatch>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    if !auth.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => return server_error(err),
    };
    let existing = match sqlx::query_as::<_, KeyRow>(
        "select public_hex, tenant, status, note, tags, created_at, updated_at from keys where public_hex = $1",
    )
    .bind(&public_hex)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(err) => return server_error(err),
    };

    let tenant = payload.tenant.unwrap_or(existing.tenant);
    let status = payload.status.unwrap_or(existing.status);
    let note = payload.note.or(existing.note);
    let tags = payload.tags.unwrap_or(existing.tags);

    let updated = sqlx::query_as::<_, KeyRow>(
        "update keys set tenant = $2, status = $3, note = $4, tags = $5, updated_at = now() \
         where public_hex = $1 returning public_hex, tenant, status, note, tags, created_at, updated_at",
    )
    .bind(&public_hex)
    .bind(tenant)
    .bind(status)
    .bind(note)
    .bind(tags)
    .fetch_one(&mut *tx)
    .await;

    match updated {
        Ok(row) => {
            if let Err(err) = tx.commit().await {
                return server_error(err);
            }
            Json(row).into_response()
        }
        Err(err) => server_error(err),
    }
}

async fn list_tenants(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    if !auth.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let rows = sqlx::query_as::<_, TenantRow>(
        "select id, name, created_at from tenants order by name",
    )
    .fetch_all(&state.db)
    .await;
    match rows {
        Ok(rows) => Json(rows).into_response(),
        Err(err) => server_error(err),
    }
}

async fn create_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TenantCreate>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    if !auth.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let name = payload.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name required").into_response();
    }
    let row = sqlx::query_as::<_, TenantRow>(
        "insert into tenants (name) values ($1) returning id, name, created_at",
    )
    .bind(name)
    .fetch_one(&state.db)
    .await;
    match row {
        Ok(row) => Json(row).into_response(),
        Err(err) => server_error(err),
    }
}

async fn rename_tenant(
    State(state): State<AppState>,
    Path(old_name): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<TenantRename>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    if !auth.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let new_name = payload.name.trim();
    if new_name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name required").into_response();
    }

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => return server_error(err),
    };

    let row = match sqlx::query_as::<_, TenantRow>(
        "update tenants set name = $2 where name = $1 returning id, name, created_at",
    )
    .bind(&old_name)
    .bind(new_name)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(err) => return server_error(err),
    };

    let _ = sqlx::query("update keys set tenant = $2 where tenant = $1")
        .bind(&old_name)
        .bind(new_name)
        .execute(&mut *tx)
        .await;
    let _ = sqlx::query("update requests set tenant = $2 where tenant = $1")
        .bind(&old_name)
        .bind(new_name)
        .execute(&mut *tx)
        .await;

    if let Err(err) = tx.commit().await {
        return server_error(err);
    }
    Json(row).into_response()
}

async fn delete_tenant(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    if !auth.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => return server_error(err),
    };

    let tenant = match sqlx::query_scalar::<_, i64>("select count(*) from tenants where name = $1")
        .bind(&name)
        .fetch_one(&mut *tx)
        .await
    {
        Ok(count) => count,
        Err(err) => return server_error(err),
    };
    if tenant == 0 {
        return (StatusCode::NOT_FOUND, "tenant not found").into_response();
    }

    let keys_count =
        match sqlx::query_scalar::<_, i64>("select count(*) from keys where tenant = $1")
            .bind(&name)
            .fetch_one(&mut *tx)
            .await
        {
            Ok(count) => count,
            Err(err) => return server_error(err),
        };
    if keys_count > 0 {
        return (
            StatusCode::CONFLICT,
            "tenant has associated keys",
        )
            .into_response();
    }
    let requests_count = match sqlx::query_scalar::<_, i64>(
        "select count(*) from requests where tenant = $1",
    )
    .bind(&name)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(count) => count,
        Err(err) => return server_error(err),
    };
    if requests_count > 0 {
        return (
            StatusCode::CONFLICT,
            "tenant has associated requests",
        )
            .into_response();
    }

    let delete = sqlx::query("delete from tenants where name = $1")
        .bind(&name)
        .execute(&mut *tx)
        .await;
    if let Err(err) = delete {
        return server_error(err);
    }
    if let Err(err) = tx.commit().await {
        return server_error(err);
    }

    StatusCode::NO_CONTENT.into_response()
}

async fn list_statuses(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    if !auth.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    Json(vec![
        "active".to_string(),
        "deprecated".to_string(),
        "hidden".to_string(),
    ])
    .into_response()
}

async fn create_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RequestCreate>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    if !auth.is_admin && !auth.is_scoped {
        return (StatusCode::FORBIDDEN, "role not allowed").into_response();
    }
    if !is_hex_64(&payload.public_hex) {
        return (StatusCode::BAD_REQUEST, "invalid public_hex").into_response();
    }
    if !is_hex_64(&payload.private_hex) {
        return (StatusCode::BAD_REQUEST, "invalid private_hex").into_response();
    }
    let tags = payload.tags.unwrap_or_default();
    let requested_by = headers
        .get("x-user")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or(auth.subject.clone());

    let row = sqlx::query_as::<_, RequestRow>(
        "insert into requests (public_hex, private_hex, tenant, note, tags, requested_by) \
         values ($1, $2, $3, $4, $5, $6) \
         returning id, public_hex, tenant, note, tags, status, requested_by, \
                   requested_at, decided_by, decided_at, decision_note",
    )
    .bind(payload.public_hex)
    .bind(payload.private_hex)
    .bind(payload.tenant)
    .bind(payload.note)
    .bind(tags)
    .bind(requested_by)
    .fetch_one(&state.db)
    .await;

    match row {
        Ok(row) => Json(row).into_response(),
        Err(err) => server_error(err),
    }
}

#[derive(Deserialize)]
struct RequestListQuery {
    status: Option<String>,
}

async fn list_requests(
    State(state): State<AppState>,
    Query(query): Query<RequestListQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    if !auth.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let rows = if let Some(status) = query.status {
        sqlx::query_as::<_, RequestRow>(
            "select id, public_hex, tenant, note, tags, status, requested_by, requested_at, \
                    decided_by, decided_at, decision_note \
             from requests where status = $1 order by requested_at desc",
        )
        .bind(status)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, RequestRow>(
            "select id, public_hex, tenant, note, tags, status, requested_by, requested_at, \
                    decided_by, decided_at, decision_note \
             from requests order by requested_at desc",
        )
        .fetch_all(&state.db)
        .await
    };

    match rows {
        Ok(rows) => Json(rows).into_response(),
        Err(err) => server_error(err),
    }
}

async fn update_request(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<RequestPatch>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    if !auth.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => return server_error(err),
    };
    let req = match sqlx::query_as::<_, RequestRow>(
        "select id, public_hex, tenant, note, tags, status, requested_by, requested_at, \
                decided_by, decided_at, decision_note \
         from requests where id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(err) => return server_error(err),
    };
    if req.status != "pending" {
        return (StatusCode::CONFLICT, "request not pending").into_response();
    }
    let tenant = payload.tenant.unwrap_or(req.tenant.clone());
    let note = payload.note.unwrap_or(req.note.clone());
    let tags = payload.tags.unwrap_or(req.tags.clone());

    let updated = sqlx::query_as::<_, RequestRow>(
        "update requests set tenant = $2, note = $3, tags = $4 where id = $1 \
         returning id, public_hex, tenant, note, tags, status, requested_by, requested_at, \
                   decided_by, decided_at, decision_note",
    )
    .bind(id)
    .bind(&tenant)
    .bind(&note)
    .bind(&tags)
    .fetch_one(&mut *tx)
    .await;

    match updated {
        Ok(row) => {
            if let Err(err) = tx.commit().await {
                return server_error(err);
            }
            Json(row).into_response()
        }
        Err(err) => server_error(err),
    }
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

async fn load_jwks(url: &str) -> anyhow::Result<std::collections::HashMap<String, DecodingKey>> {
    let body = reqwest::get(url).await?.text().await?;
    let set: JwkSet = serde_json::from_str(&body)?;
    let mut map = std::collections::HashMap::new();
    for jwk in set.keys {
        if let Some(kid) = jwk.common.key_id.clone() {
            let key = DecodingKey::from_jwk(&jwk)?;
            map.insert(kid, key);
        }
    }
    Ok(map)
}

async fn approve_request(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<RequestApprove>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    if !auth.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let decided_by = headers
        .get("x-user")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or(auth.subject.clone());

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => return server_error(err),
    };
    let req = match sqlx::query_as::<_, RequestRowSecret>(
        "select public_hex, private_hex, tenant, note, tags from requests where id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(err) => return server_error(err),
    };
    let Some(private_hex) = req.private_hex.clone() else {
        return (StatusCode::BAD_REQUEST, "private key missing in request").into_response();
    };

    let tenant = payload.tenant.unwrap_or(req.tenant.clone());
    let status = payload.status.unwrap_or_else(|| "active".to_string());
    let note = payload.note.unwrap_or(req.note.clone());
    let tags = payload.tags.unwrap_or(req.tags.clone());

    let _ = sqlx::query(
        "insert into keys (public_hex, private_hex, tenant, status, note, tags) \
         values ($1, $2, $3, $4, $5, $6) \
         on conflict (public_hex) do update \
         set private_hex = excluded.private_hex, tenant = excluded.tenant, \
             status = excluded.status, note = excluded.note, tags = excluded.tags, updated_at = now()",
    )
    .bind(&req.public_hex)
    .bind(private_hex)
    .bind(&tenant)
    .bind(&status)
    .bind(&note)
    .bind(&tags)
    .execute(&mut *tx)
    .await;

    let updated = sqlx::query_as::<_, RequestRow>(
        "update requests set status = 'approved', tenant = $2, note = $3, tags = $4, \
         decided_by = $5, decided_at = now(), decision_note = $6 where id = $1 \
         returning id, public_hex, tenant, note, tags, status, requested_by, requested_at, \
                   decided_by, decided_at, decision_note",
    )
    .bind(id)
    .bind(&tenant)
    .bind(&note)
    .bind(&tags)
    .bind(decided_by)
    .bind(None::<String>)
    .fetch_one(&mut *tx)
    .await;

    match updated {
        Ok(row) => {
            if let Err(err) = tx.commit().await {
                return server_error(err);
            }
            Json(row).into_response()
        }
        Err(err) => server_error(err),
    }
}

async fn reject_request(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<RequestReject>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    if !auth.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let decided_by = headers
        .get("x-user")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or(auth.subject.clone());

    let row = sqlx::query_as::<_, RequestRow>(
        "update requests set status = 'rejected', decided_by = $2, decided_at = now(), \
         decision_note = $3 where id = $1 \
         returning id, public_hex, tenant, note, tags, status, requested_by, requested_at, \
                   decided_by, decided_at, decision_note",
    )
    .bind(id)
    .bind(decided_by)
    .bind(payload.reason)
    .fetch_one(&state.db)
    .await;

    match row {
        Ok(row) => Json(row).into_response(),
        Err(err) => server_error(err),
    }
}

#[derive(Debug, Clone)]
struct AuthContext {
    is_admin: bool,
    is_scoped: bool,
    tenants: Vec<String>,
    subject: Option<String>,
    groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Claims {
    sub: Option<String>,
    iss: Option<String>,
    aud: Option<serde_json::Value>,
    exp: usize,
    groups: Option<Groups>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Groups {
    One(String),
    Many(Vec<String>),
}

fn ensure_auth(state: &AppState, headers: &HeaderMap) -> Result<AuthContext, Response> {
    if !state.auth_required {
        return Ok(AuthContext {
            is_admin: true,
            is_scoped: true,
            tenants: Vec::new(),
            subject: None,
            groups: Vec::new(),
        });
    }
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err((StatusCode::UNAUTHORIZED, "missing authorization").into_response());
    };
    let Ok(auth) = value.to_str() else {
        return Err((StatusCode::UNAUTHORIZED, "invalid authorization").into_response());
    };
    if !auth.starts_with("Bearer ") {
        return Err((StatusCode::UNAUTHORIZED, "invalid authorization").into_response());
    }
    let auth = auth.strip_prefix("Bearer ").unwrap_or(auth);
    let header = match decode_header(auth) {
        Ok(header) => header,
        Err(_) => return Err((StatusCode::UNAUTHORIZED, "invalid token").into_response()),
    };
    let kid = header.kid.ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, "missing kid").into_response()
    })?;
    let key = state.jwks.get(&kid).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, "unknown kid").into_response()
    })?;
    let mut validation = Validation::new(header.alg);
    if let Some(issuer) = state.jwt_issuer.as_ref() {
        validation.set_issuer(&[issuer.as_str()]);
    }
    if let Some(aud) = state.jwt_audience.as_ref() {
        validation.set_audience(&[aud.as_str()]);
    } else {
        validation.validate_aud = false;
    }
    let token = decode::<Claims>(auth, key, &validation)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "token invalid").into_response())?;
    let groups = token
        .claims
        .groups
        .map(groups_to_vec)
        .unwrap_or_default();
    let is_admin = groups.iter().any(|g| g == "encjson:role:admin");
    let is_scoped = groups.iter().any(|g| g == "encjson:role:scoped");
    if !is_admin && !is_scoped {
        return Err((StatusCode::FORBIDDEN, "role not allowed").into_response());
    }
    let tenants = groups
        .iter()
        .filter_map(|g| g.strip_prefix("encjson:tenant:").map(|v| v.to_string()))
        .collect();
    Ok(AuthContext {
        is_admin,
        is_scoped,
        tenants,
        subject: token.claims.sub,
        groups,
    })
}

#[derive(Serialize)]
struct MeResponse {
    subject: Option<String>,
    groups: Vec<String>,
    tenants: Vec<String>,
    is_admin: bool,
    is_scoped: bool,
}

async fn get_me(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    Json(MeResponse {
        subject: auth.subject,
        groups: auth.groups,
        tenants: auth.tenants,
        is_admin: auth.is_admin,
        is_scoped: auth.is_scoped,
    })
    .into_response()
}

fn groups_to_vec(groups: Groups) -> Vec<String> {
    match groups {
        Groups::One(value) => vec![value],
        Groups::Many(values) => values,
    }
}

fn server_error(err: impl std::fmt::Display) -> axum::response::Response {
    error!("server error: {}", err);
    (StatusCode::INTERNAL_SERVER_ERROR, "server error").into_response()
}
