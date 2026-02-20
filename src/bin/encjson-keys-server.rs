use std::net::SocketAddr;

use axum::{
    extract::{Path, Query, State, Form},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response, Redirect},
    routing::{get, patch, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, QueryBuilder};
use tracing::{error, info};
use x25519_dalek::{PublicKey, StaticSecret};
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng}, AeadCore};
use aes_gcm::aead::generic_array::GenericArray;
use base64::Engine;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use sha2::Digest;
use rand::Rng;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use urlencoding::encode;
use std::fmt::Write as _;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    auth_required: bool,
    jwt_issuer: Option<String>,
    jwt_audience: Option<String>,
    jwks: std::collections::HashMap<String, DecodingKey>,
    rate_limit: RateLimitCfg,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    ui: UiCfg,
    ui_states: Arc<Mutex<HashMap<String, UiAuthState>>>,
    ui_sessions: Arc<Mutex<HashMap<String, UiSession>>>,
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

#[derive(Clone, Debug)]
struct RateLimitCfg {
    per_minute: u64,
    requests_per_minute: u64,
}

#[derive(Clone, Debug)]
struct UiCfg {
    enabled: bool,
    issuer: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    base_url: Option<String>,
    cookie_secure: bool,
}

#[derive(Clone, Debug)]
struct UiAuthState {
    code_verifier: String,
    nonce: String,
    created_at: Instant,
}

#[derive(Clone, Debug)]
struct UiSession {
    subject: String,
    #[allow(dead_code)]
    groups: Vec<String>,
    tenants: Vec<String>,
    is_admin: bool,
    is_scoped: bool,
    expires_at: Instant,
}

#[derive(Default)]
struct RateLimiter {
    hits: HashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    fn check_and_record(&mut self, key: &str, limit: u64, window: Duration) -> bool {
        let now = Instant::now();
        let entries = self.hits.entry(key.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < window);
        if entries.len() as u64 >= limit {
            return false;
        }
        entries.push(now);
        true
    }
}

const ENC_PREFIX: &str = "encjson:aesgcm:";
const STATUS_ACTIVE: &str = "active";
const STATUS_REVOKED: &str = "revoked";

fn is_valid_key_status(status: &str) -> bool {
    matches!(status, STATUS_ACTIVE | STATUS_REVOKED)
}

fn public_from_private_hex(private_hex: &str) -> anyhow::Result<String> {
    let bytes = hex::decode(private_hex).map_err(|_| anyhow::anyhow!("invalid private_hex"))?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!("invalid private_hex length"));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    let secret = StaticSecret::from(key_bytes);
    let public = PublicKey::from(&secret);
    Ok(hex::encode(public.as_bytes()))
}

fn encryption_key() -> anyhow::Result<[u8; 32]> {
    let secret = std::env::var("ENCRYPTION_SECRET")
        .map_err(|_| anyhow::anyhow!("ENCRYPTION_SECRET is required"))?;
    let hash = sha2::Sha256::digest(secret.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    Ok(key)
}

fn random_token() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn layout(title: &str, tabs: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{}</title>
  <link href="https://unpkg.com/@tabler/core@latest/dist/css/tabler.min.css" rel="stylesheet">
  <script src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body class="bg-light">
  <div class="page">
    <header class="navbar navbar-expand-md navbar-light d-print-none">
      <div class="container-xl">
        <span class="navbar-brand">encjson-keys-server</span>
        <div class="navbar-nav ms-auto">
          <a class="nav-link" href="/ui/logout">Logout</a>
        </div>
      </div>
    </header>
    <div class="page-wrapper">
      <div class="container-xl mt-3">
        {}
        <div class="card mt-3">
          <div class="card-body">
            {}
          </div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>"#,
        title, tabs, body
    )
}

fn tabs(active: &str) -> String {
    let items = [
        ("keys", "Keys", "/ui/keys"),
        ("requests", "Requests", "/ui/requests"),
        ("tenants", "Tenants", "/ui/tenants"),
    ];
    let mut out = String::new();
    out.push_str(r#"<ul class="nav nav-tabs">"#);
    for (id, label, href) in items {
        let cls = if id == active { "nav-link active" } else { "nav-link" };
        let _ = write!(
            out,
            r#"<li class="nav-item"><a class="{}" href="{}">{}</a></li>"#,
            cls, href, label
        );
    }
    out.push_str("</ul>");
    out
}

fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let mut it = part.trim().splitn(2, '=');
        let k = it.next()?.trim();
        let v = it.next()?.trim();
        if k == name {
            return Some(v.to_string());
        }
    }
    None
}

async fn ui_session(state: &AppState, headers: &HeaderMap) -> Option<UiSession> {
    let sid = get_cookie(headers, "encjson_ui")?;
    let mut sessions = state.ui_sessions.lock().await;
    let sess = sessions.get(&sid).cloned()?;
    if Instant::now() > sess.expires_at {
        sessions.remove(&sid);
        return None;
    }
    Some(sess)
}

fn set_cookie(value: &str, secure: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let mut cookie = format!("encjson_ui={value}; HttpOnly; SameSite=Lax; Path=/");
    if secure {
        cookie.push_str("; Secure");
    }
    headers.insert(axum::http::header::SET_COOKIE, cookie.parse().unwrap());
    headers
}

fn encrypt_private_hex(plaintext: &str) -> anyhow::Result<String> {
    let key = encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("encrypt failed"))?;
    let mut buf = Vec::with_capacity(nonce.len() + ciphertext.len());
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(&ciphertext);
    let b64 = base64::engine::general_purpose::STANDARD.encode(buf);
    Ok(format!("{ENC_PREFIX}{b64}"))
}

fn decrypt_private_hex(stored: &str) -> anyhow::Result<String> {
    if let Some(rest) = stored.strip_prefix(ENC_PREFIX) {
        let key = encryption_key()?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(rest)
            .map_err(|_| anyhow::anyhow!("decrypt failed"))?;
        if raw.len() < 13 {
            return Err(anyhow::anyhow!("decrypt failed"));
        }
        let (nonce, ciphertext) = raw.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = GenericArray::from_slice(nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("decrypt failed"))?;
        return Ok(String::from_utf8(plaintext)?);
    }
    Ok(stored.to_string())
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
    let addr: SocketAddr = std::env::var("ENCJSON_KEYS_ADDR")
        .or_else(|_| std::env::var("ENCJSON_VAULT_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .map_err(|err| anyhow::anyhow!("Invalid ENCJSON_KEYS_ADDR: {err}"))?;
    let auth_required = std::env::var("ENCJSON_KEYS_AUTH")
        .or_else(|_| std::env::var("ENCJSON_VAULT_AUTH"))
        .ok()
        .map(|v| v == "required")
        .unwrap_or(false);
    let jwt_issuer = std::env::var("ENCJSON_KEYS_JWT_ISSUER")
        .or_else(|_| std::env::var("ENCJSON_JWT_ISSUER"))
        .ok();
    let jwks_url = std::env::var("ENCJSON_KEYS_JWKS_URL")
        .or_else(|_| std::env::var("ENCJSON_JWKS_URL"))
        .ok();
    let jwt_audience = std::env::var("ENCJSON_KEYS_JWT_AUDIENCE")
        .or_else(|_| std::env::var("ENCJSON_JWT_AUDIENCE"))
        .ok();

    let db = PgPool::connect(&database_url).await?;
    sqlx::migrate!().run(&db).await?;

    let jwks = if auth_required {
        let issuer = jwt_issuer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ENCJSON_KEYS_JWT_ISSUER is required when auth is enabled"))?;
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
        rate_limit: RateLimitCfg {
            per_minute: std::env::var("ENCJSON_KEYS_RATE_LIMIT_PER_MINUTE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            requests_per_minute: std::env::var("ENCJSON_KEYS_REQUESTS_RATE_LIMIT_PER_MINUTE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
        },
        rate_limiter: Arc::new(Mutex::new(RateLimiter::default())),
        ui: UiCfg {
            enabled: std::env::var("ENCJSON_KEYS_UI_ENABLED")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            issuer: std::env::var("ENCJSON_KEYS_UI_ISSUER").ok(),
            client_id: std::env::var("ENCJSON_KEYS_UI_CLIENT_ID").ok(),
            client_secret: std::env::var("ENCJSON_KEYS_UI_CLIENT_SECRET").ok(),
            base_url: std::env::var("ENCJSON_KEYS_UI_BASE_URL").ok(),
            cookie_secure: std::env::var("ENCJSON_KEYS_UI_COOKIE_SECURE")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
        },
        ui_states: Arc::new(Mutex::new(HashMap::new())),
        ui_sessions: Arc::new(Mutex::new(HashMap::new())),
    };
    let ui_enabled = state.ui.enabled;

    let mut app = Router::new()
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
        .route("/v1/keys/reencrypt", post(reencrypt_keys));

    if ui_enabled {
        app = app
            .route("/ui", get(ui_index))
            .route("/ui/login", get(ui_login))
            .route("/ui/callback", get(ui_callback))
            .route("/ui/logout", get(ui_logout))
            .route("/ui/keys", get(ui_keys))
            .route("/ui/keys/list", get(ui_keys_list))
            .route("/ui/keys/{public_hex}", get(ui_key_detail))
            .route("/ui/keys/{public_hex}/edit", post(ui_key_edit))
            .route("/ui/requests", get(ui_requests))
            .route("/ui/requests/list", get(ui_requests_list))
            .route("/ui/requests", post(ui_request_create))
            .route("/ui/requests/{id}/approve", post(ui_request_approve))
            .route("/ui/requests/{id}/reject", post(ui_request_reject))
            .route("/ui/tenants", get(ui_tenants))
            .route("/ui/tenants/list", get(ui_tenants_list))
            .route("/ui/tenants/add", post(ui_tenant_add))
            .route("/ui/tenants/{name}/rename", post(ui_tenant_rename))
            .route("/ui/tenants/{name}/delete", post(ui_tenant_delete))
            .route("/ui/keys/reencrypt", post(ui_reencrypt));
    }

    let app = app.with_state::<()>(state);
    info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
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
    let limiter_key = format!(
        "{}:{}",
        auth.subject.clone().unwrap_or_else(|| "anon".to_string()),
        public_hex
    );
    let allowed = {
        let mut limiter = state.rate_limiter.lock().await;
        limiter.check_and_record(
            &limiter_key,
            state.rate_limit.per_minute,
            Duration::from_secs(60),
        )
    };
    if !allowed {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit").into_response();
    }
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
            let private_hex = match decrypt_private_hex(&private_hex) {
                Ok(v) => v,
                Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "decrypt failed").into_response(),
            };
            let _ = sqlx::query(
                "insert into key_access_log (public_hex, tenant, subject, reason) values ($1, $2, $3, $4)",
            )
            .bind(&row.public_hex)
            .bind(&row.tenant)
            .bind(auth.subject.clone())
            .bind("get_private_key")
            .execute(&state.db)
            .await;
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
    if let Some(ref status) = payload.status {
        if !is_valid_key_status(status) {
            return (StatusCode::BAD_REQUEST, "invalid status").into_response();
        }
    }
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
    Json(vec![STATUS_ACTIVE, STATUS_REVOKED]).into_response()
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
    let limiter_key = format!(
        "request:{}",
        auth.subject.clone().unwrap_or_else(|| "anon".to_string())
    );
    let allowed = {
        let mut limiter = state.rate_limiter.lock().await;
        limiter.check_and_record(
            &limiter_key,
            state.rate_limit.requests_per_minute,
            Duration::from_secs(60),
        )
    };
    if !allowed {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit").into_response();
    }
    if !is_hex_64(&payload.public_hex) {
        return (StatusCode::BAD_REQUEST, "invalid public_hex").into_response();
    }
    if !is_hex_64(&payload.private_hex) {
        return (StatusCode::BAD_REQUEST, "invalid private_hex").into_response();
    }
    let derived = match public_from_private_hex(payload.private_hex.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid private_hex").into_response(),
    };
    if derived != payload.public_hex.trim() {
        return (StatusCode::BAD_REQUEST, "public/private mismatch").into_response();
    }
    let tags = payload.tags.unwrap_or_default();
    let requested_by = headers
        .get("x-user")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or(auth.subject.clone());

    let encrypted = match encrypt_private_hex(payload.private_hex.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "encrypt failed").into_response(),
    };

    let row = sqlx::query_as::<_, RequestRow>(
        "insert into requests (public_hex, private_hex, tenant, note, tags, requested_by) \
         values ($1, $2, $3, $4, $5, $6) \
         returning id, public_hex, tenant, note, tags, status, requested_by, \
                   requested_at, decided_by, decided_at, decision_note",
    )
    .bind(payload.public_hex)
    .bind(encrypted)
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

#[derive(Serialize)]
struct ReencryptResult {
    keys_updated: i64,
    requests_updated: i64,
}

async fn reencrypt_keys(
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

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => return server_error(err),
    };

    let rows = sqlx::query_as::<_, (String, String)>(
        "select public_hex, private_hex from keys where private_hex is not null",
    )
    .fetch_all(&mut *tx)
    .await;
    let rows = match rows {
        Ok(v) => v,
        Err(err) => return server_error(err),
    };

    let mut keys_updated = 0i64;
    for (public_hex, private_hex) in rows {
        if private_hex.starts_with(ENC_PREFIX) {
            continue;
        }
        let encrypted = match encrypt_private_hex(&private_hex) {
            Ok(v) => v,
            Err(err) => return server_error(err),
        };
        let _ = sqlx::query("update keys set private_hex = $2 where public_hex = $1")
            .bind(&public_hex)
            .bind(encrypted)
            .execute(&mut *tx)
            .await;
        keys_updated += 1;
    }

    let rows = sqlx::query_as::<_, (i64, String)>(
        "select id, private_hex from requests where private_hex is not null",
    )
    .fetch_all(&mut *tx)
    .await;
    let rows = match rows {
        Ok(v) => v,
        Err(err) => return server_error(err),
    };

    let mut requests_updated = 0i64;
    for (id, private_hex) in rows {
        if private_hex.starts_with(ENC_PREFIX) {
            continue;
        }
        let encrypted = match encrypt_private_hex(&private_hex) {
            Ok(v) => v,
            Err(err) => return server_error(err),
        };
        let _ = sqlx::query("update requests set private_hex = $2 where id = $1")
            .bind(id)
            .bind(encrypted)
            .execute(&mut *tx)
            .await;
        requests_updated += 1;
    }

    if let Err(err) = tx.commit().await {
        return server_error(err);
    }

    Json(ReencryptResult {
        keys_updated,
        requests_updated,
    })
    .into_response()
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
    let status = payload.status.unwrap_or_else(|| STATUS_ACTIVE.to_string());
    if !is_valid_key_status(&status) {
        return (StatusCode::BAD_REQUEST, "invalid status").into_response();
    }
    let note = payload.note.unwrap_or(req.note.clone());
    let tags = payload.tags.unwrap_or(req.tags.clone());

    let decrypted = match decrypt_private_hex(private_hex.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "decrypt failed").into_response(),
    };
    let derived = match public_from_private_hex(decrypted.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid private_hex").into_response(),
    };
    if derived != req.public_hex {
        return (StatusCode::BAD_REQUEST, "public/private mismatch").into_response();
    }
    let encrypted_key = match encrypt_private_hex(decrypted.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "encrypt failed").into_response(),
    };

    let _ = sqlx::query(
        "insert into keys (public_hex, private_hex, tenant, status, note, tags) \
         values ($1, $2, $3, $4, $5, $6) \
         on conflict (public_hex) do update \
         set private_hex = excluded.private_hex, tenant = excluded.tenant, \
             status = excluded.status, note = excluded.note, tags = excluded.tags, updated_at = now()",
    )
    .bind(&req.public_hex)
    .bind(encrypted_key)
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

// ---------------- UI (HTMX + Tabler) ----------------

#[derive(Deserialize)]
struct UiCallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct UiKeyEditForm {
    tenant: String,
    status: String,
    note: String,
    tags: String,
}


#[derive(Deserialize)]
struct UiTenantForm {
    name: String,
}

#[derive(Deserialize)]
struct UiTenantRenameForm {
    name: String,
}

#[derive(Deserialize)]
struct UiRequestCreateForm {
    public_hex: String,
    private_hex: String,
    tenant: String,
    note: String,
    tags: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    #[allow(dead_code)]
    access_token: String,
    id_token: String,
    expires_in: Option<i64>,
}

async fn ui_index() -> impl IntoResponse {
    Redirect::to("/ui/keys")
}

async fn ui_login(State(state): State<AppState>) -> impl IntoResponse {
    let Some(issuer) = state.ui.issuer.clone() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "UI issuer missing").into_response();
    };
    let Some(client_id) = state.ui.client_id.clone() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "UI client_id missing").into_response();
    };
    let Some(base_url) = state.ui.base_url.clone() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "UI base_url missing").into_response();
    };

    let state_token = random_token();
    let nonce = random_token();
    let code_verifier = random_token();
    let challenge = {
        let digest = sha2::Sha256::digest(code_verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    };

    state
        .ui_states
        .lock()
        .await
        .insert(state_token.clone(), UiAuthState {
            code_verifier,
            nonce: nonce.clone(),
            created_at: Instant::now(),
        });

    let redirect_uri = format!("{}/ui/callback", base_url.trim_end_matches('/'));
    let auth_url = format!(
        "{}/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email%20groups&state={}&code_challenge={}&code_challenge_method=S256&nonce={}",
        issuer.trim_end_matches('/'),
        encode(&client_id),
        encode(&redirect_uri),
        encode(&state_token),
        encode(&challenge),
        encode(&nonce),
    );
    Redirect::to(&auth_url).into_response()
}

async fn ui_callback(
    State(state): State<AppState>,
    Query(q): Query<UiCallbackQuery>,
) -> impl IntoResponse {
    let Some(issuer) = state.ui.issuer.clone() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "UI issuer missing").into_response();
    };
    let Some(client_id) = state.ui.client_id.clone() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "UI client_id missing").into_response();
    };
    let Some(client_secret) = state.ui.client_secret.clone() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "UI client_secret missing").into_response();
    };
    let Some(base_url) = state.ui.base_url.clone() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "UI base_url missing").into_response();
    };

    let st = state.ui_states.lock().await.remove(&q.state);
    let Some(auth_state) = st else {
        return (StatusCode::BAD_REQUEST, "invalid state").into_response();
    };
    if auth_state.created_at.elapsed() > Duration::from_secs(600) {
        return (StatusCode::BAD_REQUEST, "state expired").into_response();
    }

    let redirect_uri = format!("{}/ui/callback", base_url.trim_end_matches('/'));
    let token_url = format!("{}/oauth2/token", issuer.trim_end_matches('/'));

    let resp = reqwest::Client::new()
        .post(token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", q.code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code_verifier", auth_state.code_verifier.as_str()),
        ])
        .send()
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_REQUEST, "token exchange failed").into_response(),
    };
    if !resp.status().is_success() {
        return (StatusCode::BAD_REQUEST, "token exchange failed").into_response();
    }
    let token: TokenResponse = match resp.json().await {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid token response").into_response(),
    };

    let claims = match decode_id_token(&state, &token.id_token, &issuer, &client_id).await {
        Ok(c) => c,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid id_token").into_response(),
    };
    if claims.nonce.as_deref() != Some(auth_state.nonce.as_str()) {
        return (StatusCode::BAD_REQUEST, "invalid nonce").into_response();
    }

    let groups = claims
        .groups
        .map(groups_to_vec)
        .unwrap_or_default();
    let is_admin = groups.iter().any(|g| g == "encjson:role:admin");
    let is_scoped = groups.iter().any(|g| g == "encjson:role:scoped");
    if !is_admin && !is_scoped {
        return (StatusCode::FORBIDDEN, "role not allowed").into_response();
    }
    let tenants = groups
        .iter()
        .filter_map(|g| g.strip_prefix("encjson:tenant:").map(|v| v.to_string()))
        .collect::<Vec<_>>();

    let sid = random_token();
    let expires = Instant::now()
        + Duration::from_secs(token.expires_in.unwrap_or(3600).max(300) as u64);
    state.ui_sessions.lock().await.insert(
        sid.clone(),
        UiSession {
            subject: claims.sub.unwrap_or_else(|| "unknown".to_string()),
            groups,
            tenants,
            is_admin,
            is_scoped,
            expires_at: expires,
        },
    );

    let mut headers = set_cookie(&sid, state.ui.cookie_secure);
    headers.insert(axum::http::header::LOCATION, "/ui/keys".parse().unwrap());
    (StatusCode::FOUND, headers, "").into_response()
}

async fn decode_id_token(
    state: &AppState,
    token: &str,
    issuer: &str,
    audience: &str,
) -> anyhow::Result<Claims> {
    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| anyhow::anyhow!("missing kid"))?;

    let key = if let Some(k) = state.jwks.get(&kid) {
        k.clone()
    } else {
        let url = format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/'));
        let jwks = load_jwks(&url).await?;
        jwks.get(&kid).cloned().ok_or_else(|| anyhow::anyhow!("unknown kid"))?
    };

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    let token = decode::<Claims>(token, &key, &validation)?;
    Ok(token.claims)
}

async fn ui_logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(sid) = get_cookie(&headers, "encjson_ui") {
        state.ui_sessions.lock().await.remove(&sid);
    }
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::SET_COOKIE,
        "encjson_ui=; Max-Age=0; Path=/".parse().unwrap(),
    );
    h.insert(axum::http::header::LOCATION, "/ui/login".parse().unwrap());
    (StatusCode::FOUND, h, "").into_response()
}

async fn ui_require(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UiSession, Response> {
    if let Some(sess) = ui_session(state, headers).await {
        return Ok(sess);
    }
    Err(Redirect::to("/ui/login").into_response())
}

async fn ui_keys(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let _ = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let body = r#"<div id="list" hx-get="/ui/keys/list" hx-trigger="load"></div>
<div class="mt-3">
  <form method="post" action="/ui/keys/reencrypt">
    <button class="btn btn-warning" type="submit">Re-encrypt keys</button>
  </form>
</div>"#;
    let html = layout("Keys", &tabs("keys"), body);
    (StatusCode::OK, html).into_response()
}

async fn ui_keys_list(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let mut rows = String::new();
    let mut builder = QueryBuilder::<Postgres>::new(
        "select public_hex, tenant, status, note, tags, created_at, updated_at from keys",
    );
    if !sess.is_admin {
        if sess.tenants.is_empty() {
            return (StatusCode::FORBIDDEN, "no tenant access").into_response();
        }
        builder.push(" where tenant = any(").push_bind(sess.tenants.clone()).push(")");
    }
    builder.push(" order by created_at desc");
    let query = builder.build_query_as::<KeyRow>();
    let list = match query.fetch_all(&state.db).await {
        Ok(v) => v,
        Err(err) => return server_error(err),
    };
    for k in list {
        let tags = if k.tags.is_empty() { "-".to_string() } else { k.tags.join(", ") };
        let _ = write!(
            rows,
            r#"<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a class="btn btn-sm btn-outline-primary" href="/ui/keys/{}">Edit</a></td></tr>"#,
            html_escape(&k.public_hex),
            html_escape(&k.tenant),
            html_escape(&k.status),
            html_escape(k.note.as_deref().unwrap_or("-")),
            html_escape(&tags),
            html_escape(&k.public_hex),
        );
    }
    let html = format!(
        r#"<div id="list"><table class="table table-sm"><thead><tr><th>Public</th><th>Tenant</th><th>Status</th><th>Note</th><th>Tags</th><th></th></tr></thead><tbody>{}</tbody></table></div>"#,
        rows
    );
    (StatusCode::OK, html).into_response()
}

async fn ui_key_detail(
    State(state): State<AppState>,
    Path(public_hex): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !sess.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let row = sqlx::query_as::<_, KeyRow>(
        "select public_hex, tenant, status, note, tags, created_at, updated_at from keys where public_hex = $1",
    )
    .bind(public_hex.clone())
    .fetch_optional(&state.db)
    .await;
    let row = match row {
        Ok(v) => v,
        Err(err) => return server_error(err),
    };
    let Some(row) = row else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let tags = row.tags.join(", ");
    let body = format!(
        r#"<form method="post" action="/ui/keys/{public_hex}/edit">
  <div class="mb-3"><label class="form-label">Tenant</label>
    <input class="form-control" name="tenant" value="{tenant}">
  </div>
  <div class="mb-3"><label class="form-label">Status</label>
    <input class="form-control" name="status" value="{status}">
  </div>
  <div class="mb-3"><label class="form-label">Note</label>
    <input class="form-control" name="note" value="{note}">
  </div>
  <div class="mb-3"><label class="form-label">Tags</label>
    <input class="form-control" name="tags" value="{tags}">
  </div>
  <button class="btn btn-primary">Save</button>
</form>"#,
        public_hex = html_escape(&row.public_hex),
        tenant = html_escape(&row.tenant),
        status = html_escape(&row.status),
        note = html_escape(row.note.as_deref().unwrap_or("")),
        tags = html_escape(&tags),
    );
    let html = layout("Key", &tabs("keys"), &body);
    (StatusCode::OK, html).into_response()
}

async fn ui_key_edit(
    State(state): State<AppState>,
    Path(public_hex): Path<String>,
    headers: HeaderMap,
    Form(form): Form<UiKeyEditForm>,
) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !sess.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let tags = form
        .tags
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    let _ = sqlx::query(
        "update keys set tenant = $2, status = $3, note = $4, tags = $5, updated_at = now() where public_hex = $1",
    )
    .bind(public_hex)
    .bind(form.tenant)
    .bind(form.status)
    .bind(form.note)
    .bind(tags)
    .execute(&state.db)
    .await;
    Redirect::to("/ui/keys").into_response()
}

async fn ui_requests(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let _ = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let body = r#"
<div class="mb-3">
  <form method="post" action="/ui/requests">
    <div class="row g-2">
      <div class="col"><input class="form-control" name="public_hex" placeholder="public_hex"></div>
      <div class="col"><input class="form-control" name="private_hex" placeholder="private_hex"></div>
      <div class="col"><input class="form-control" name="tenant" placeholder="tenant"></div>
      <div class="col"><input class="form-control" name="note" placeholder="note"></div>
      <div class="col"><input class="form-control" name="tags" placeholder="tags"></div>
      <div class="col"><button class="btn btn-primary" type="submit">Create</button></div>
    </div>
  </form>
</div>
<div id="list" hx-get="/ui/requests/list" hx-trigger="load"></div>
"#;
    let html = layout("Requests", &tabs("requests"), body);
    (StatusCode::OK, html).into_response()
}

async fn ui_request_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UiRequestCreateForm>,
) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !sess.is_admin && !sess.is_scoped {
        return (StatusCode::FORBIDDEN, "role not allowed").into_response();
    }
    let tags = form
        .tags
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if !is_hex_64(&form.public_hex) || !is_hex_64(&form.private_hex) {
        return (StatusCode::BAD_REQUEST, "invalid key").into_response();
    }
    let derived = match public_from_private_hex(form.private_hex.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid private_hex").into_response(),
    };
    if derived != form.public_hex.trim() {
        return (StatusCode::BAD_REQUEST, "public/private mismatch").into_response();
    }
    let encrypted = match encrypt_private_hex(form.private_hex.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "encrypt failed").into_response(),
    };
    let requested_by = Some(sess.subject.clone());
    let _ = sqlx::query(
        "insert into requests (public_hex, private_hex, tenant, note, tags, requested_by) \
         values ($1, $2, $3, $4, $5, $6)",
    )
    .bind(form.public_hex.trim())
    .bind(encrypted)
    .bind(form.tenant.trim())
    .bind(form.note.trim())
    .bind(tags)
    .bind(requested_by)
    .execute(&state.db)
    .await;
    Redirect::to("/ui/requests").into_response()
}

async fn ui_requests_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let rows = if sess.is_admin {
        sqlx::query_as::<_, RequestRow>(
            "select id, public_hex, tenant, note, tags, status, requested_by, requested_at, decided_by, decided_at, decision_note \
             from requests order by requested_at desc",
        )
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, RequestRow>(
            "select id, public_hex, tenant, note, tags, status, requested_by, requested_at, decided_by, decided_at, decision_note \
             from requests where requested_by = $1 order by requested_at desc",
        )
        .bind(sess.subject.clone())
        .fetch_all(&state.db)
        .await
    };
    let rows = match rows {
        Ok(v) => v,
        Err(err) => return server_error(err),
    };
    let mut out = String::new();
    for r in rows {
        let tags = if r.tags.is_empty() { "-".to_string() } else { r.tags.join(", ") };
        let actions = if sess.is_admin {
            format!(
                r#"<form style="display:inline" method="post" action="/ui/requests/{}/approve"><button class="btn btn-sm btn-success">Approve</button></form>
<form style="display:inline" method="post" action="/ui/requests/{}/reject"><button class="btn btn-sm btn-danger">Reject</button></form>"#,
                r.id, r.id
            )
        } else {
            "-".to_string()
        };
        let _ = write!(
            out,
            r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
            html_escape(&r.public_hex),
            html_escape(&r.tenant),
            html_escape(&r.status),
            html_escape(&tags),
            html_escape(r.note.as_str()),
            actions
        );
    }
    let html = format!(
        r#"<div id="list"><table class="table table-sm"><thead><tr><th>Public</th><th>Tenant</th><th>Status</th><th>Tags</th><th>Note</th><th>Actions</th></tr></thead><tbody>{}</tbody></table></div>"#,
        out
    );
    (StatusCode::OK, html).into_response()
}

async fn ui_request_approve(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !sess.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
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
    let decrypted = match decrypt_private_hex(private_hex.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "decrypt failed").into_response(),
    };
    let derived = match public_from_private_hex(decrypted.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid private_hex").into_response(),
    };
    if derived != req.public_hex {
        return (StatusCode::BAD_REQUEST, "public/private mismatch").into_response();
    }
    let encrypted_key = match encrypt_private_hex(decrypted.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "encrypt failed").into_response(),
    };
    let _ = sqlx::query(
        "insert into keys (public_hex, private_hex, tenant, status, note, tags) \
         values ($1, $2, $3, $4, $5, $6) \
         on conflict (public_hex) do update \
         set private_hex = excluded.private_hex, tenant = excluded.tenant, \
             status = excluded.status, note = excluded.note, tags = excluded.tags, updated_at = now()",
    )
    .bind(&req.public_hex)
    .bind(encrypted_key)
    .bind(&req.tenant)
    .bind(STATUS_ACTIVE)
    .bind(&req.note)
    .bind(&req.tags)
    .execute(&mut *tx)
    .await;
    let _ = sqlx::query(
        "update requests set status = 'approved', decided_by = $2, decided_at = now() where id = $1",
    )
    .bind(id)
    .bind(sess.subject.clone())
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    Redirect::to("/ui/requests").into_response()
}

async fn ui_request_reject(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !sess.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let _ = sqlx::query(
        "update requests set status = 'rejected', decided_by = $2, decided_at = now(), decision_note = $3 where id = $1",
    )
    .bind(id)
    .bind(sess.subject.clone())
    .bind("rejected")
    .execute(&state.db)
    .await;
    Redirect::to("/ui/requests").into_response()
}

async fn ui_tenants(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !sess.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let body = r#"
<div class="mb-3">
  <form method="post" action="/ui/tenants/add">
    <div class="row g-2">
      <div class="col"><input class="form-control" name="name" placeholder="tenant"></div>
      <div class="col"><button class="btn btn-primary" type="submit">Add</button></div>
    </div>
  </form>
</div>
<div id="list" hx-get="/ui/tenants/list" hx-trigger="load"></div>
"#;
    let html = layout("Tenants", &tabs("tenants"), body);
    (StatusCode::OK, html).into_response()
}

async fn ui_tenants_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !sess.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let rows = sqlx::query_as::<_, TenantRow>(
        "select id, name, created_at from tenants order by name",
    )
    .fetch_all(&state.db)
    .await;
    let rows = match rows {
        Ok(v) => v,
        Err(err) => return server_error(err),
    };
    let mut out = String::new();
    for t in rows {
        let _ = write!(
            out,
            r#"<tr><td>{}</td><td>
<form style="display:inline" method="post" action="/ui/tenants/{}/rename">
  <input name="name" class="form-control form-control-sm d-inline-block" style="width:200px" placeholder="new name">
  <button class="btn btn-sm btn-outline-primary">Rename</button>
</form>
<form style="display:inline" method="post" action="/ui/tenants/{}/delete">
  <button class="btn btn-sm btn-outline-danger">Delete</button>
</form>
</td></tr>"#,
            html_escape(&t.name),
            html_escape(&t.name),
            html_escape(&t.name),
        );
    }
    let html = format!(
        r#"<div id="list"><table class="table table-sm"><thead><tr><th>Name</th><th>Actions</th></tr></thead><tbody>{}</tbody></table></div>"#,
        out
    );
    (StatusCode::OK, html).into_response()
}

async fn ui_tenant_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UiTenantForm>,
) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !sess.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let _ = sqlx::query("insert into tenants (name) values ($1)")
        .bind(form.name.trim())
        .execute(&state.db)
        .await;
    Redirect::to("/ui/tenants").into_response()
}

async fn ui_tenant_rename(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Form(form): Form<UiTenantRenameForm>,
) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !sess.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let _ = sqlx::query("update tenants set name = $2 where name = $1")
        .bind(&name)
        .bind(form.name.trim())
        .execute(&state.db)
        .await;
    let _ = sqlx::query("update keys set tenant = $2 where tenant = $1")
        .bind(&name)
        .bind(form.name.trim())
        .execute(&state.db)
        .await;
    let _ = sqlx::query("update requests set tenant = $2 where tenant = $1")
        .bind(&name)
        .bind(form.name.trim())
        .execute(&state.db)
        .await;
    Redirect::to("/ui/tenants").into_response()
}

async fn ui_tenant_delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !sess.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let _ = sqlx::query("delete from tenants where name = $1")
        .bind(&name)
        .execute(&state.db)
        .await;
    Redirect::to("/ui/tenants").into_response()
}

async fn ui_reencrypt(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !sess.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let _ = reencrypt_keys(State(state), headers).await;
    Redirect::to("/ui/keys").into_response()
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
    nonce: Option<String>,
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
