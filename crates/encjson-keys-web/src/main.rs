mod models;
mod views;

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use async_stream::stream;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Parser, ValueEnum};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use models::*;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use tracing::info;
use urlencoding::encode;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AuthMode {
    Local,
    Oidc,
}

#[derive(Debug, Parser)]
#[command(name = "encjson-keys-web", about = "Web UI for encjson-keys-server")]
struct Args {
    #[arg(long, env = "ENCJSON_KEYS_WEB_BIND", default_value = "127.0.0.1:8189")]
    bind: String,
    #[arg(long, env = "ENCJSON_KEYS_WEB_KEYS_SERVER", default_value = "http://127.0.0.1:8080")]
    keys_server: String,
    #[arg(long, env = "ENCJSON_KEYS_WEB_AUTH_MODE", value_enum, default_value = "local")]
    auth_mode: AuthMode,
    #[arg(long, env = "ENCJSON_KEYS_WEB_OPEN")]
    open: bool,

    #[arg(long, env = "ENCJSON_KEYS_WEB_OIDC_ISSUER")]
    oidc_issuer: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_WEB_OIDC_CLIENT_ID")]
    oidc_client_id: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_WEB_OIDC_CLIENT_SECRET")]
    oidc_client_secret: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_WEB_OIDC_REDIRECT_BASE_URL")]
    oidc_redirect_base_url: Option<String>,
    #[arg(
        long,
        env = "ENCJSON_KEYS_WEB_OIDC_SCOPES",
        default_value = "openid profile email groups"
    )]
    oidc_scopes: String,
    #[arg(
        long,
        env = "ENCJSON_KEYS_WEB_OIDC_ADMIN_ROLE",
        default_value = "encjson:role:admin"
    )]
    oidc_admin_role: String,
    #[arg(
        long,
        env = "ENCJSON_KEYS_WEB_OIDC_SCOPED_ROLE",
        default_value = "encjson:role:scoped"
    )]
    oidc_scoped_role: String,
    #[arg(long, env = "ENCJSON_KEYS_WEB_OIDC_COOKIE_SECURE")]
    oidc_cookie_secure: Option<bool>,
}

#[derive(Clone)]
struct AppState {
    http: reqwest::Client,
    keys_server_base: String,
    auth_mode: AuthMode,
    oidc: Option<Arc<OidcState>>,
}

#[derive(Debug)]
struct OidcState {
    cfg: OidcConfig,
    http: reqwest::Client,
    auth_states: tokio::sync::Mutex<HashMap<String, OidcAuthState>>,
    sessions: tokio::sync::Mutex<HashMap<String, OidcSession>>,
    jwks: tokio::sync::Mutex<HashMap<String, DecodingKey>>,
}

#[derive(Debug, Clone)]
struct OidcConfig {
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_base_url: String,
    scopes: String,
    admin_role: String,
    scoped_role: String,
    cookie_secure: bool,
}

#[derive(Debug, Clone)]
struct OidcAuthState {
    pkce_verifier: String,
    nonce: String,
    created_at: Instant,
}

#[derive(Debug, Clone)]
struct OidcSession {
    subject: String,
    roles: Vec<String>,
    access_token: String,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct UserContext {
    subject: String,
    roles: Vec<String>,
    access_token: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum AccessKind {
    Ui,
    Api,
}

#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    access_token: String,
    id_token: String,
    expires_in: Option<i64>,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "encjson_keys_web=info".into()),
        )
        .init();

    let args = Args::parse();
    let bind: SocketAddr = args
        .bind
        .parse()
        .map_err(|e| anyhow!("invalid bind address '{}': {}", args.bind, e))?;

    if matches!(args.auth_mode, AuthMode::Local) && !bind.ip().is_loopback() {
        return Err(anyhow!(
            "auth-mode=local is allowed only on loopback addresses (got {})",
            bind.ip()
        ));
    }
    if args.open && !matches!(args.auth_mode, AuthMode::Local) {
        return Err(anyhow!("--open is allowed only with --auth-mode local"));
    }

    let oidc = match args.auth_mode {
        AuthMode::Local => None,
        AuthMode::Oidc => {
            let issuer = args
                .oidc_issuer
                .clone()
                .ok_or_else(|| anyhow!("missing --oidc-issuer (or ENCJSON_KEYS_WEB_OIDC_ISSUER)"))?;
            let client_id = args.oidc_client_id.clone().ok_or_else(|| {
                anyhow!("missing --oidc-client-id (or ENCJSON_KEYS_WEB_OIDC_CLIENT_ID)")
            })?;
            let redirect_base_url = args.oidc_redirect_base_url.clone().ok_or_else(|| {
                anyhow!(
                    "missing --oidc-redirect-base-url (or ENCJSON_KEYS_WEB_OIDC_REDIRECT_BASE_URL)"
                )
            })?;

            let scopes = args
                .oidc_scopes
                .split_whitespace()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            if scopes.is_empty() {
                return Err(anyhow!("OIDC scopes cannot be empty"));
            }

            let cookie_secure = args
                .oidc_cookie_secure
                .unwrap_or_else(|| redirect_base_url.starts_with("https://"));

            let http = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("failed to build OIDC HTTP client")?;

            let cfg = OidcConfig {
                issuer,
                client_id,
                client_secret: args.oidc_client_secret,
                redirect_base_url,
                scopes: scopes.join(" "),
                admin_role: args.oidc_admin_role,
                scoped_role: args.oidc_scoped_role,
                cookie_secure,
            };

            Some(Arc::new(OidcState {
                cfg,
                http,
                auth_states: tokio::sync::Mutex::new(HashMap::new()),
                sessions: tokio::sync::Mutex::new(HashMap::new()),
                jwks: tokio::sync::Mutex::new(HashMap::new()),
            }))
        }
    };

    let state = AppState {
        http: reqwest::Client::new(),
        keys_server_base: args.keys_server.trim_end_matches('/').to_string(),
        auth_mode: args.auth_mode,
        oidc,
    };

    let app = app_router(state);

    if args.open {
        let url = format!("http://{}/ui", bind);
        let _ = open_browser(&url);
    }

    info!(bind = %bind, auth_mode = ?args.auth_mode, "encjson-keys-web started");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}


fn app_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/openapi.yaml", get(openapi_yaml))
        .route("/ui", get(ui_dashboard))
        .route("/ui/bootstrap", get(ui_bootstrap))
        .route("/ui/login", get(ui_login))
        .route("/ui/callback", get(ui_callback))
        .route("/ui/logout", get(ui_logout))
        .route("/ui/keys", get(ui_keys))
        .route("/ui/requests", get(ui_requests))
        .route("/ui/tenants", get(ui_tenants))
        .route("/api/v1/ui/me", get(api_me))
        .route("/api/v1/ui/events", get(api_events))
        .route("/api/v1/ui/bootstrap/import", post(api_bootstrap_import))
        .route("/api/v1/ui/keys", get(api_keys))
        .route("/api/v1/ui/keys/{public_hex}", get(api_key_detail).patch(api_patch_key))
        .route("/api/v1/ui/keys/reencrypt", post(api_reencrypt))
        .route("/api/v1/ui/requests", get(api_requests).post(api_create_request))
        .route(
            "/api/v1/ui/requests/{id}/approve",
            post(api_approve_request),
        )
        .route("/api/v1/ui/requests/{id}/reject", post(api_reject_request))
        .route("/api/v1/ui/tenants", get(api_tenants).post(api_create_tenant))
        .route(
            "/api/v1/ui/tenants/{name}",
            patch(api_rename_tenant).delete(api_delete_tenant),
        )
        .with_state(state)
}

async fn root() -> Redirect {
    Redirect::to("/ui")
}

async fn openapi_yaml() -> impl IntoResponse {
    (
        [("content-type", "application/yaml; charset=utf-8")],
        include_str!("../openapi/openapi.yaml"),
    )
}

async fn ui_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = ensure_user(&state, &headers, AccessKind::Ui).await {
        return resp;
    }
    Html(views::dashboard_html()).into_response()
}

async fn ui_keys(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = ensure_user(&state, &headers, AccessKind::Ui).await {
        return resp;
    }
    Html(views::keys_html()).into_response()
}

async fn ui_bootstrap(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Ui).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    if !is_admin_user(&user) {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    Html(views::bootstrap_html()).into_response()
}

async fn ui_requests(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = ensure_user(&state, &headers, AccessKind::Ui).await {
        return resp;
    }
    Html(views::requests_html()).into_response()
}

async fn ui_tenants(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = ensure_user(&state, &headers, AccessKind::Ui).await {
        return resp;
    }
    Html(views::tenants_html()).into_response()
}

async fn ui_login(State(state): State<AppState>) -> Response {
    if matches!(state.auth_mode, AuthMode::Local) {
        return Redirect::to("/ui").into_response();
    }
    let Some(oidc) = &state.oidc else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "OIDC is not configured").into_response();
    };

    let state_token = random_token();
    let nonce = random_token();
    let code_verifier = random_token();
    let challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(code_verifier.as_bytes()));

    oidc.auth_states.lock().await.insert(
        state_token.clone(),
        OidcAuthState {
            pkce_verifier: code_verifier,
            nonce: nonce.clone(),
            created_at: Instant::now(),
        },
    );

    let redirect_uri = format!("{}/ui/callback", oidc.cfg.redirect_base_url.trim_end_matches('/'));
    let auth_url = format!(
        "{}/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256&nonce={}",
        oidc.cfg.issuer.trim_end_matches('/'),
        encode(&oidc.cfg.client_id),
        encode(&redirect_uri),
        encode(&oidc.cfg.scopes),
                urlencoding::encode(&state_token),
        encode(&challenge),
        encode(&nonce),
    );

    Redirect::to(&auth_url).into_response()
}

async fn ui_callback(
    State(state): State<AppState>,
    Query(query): Query<OidcCallbackQuery>,
) -> Response {
    let Some(oidc) = &state.oidc else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "OIDC is not configured").into_response();
    };

    if let Some(err) = query.error {
        let detail = query.error_description.unwrap_or_default();
        return (
            StatusCode::BAD_REQUEST,
            format!("oidc error: {} {}", err, detail).trim().to_string(),
        )
            .into_response();
    }

    let Some(code) = query.code else {
        return (StatusCode::BAD_REQUEST, "missing code").into_response();
    };
    let Some(state_token) = query.state else {
        return (StatusCode::BAD_REQUEST, "missing state").into_response();
    };

    let auth_state = oidc.auth_states.lock().await.remove(&state_token);
    let Some(auth_state) = auth_state else {
        return (StatusCode::BAD_REQUEST, "invalid state").into_response();
    };
    if auth_state.created_at.elapsed() > Duration::from_secs(600) {
        return (StatusCode::BAD_REQUEST, "state expired").into_response();
    }

    let redirect_uri = format!("{}/ui/callback", oidc.cfg.redirect_base_url.trim_end_matches('/'));
    let token_url = format!("{}/oauth2/token", oidc.cfg.issuer.trim_end_matches('/'));

    let mut form: Vec<(&str, String)> = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", oidc.cfg.client_id.clone()),
        ("code_verifier", auth_state.pkce_verifier),
    ];
    if let Some(secret) = &oidc.cfg.client_secret {
        form.push(("client_secret", secret.clone()));
    }

    let resp = match oidc.http.post(token_url).form(&form).send().await {
        Ok(v) => v,
        Err(e) => return internal_error(e),
    };
    if !resp.status().is_success() {
        let status = map_status(resp.status());
        let body = resp.text().await.unwrap_or_default();
        return (status, body).into_response();
    }

    let token: OidcTokenResponse = match resp.json().await {
        Ok(v) => v,
        Err(e) => return internal_error(e),
    };

    let claims = match decode_id_token(oidc, &token.id_token).await {
        Ok(v) => v,
        Err(e) => return internal_error(e),
    };
    if claims.nonce.as_deref() != Some(auth_state.nonce.as_str()) {
        return (StatusCode::BAD_REQUEST, "invalid nonce").into_response();
    }

    let roles = claims.groups.map(groups_to_vec).unwrap_or_default();
    let is_admin = roles.iter().any(|r| r == &oidc.cfg.admin_role);
    let is_scoped = roles.iter().any(|r| r == &oidc.cfg.scoped_role);
    if !is_admin && !is_scoped {
        return (StatusCode::FORBIDDEN, "role not allowed").into_response();
    }

    let sid = random_token();
    oidc.sessions.lock().await.insert(
        sid.clone(),
        OidcSession {
            subject: claims.sub.unwrap_or_else(|| "unknown".to_string()),
            roles,
            access_token: token.access_token,
            expires_at: Instant::now()
                + Duration::from_secs(token.expires_in.unwrap_or(3600).max(300) as u64),
        },
    );

    let mut headers = set_session_cookie(&sid, oidc.cfg.cookie_secure);
    headers.insert(axum::http::header::LOCATION, "/ui".parse().unwrap());
    (StatusCode::FOUND, headers, "").into_response()
}

async fn decode_id_token(oidc: &OidcState, token: &str) -> Result<Claims> {
    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| anyhow!("missing kid"))?;

    let key = {
        let guard = oidc.jwks.lock().await;
        guard.get(&kid).cloned()
    };

    let key = if let Some(key) = key {
        key
    } else {
        let jwks_url = format!("{}/.well-known/jwks.json", oidc.cfg.issuer.trim_end_matches('/'));
        let loaded = load_jwks(&oidc.http, &jwks_url).await?;

        let mut guard = oidc.jwks.lock().await;
        for (k, v) in loaded {
            guard.insert(k, v);
        }
        guard
            .get(&kid)
            .cloned()
            .ok_or_else(|| anyhow!("unknown kid"))?
    };

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[oidc.cfg.issuer.as_str()]);
    validation.set_audience(&[oidc.cfg.client_id.as_str()]);

    let token = decode::<Claims>(token, &key, &validation)?;
    Ok(token.claims)
}

async fn load_jwks(
    http: &reqwest::Client,
    url: &str,
) -> Result<HashMap<String, DecodingKey>> {
    let body = http.get(url).send().await?.text().await?;
    let set: JwkSet = serde_json::from_str(&body)?;
    let mut map = HashMap::new();
    for jwk in set.keys {
        if let Some(kid) = jwk.common.key_id.clone() {
            let key = DecodingKey::from_jwk(&jwk)?;
            map.insert(kid, key);
        }
    }
    Ok(map)
}

fn groups_to_vec(groups: Groups) -> Vec<String> {
    match groups {
        Groups::One(value) => vec![value],
        Groups::Many(values) => values,
    }
}

async fn ui_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(oidc) = &state.oidc
        && let Some(sid) = get_cookie(&headers, "encjson_keys_web") {
            oidc.sessions.lock().await.remove(&sid);
        }

    let mut out = HeaderMap::new();
    out.insert(
        axum::http::header::SET_COOKIE,
        "encjson_keys_web=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/"
            .parse()
            .unwrap(),
    );
    out.insert(
        axum::http::header::LOCATION,
        if matches!(state.auth_mode, AuthMode::Oidc) {
            "/ui/login"
        } else {
            "/ui"
        }
        .parse()
        .unwrap(),
    );
    (StatusCode::FOUND, out, "").into_response()
}

async fn api_me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    Json(MeResponse {
        auth_mode: match state.auth_mode {
            AuthMode::Local => "local".to_string(),
            AuthMode::Oidc => "oidc".to_string(),
        },
        subject: user.subject,
        roles: user.roles,
    })
    .into_response()
}

async fn api_events(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let token = user.access_token.clone();
    let state_clone = state.clone();
    let s = stream! {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            let pending = pending_count(&state_clone, token.as_deref()).await.unwrap_or(0);
            let payload = serde_json::json!({
                "pending_count": pending,
                "ts": chrono::Utc::now().to_rfc3339(),
            });
            yield Ok::<Event, Infallible>(Event::default().event("requests.pending_count").data(payload.to_string()));
        }
    };
    Sse::new(s)
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn api_bootstrap_import(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<BootstrapImportRequest>,
) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    if !is_admin_user(&user) {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    match proxy_json_method::<BootstrapImportRequest, BootstrapImportResponse>(
        &state,
        reqwest::Method::POST,
        "/api/v1/bootstrap/import",
        &payload,
        user.access_token.as_deref(),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn api_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    match proxy_get::<Vec<KeyItem>>(&state, "/api/v1/keys", &query, user.access_token.as_deref()).await {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn api_key_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(public_hex): Path<String>,
) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let path = format!("/api/v1/keys/{}", public_hex);
    match proxy_get::<KeyItem>(&state, &path, &HashMap::new(), user.access_token.as_deref()).await {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn api_patch_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(public_hex): Path<String>,
    Json(payload): Json<KeyPatch>,
) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let path = format!("/api/v1/keys/{}", public_hex);
    match proxy_json_method::<KeyPatch, Value>(
        &state,
        reqwest::Method::PATCH,
        &path,
        &payload,
        user.access_token.as_deref(),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn api_reencrypt(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    match proxy_json_method::<Value, ReencryptResponse>(
        &state,
        reqwest::Method::POST,
        "/api/v1/keys/reencrypt",
        &serde_json::json!({}),
        user.access_token.as_deref(),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn api_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    match proxy_get::<Vec<RequestItem>>(
        &state,
        "/api/v1/requests",
        &query,
        user.access_token.as_deref(),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn api_create_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RequestCreate>,
) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    match proxy_json_method::<RequestCreate, Value>(
        &state,
        reqwest::Method::POST,
        "/api/v1/requests",
        &payload,
        user.access_token.as_deref(),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn api_approve_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(payload): Json<RequestDecision>,
) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let path = format!("/api/v1/requests/{}/approve", id);
    match proxy_json_method::<RequestDecision, Value>(
        &state,
        reqwest::Method::POST,
        &path,
        &payload,
        user.access_token.as_deref(),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn api_reject_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(payload): Json<RequestDecision>,
) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let path = format!("/api/v1/requests/{}/reject", id);
    match proxy_json_method::<RequestDecision, Value>(
        &state,
        reqwest::Method::POST,
        &path,
        &payload,
        user.access_token.as_deref(),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn api_tenants(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    match proxy_get::<Vec<TenantItem>>(
        &state,
        "/api/v1/tenants",
        &HashMap::new(),
        user.access_token.as_deref(),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn api_create_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TenantCreate>,
) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    match proxy_json_method::<TenantCreate, Value>(
        &state,
        reqwest::Method::POST,
        "/api/v1/tenants",
        &payload,
        user.access_token.as_deref(),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn api_rename_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(payload): Json<TenantRename>,
) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let path = format!("/api/v1/tenants/{}", name);
    match proxy_json_method::<TenantRename, Value>(
        &state,
        reqwest::Method::PATCH,
        &path,
        &payload,
        user.access_token.as_deref(),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn api_delete_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let user = match ensure_user(&state, &headers, AccessKind::Api).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let path = format!("/api/v1/tenants/{}", name);
    match proxy_no_body(
        &state,
        reqwest::Method::DELETE,
        &path,
        user.access_token.as_deref(),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(resp) => resp,
    }
}

async fn ensure_user(
    state: &AppState,
    headers: &HeaderMap,
    access: AccessKind,
) -> Result<UserContext, Response> {
    match state.auth_mode {
        AuthMode::Local => Ok(UserContext {
            subject: "local-user".to_string(),
            roles: vec!["admin".to_string()],
            access_token: None,
        }),
        AuthMode::Oidc => {
            let Some(oidc) = &state.oidc else {
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "OIDC is not configured").into_response());
            };

            let Some(sid) = get_cookie(headers, "encjson_keys_web") else {
                return Err(unauthorized_response(access));
            };

            let mut sessions = oidc.sessions.lock().await;
            let Some(sess) = sessions.get(&sid).cloned() else {
                return Err(unauthorized_response(access));
            };
            if Instant::now() > sess.expires_at {
                sessions.remove(&sid);
                return Err(unauthorized_response(access));
            }

            Ok(UserContext {
                subject: sess.subject,
                roles: sess.roles,
                access_token: Some(sess.access_token),
            })
        }
    }
}

fn unauthorized_response(access: AccessKind) -> Response {
    match access {
        AccessKind::Ui => Redirect::to("/ui/login").into_response(),
        AccessKind::Api => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    }
}

fn is_admin_user(user: &UserContext) -> bool {
    user.roles
        .iter()
        .any(|r| r == "admin" || r == "encjson:role:admin")
}

async fn pending_count(state: &AppState, access_token: Option<&str>) -> Result<usize> {
    let mut query = HashMap::new();
    query.insert("status".to_string(), "pending".to_string());
    let rows: Vec<RequestItem> = proxy_get(state, "/api/v1/requests", &query, access_token)
        .await
        .map_err(|_| anyhow!("request failed"))?;
    Ok(rows.len())
}

async fn proxy_get<T: serde::de::DeserializeOwned>(
    state: &AppState,
    path: &str,
    query: &HashMap<String, String>,
    access_token: Option<&str>,
) -> Result<T, Response> {
    let mut url = format!("{}{}", state.keys_server_base, path);
    if !query.is_empty() {
        let qp = query
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        url = format!("{}?{}", url, qp);
    }

    let mut req = state.http.get(url);
    if let Some(token) = access_token {
        req = req.bearer_auth(token);
    }

    let resp = req.send().await.map_err(internal_error)?;
    handle_json_response(resp).await
}

async fn proxy_json_method<B: Serialize, T: serde::de::DeserializeOwned>(
    state: &AppState,
    method: reqwest::Method,
    path: &str,
    body: &B,
    access_token: Option<&str>,
) -> Result<T, Response> {
    let url = format!("{}{}", state.keys_server_base, path);
    let mut req = state.http.request(method, url).json(body);
    if let Some(token) = access_token {
        req = req.bearer_auth(token);
    }

    let resp = req.send().await.map_err(internal_error)?;
    handle_json_response(resp).await
}

async fn proxy_no_body(
    state: &AppState,
    method: reqwest::Method,
    path: &str,
    access_token: Option<&str>,
) -> Result<Value, Response> {
    let url = format!("{}{}", state.keys_server_base, path);
    let mut req = state.http.request(method, url);
    if let Some(token) = access_token {
        req = req.bearer_auth(token);
    }

    let resp = req.send().await.map_err(internal_error)?;
    handle_json_response(resp).await
}

async fn handle_json_response<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, Response> {
    let status = map_status(resp.status());
    let body = resp.text().await.map_err(internal_error)?;
    if !status.is_success() {
        return Err((status, body).into_response());
    }
    serde_json::from_str::<T>(&body)
        .with_context(|| format!("invalid upstream json body: {}", body))
        .map_err(internal_error)
}

fn map_status(status: reqwest::StatusCode) -> StatusCode {
    StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY)
}

fn internal_error<E: std::fmt::Display>(e: E) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
}

fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let mut it = part.trim().splitn(2, '=');
        let key = it.next()?.trim();
        let value = it.next()?.trim();
        if key == name {
            return Some(value.to_string());
        }
    }
    None
}

fn set_session_cookie(value: &str, secure: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let mut cookie = format!("encjson_keys_web={value}; HttpOnly; SameSite=Lax; Path=/");
    if secure {
        cookie.push_str("; Secure");
    }
    headers.insert(axum::http::header::SET_COOKIE, cookie.parse().unwrap());
    headers
}

fn random_token() -> String {
    let mut buf = [0u8; 32];
    let mut rng = rand::rng();
    rng.fill(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .status()
            .context("failed to execute open")?;
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
            .context("failed to execute start")?;
        return Ok(());
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .status()
            .context("failed to execute xdg-open")?;
        return Ok(());
    }
    #[allow(unreachable_code)]
    Err(anyhow!("open browser is not supported on this platform"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Form, State};
    use axum::http::header::{AUTHORIZATION, COOKIE, LOCATION, SET_COOKIE};
    use axum::response::IntoResponse;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockOidcState {
        issuer: String,
        client_id: String,
        kid: String,
        secret: String,
        nonce: Arc<tokio::sync::Mutex<String>>,
    }

    #[derive(Serialize)]
    struct TokenPayload {
        access_token: String,
        id_token: String,
        expires_in: i64,
    }

    #[derive(Serialize)]
    struct JwksPayload {
        keys: Vec<JwkPayload>,
    }

    #[derive(Serialize)]
    struct JwkPayload {
        kty: String,
        kid: String,
        alg: String,
        k: String,
        #[serde(rename = "use")]
        use_field: String,
    }

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        iss: String,
        aud: String,
        exp: usize,
        nonce: String,
        groups: Vec<String>,
    }

    async fn mock_authorize() -> impl IntoResponse {
        StatusCode::OK
    }

    async fn mock_token(
        State(state): State<MockOidcState>,
        Form(_form): Form<HashMap<String, String>>,
    ) -> Response {
        let nonce = state.nonce.lock().await.clone();
        let claims = TestClaims {
            sub: "test-user".to_string(),
            iss: state.issuer.clone(),
            aud: state.client_id.clone(),
            exp: (chrono::Utc::now().timestamp() + 3600) as usize,
            nonce,
            groups: vec!["encjson:role:admin".to_string()],
        };
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(state.kid.clone());

        let id_token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(state.secret.as_bytes()),
        )
        .unwrap();

        Json(TokenPayload {
            access_token: "mock-access-token".to_string(),
            id_token,
            expires_in: 3600,
        })
        .into_response()
    }

    async fn mock_jwks(State(state): State<MockOidcState>) -> Response {
        let jwks = JwksPayload {
            keys: vec![JwkPayload {
                kty: "oct".to_string(),
                kid: state.kid,
                alg: "HS256".to_string(),
                k: URL_SAFE_NO_PAD.encode(state.secret.as_bytes()),
                use_field: "sig".to_string(),
            }],
        };
        Json(jwks).into_response()
    }

    async fn mock_keys_requests(headers: HeaderMap) -> Response {
        let auth = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if auth != "Bearer mock-access-token" {
            return (StatusCode::UNAUTHORIZED, "missing bearer").into_response();
        }
        Json(Vec::<RequestItem>::new()).into_response()
    }

    async fn spawn_server(router: Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (addr, handle)
    }

    fn query_param(url: &str, key: &str) -> Option<String> {
        let needle = format!("{}=", key);
        let query = url.split('?').nth(1)?;
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix(&needle) {
                return Some(value.to_string());
            }
        }
        None
    }

    fn cookie_pair(set_cookie: &str) -> Option<String> {
        set_cookie.split(';').next().map(ToString::to_string)
    }

    #[tokio::test]
    async fn oidc_login_callback_creates_session_and_allows_api_proxy() {
        let oidc_nonce = Arc::new(tokio::sync::Mutex::new(String::new()));

        let oidc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let oidc_addr = oidc_listener.local_addr().unwrap();
        let issuer = format!("http://{}", oidc_addr);

        let mock_oidc_state = MockOidcState {
            issuer: issuer.clone(),
            client_id: "encjson-keys-web".to_string(),
            kid: "kid-1".to_string(),
            secret: "super-secret-oidc-key".to_string(),
            nonce: oidc_nonce.clone(),
        };

        let mock_oidc_router = Router::new()
            .route("/oauth2/authorize", get(mock_authorize))
            .route("/oauth2/token", post(mock_token))
            .route("/.well-known/jwks.json", get(mock_jwks))
            .with_state(mock_oidc_state);

        let oidc_handle = tokio::spawn(async move {
            axum::serve(oidc_listener, mock_oidc_router).await.unwrap();
        });

        let keys_router = Router::new().route("/api/v1/requests", get(mock_keys_requests));
        let (keys_addr, keys_handle) = spawn_server(keys_router).await;

        let web_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let web_addr = web_listener.local_addr().unwrap();
        let web_base = format!("http://{}", web_addr);

        let oidc_state = Arc::new(OidcState {
            cfg: OidcConfig {
                issuer: issuer.clone(),
                client_id: "encjson-keys-web".to_string(),
                client_secret: Some("client-secret".to_string()),
                redirect_base_url: web_base.clone(),
                scopes: "openid profile email groups".to_string(),
                admin_role: "encjson:role:admin".to_string(),
                scoped_role: "encjson:role:scoped".to_string(),
                cookie_secure: false,
            },
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            auth_states: tokio::sync::Mutex::new(HashMap::new()),
            sessions: tokio::sync::Mutex::new(HashMap::new()),
            jwks: tokio::sync::Mutex::new(HashMap::new()),
        });

        let app_state = AppState {
            http: reqwest::Client::new(),
            keys_server_base: format!("http://{}", keys_addr),
            auth_mode: AuthMode::Oidc,
            oidc: Some(oidc_state.clone()),
        };

        let web_router = app_router(app_state);
        let web_handle = tokio::spawn(async move {
            axum::serve(web_listener, web_router).await.unwrap();
        });

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let login_resp = client
            .get(format!("{}/ui/login", web_base))
            .send()
            .await
            .unwrap();
        assert!(login_resp.status().is_redirection());
        let location = login_resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();

        let state_token_encoded = query_param(&location, "state").expect("missing state query");
        let state_token = urlencoding::decode(&state_token_encoded).unwrap().to_string();

        let auth_states = oidc_state.auth_states.lock().await;
        let auth_state = auth_states
            .get(&state_token)
            .expect("missing auth state")
            .clone();
        drop(auth_states);

        *oidc_nonce.lock().await = auth_state.nonce.clone();

        let callback_resp = client
            .get(format!(
                "{}/ui/callback?code=test-code&state={}",
                web_base,
                urlencoding::encode(&state_token)
            ))
            .send()
            .await
            .unwrap();
        assert!(callback_resp.status().is_redirection());

        let set_cookie = callback_resp
            .headers()
            .get(SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .expect("missing set-cookie")
            .to_string();
        let cookie = cookie_pair(&set_cookie).expect("invalid set-cookie format");

        let me_resp = client
            .get(format!("{}/api/v1/ui/me", web_base))
            .header(COOKIE, cookie.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(me_resp.status(), reqwest::StatusCode::OK);

        let req_resp = client
            .get(format!("{}/api/v1/ui/requests", web_base))
            .header(COOKIE, cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(req_resp.status(), reqwest::StatusCode::OK);

        web_handle.abort();
        keys_handle.abort();
        oidc_handle.abort();
    }
}
