use std::net::SocketAddr;
use std::{io::BufReader, sync::Arc as StdArc};

use axum::{
    Json, Router,
    extract::{Form, Path, Query, State},
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, patch, post},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use encjson_core::key_sources::{
    ConjurConfig, KeySourceOptions, RemoteMtlsConfig, VaultConfig, load_from_source,
    require_policy_context,
};
use encjson_core::policy_engine::{
    Decision, EngineInput, Policy, Profile, ResourceInput, ResourceScopedInput, evaluate,
    validate_for_profile,
};
use encjson_core::recipient::{PrivateBundle, PublicBundle, compute_key_id};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sqlx::{PgPool, Postgres, QueryBuilder};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;
use tracing::{error, info};
use urlencoding::encode;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::ParsedExtension;

mod args;
mod crypto_store;
mod handlers_keys;
mod handlers_requests;
mod handlers_tenants;
mod models;
mod rate_limit;
mod state;
mod ui_html;
mod ui_state;

use args::{Args, KeySourceCli};
use crypto_store::{
    ENC_PREFIX, decrypt_private_hex, encrypt_private_hex, public_from_private_hex, random_token,
};
use handlers_keys::{get_key, get_key_bundle, get_private_key, list_keys, patch_key};
use handlers_requests::{
    approve_request, create_request, list_requests, reject_request, update_request,
};
use handlers_tenants::{create_tenant, delete_tenant, list_statuses, list_tenants, rename_tenant};
use models::*;
use rate_limit::{RateLimitCfg, RateLimiter};
use state::{AppState, BootstrapCfg, MtlsCfg, MtlsSpiffeIdentity};
use ui_html::{get_cookie, html_escape, layout, set_cookie, tabs};
use ui_state::{UiAuthState, UiCfg, UiSession};

pub(crate) const STATUS_ACTIVE: &str = "active";
pub(crate) const STATUS_REVOKED: &str = "revoked";

pub(crate) fn is_valid_key_status(status: &str) -> bool {
    matches!(status, STATUS_ACTIVE | STATUS_REVOKED)
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

fn build_key_source_options(args: &Args) -> anyhow::Result<Option<KeySourceOptions>> {
    let Some(kind) = args.key_source.as_ref() else {
        return Ok(None);
    };

    let remote_mtls = match kind {
        KeySourceCli::RemoteMtls => Some(RemoteMtlsConfig {
            url: args
                .remote_keys_url
                .clone()
                .ok_or_else(|| anyhow::anyhow!("ENCJSON_REMOTE_KEYS_URL is required"))?,
            client_cert_path: args
                .remote_tls_cert_file
                .clone()
                .ok_or_else(|| anyhow::anyhow!("ENCJSON_REMOTE_TLS_CERT_FILE is required"))?,
            client_key_path: args
                .remote_tls_key_file
                .clone()
                .ok_or_else(|| anyhow::anyhow!("ENCJSON_REMOTE_TLS_KEY_FILE is required"))?,
            ca_cert_path: args.remote_tls_ca_file.clone(),
        }),
        _ => None,
    };

    let vault = match kind {
        KeySourceCli::Vault => Some(VaultConfig {
            addr: args
                .vault_addr
                .clone()
                .ok_or_else(|| anyhow::anyhow!("ENCJSON_VAULT_ADDR is required"))?,
            path: args
                .vault_path
                .clone()
                .ok_or_else(|| anyhow::anyhow!("ENCJSON_VAULT_PATH is required"))?,
            token: args
                .vault_token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("ENCJSON_VAULT_TOKEN is required"))?,
            public_field: args.vault_public_field.clone(),
            private_field: args.vault_private_field.clone(),
        }),
        _ => None,
    };

    let conjur =
        match kind {
            KeySourceCli::Conjur => {
                Some(ConjurConfig {
                    appliance_url: args.conjur_appliance_url.clone().ok_or_else(|| {
                        anyhow::anyhow!("ENCJSON_CONJUR_APPLIANCE_URL is required")
                    })?,
                    account: args
                        .conjur_account
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("ENCJSON_CONJUR_ACCOUNT is required"))?,
                    authn_login: args
                        .conjur_authn_login
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("ENCJSON_CONJUR_AUTHN_LOGIN is required"))?,
                    authn_api_key: args.conjur_authn_api_key.clone().ok_or_else(|| {
                        anyhow::anyhow!("ENCJSON_CONJUR_AUTHN_API_KEY is required")
                    })?,
                    public_variable_id: args.conjur_public_variable_id.clone().ok_or_else(
                        || anyhow::anyhow!("ENCJSON_CONJUR_PUBLIC_VARIABLE_ID is required"),
                    )?,
                    private_variable_id: args.conjur_private_variable_id.clone().ok_or_else(
                        || anyhow::anyhow!("ENCJSON_CONJUR_PRIVATE_VARIABLE_ID is required"),
                    )?,
                    ca_cert_path: args.conjur_ca_cert_file.clone(),
                })
            }
            _ => None,
        };

    Ok(Some(KeySourceOptions {
        kind: kind.to_core_kind(),
        keydir: std::env::var("ENCJSON_KEYDIR").ok(),
        remote_mtls,
        vault,
        conjur,
    }))
}

async fn bootstrap_key_from_source(
    db: &PgPool,
    encryption_secret: &str,
    options: &KeySourceOptions,
    tenant: &str,
    env: &str,
    status: &str,
    note: &str,
) -> anyhow::Result<BootstrapImportResponse> {
    if !is_valid_key_status(status.trim()) {
        return Err(anyhow::anyhow!(
            "status must be one of: {STATUS_ACTIVE}, {STATUS_REVOKED}"
        ));
    }
    let tenant = tenant.trim();
    let env = env.trim();
    if tenant.is_empty() {
        return Err(anyhow::anyhow!("tenant is required"));
    }
    if env.is_empty() {
        return Err(anyhow::anyhow!("env is required"));
    }

    let loaded = load_from_source(options).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let encrypted = encrypt_private_hex(encryption_secret, loaded.private_hex.trim())?;
    let env_tag = format!("env:{env}");
    let source_tag = format!("source:{}", options.kind.as_str());
    let tags = vec!["bootstrap".to_string(), source_tag, env_tag];
    let status = status.trim().to_string();
    let note = note.trim().to_string();

    let mut tx = db.begin().await?;
    sqlx::query("insert into tenants (name) values ($1) on conflict (name) do nothing")
        .bind(tenant)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "insert into keys (public_hex, private_hex, tenant, status, note, tags, legacy_mode, pair_consistent, legacy_reason) \
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         on conflict (public_hex) do update \
         set private_hex = excluded.private_hex, \
             tenant = excluded.tenant, \
             status = excluded.status, \
             note = excluded.note, \
             tags = excluded.tags, \
             legacy_mode = excluded.legacy_mode, \
             pair_consistent = excluded.pair_consistent, \
             legacy_reason = excluded.legacy_reason, \
             updated_at = now()",
    )
    .bind(loaded.public_hex.trim())
    .bind(encrypted)
    .bind(tenant)
    .bind(&status)
    .bind(&note)
    .bind(&tags)
    .bind(false)
    .bind(true)
    .bind(None::<String>)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    info!(
        "bootstrap key imported from source={} for tenant={} env={}",
        options.kind.as_str(),
        tenant,
        env
    );
    Ok(BootstrapImportResponse {
        public_hex: loaded.public_hex,
        tenant: tenant.to_string(),
        env: env.to_string(),
        status,
        note,
        tags,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    dotenvy::dotenv().ok();
    let args = Args::parse();
    if args.keys_server_scope_required {
        require_policy_context(args.tenant.as_deref(), args.env_name.as_deref())
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    }
    let encryption_secret = args
        .encryption_secret
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("ENCRYPTION_SECRET is required"))?;
    let database_url = args
        .database_url
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("DATABASE_URL is required"))?;
    let addr: SocketAddr = args
        .keys_addr
        .parse()
        .map_err(|err| anyhow::anyhow!("Invalid ENCJSON_KEYS_ADDR: {err}"))?;
    let auth_required = args
        .keys_auth
        .as_deref()
        .map(|v| v == "required")
        .unwrap_or(false);
    let jwt_issuer = args.keys_jwt_issuer.clone();
    let jwks_url = args.keys_jwks_url.clone();
    let jwt_audience = args.keys_jwt_audience.clone();
    let mtls_required = args
        .keys_mtls_mode
        .as_deref()
        .map(|v| v.eq_ignore_ascii_case("required"))
        .unwrap_or(false);
    let tls_cert_file = args.keys_tls_cert_file.clone();
    let tls_key_file = args.keys_tls_key_file.clone();
    let tls_client_ca_file = args.keys_tls_client_ca_file.clone();
    let key_source_options = build_key_source_options(&args)?;

    let db = PgPool::connect(&database_url).await?;
    sqlx::migrate!("../../migrations").run(&db).await?;

    if args.keys_bootstrap_from_source {
        let source = key_source_options.as_ref().ok_or_else(|| {
            anyhow::anyhow!("ENCJSON_KEY_SOURCE is required when bootstrap is enabled")
        })?;
        let ctx = require_policy_context(args.tenant.as_deref(), args.env_name.as_deref())
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let _ = bootstrap_key_from_source(
            &db,
            &encryption_secret,
            source,
            ctx.tenant.as_str(),
            ctx.env.as_str(),
            args.keys_bootstrap_status.as_str(),
            args.keys_bootstrap_note.as_str(),
        )
        .await?;
    }

    let jwks = if auth_required {
        let issuer = jwt_issuer.as_ref().ok_or_else(|| {
            anyhow::anyhow!("ENCJSON_KEYS_JWT_ISSUER is required when auth is enabled")
        })?;
        let url = jwks_url
            .clone()
            .unwrap_or_else(|| format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/')));
        info!("loading JWKS from {}", url);
        load_jwks(&url).await?
    } else {
        std::collections::HashMap::new()
    };

    let policy = match args.keys_policy_file {
        Some(path) if !path.trim().is_empty() => {
            let parsed = Policy::from_file(std::path::Path::new(&path))
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let violations = validate_for_profile(&parsed, Profile::EncjsonKeys);
            if !violations.is_empty() {
                let messages = violations
                    .iter()
                    .map(|v| match &v.policy_id {
                        Some(id) => format!("policy '{id}': {}", v.message),
                        None => v.message.clone(),
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(anyhow::anyhow!(
                    "policy profile validation failed for encjson-keys: {messages}"
                ));
            }
            info!("loaded policy file {}", path);
            Some(parsed)
        }
        _ => None,
    };

    let state = AppState {
        db,
        encryption_secret,
        auth_required,
        jwt_issuer,
        jwt_audience,
        jwks,
        rate_limit: RateLimitCfg {
            per_minute: args.keys_rate_limit_per_minute.unwrap_or(60),
            requests_per_minute: args.keys_requests_rate_limit_per_minute.unwrap_or(30),
        },
        rate_limiter: Arc::new(Mutex::new(RateLimiter::default())),
        ui: UiCfg {
            enabled: args.keys_ui_enabled.unwrap_or(true),
            issuer: args.keys_ui_issuer.clone(),
            client_id: args.keys_ui_client_id.clone(),
            client_secret: args.keys_ui_client_secret.clone(),
            base_url: args.keys_ui_base_url.clone(),
            cookie_secure: args.keys_ui_cookie_secure.unwrap_or(true),
        },
        ui_states: Arc::new(Mutex::new(HashMap::new())),
        ui_sessions: Arc::new(Mutex::new(HashMap::new())),
        policy,
        mtls_required,
        bootstrap: BootstrapCfg {
            source_options: key_source_options,
            default_status: args.keys_bootstrap_status.clone(),
            default_note: args.keys_bootstrap_note.clone(),
        },
    };
    let ui_enabled = state.ui.enabled;

    let mut app = Router::new()
        .route("/api/v1/keys", get(list_keys))
        .route("/api/v1/keys/{public_hex}", get(get_key).patch(patch_key))
        .route("/api/v1/keys/{public_hex}/private", get(get_private_key))
        .route("/api/v1/keys/{key_id}/bundle", get(get_key_bundle))
        .route("/api/v1/me", get(get_me))
        .route("/api/v1/tenants", get(list_tenants).post(create_tenant))
        .route(
            "/api/v1/tenants/{name}",
            patch(rename_tenant).delete(delete_tenant),
        )
        .route("/api/v1/statuses", get(list_statuses))
        .route("/api/v1/requests", get(list_requests).post(create_request))
        .route("/api/v1/requests/{id}", patch(update_request))
        .route("/api/v1/requests/{id}/approve", post(approve_request))
        .route("/api/v1/requests/{id}/reject", post(reject_request))
        .route("/api/v1/keys/reencrypt", post(reencrypt_keys))
        .route("/api/v1/bootstrap/import", post(bootstrap_import));

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

    let app = app.with_state::<()>(state.clone());
    info!("listening on {}", addr);
    if state.mtls_required {
        let cert_path = tls_cert_file.ok_or_else(|| {
            anyhow::anyhow!("ENCJSON_KEYS_TLS_CERT_FILE is required in mTLS mode")
        })?;
        let key_path = tls_key_file
            .ok_or_else(|| anyhow::anyhow!("ENCJSON_KEYS_TLS_KEY_FILE is required in mTLS mode"))?;
        let client_ca_path = tls_client_ca_file.ok_or_else(|| {
            anyhow::anyhow!("ENCJSON_KEYS_TLS_CLIENT_CA_FILE is required in mTLS mode")
        })?;
        serve_mtls(
            addr,
            app,
            MtlsCfg {
                cert_path,
                key_path,
                client_ca_path,
            },
        )
        .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    }
    Ok(())
}

#[derive(Serialize)]
struct ReencryptResult {
    keys_updated: i64,
    requests_updated: i64,
}

async fn reencrypt_keys(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return *resp,
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
        let encrypted = match encrypt_private_hex(&state.encryption_secret, &private_hex) {
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
        let encrypted = match encrypt_private_hex(&state.encryption_secret, &private_hex) {
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

async fn bootstrap_import(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<BootstrapImportRequest>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return *resp,
    };
    if !auth.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let Some(source) = state.bootstrap.source_options.as_ref() else {
        return (StatusCode::BAD_REQUEST, "key source is not configured").into_response();
    };
    let status = payload
        .status
        .as_deref()
        .unwrap_or(state.bootstrap.default_status.as_str());
    let note = payload
        .note
        .as_deref()
        .unwrap_or(state.bootstrap.default_note.as_str());

    let imported = match bootstrap_key_from_source(
        &state.db,
        &state.encryption_secret,
        source,
        payload.tenant.trim(),
        payload.env_name.trim(),
        status,
        note,
    )
    .await
    {
        Ok(v) => v,
        Err(err) => return server_error(err),
    };
    Json(imported).into_response()
}

pub(crate) fn is_hex_64(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn extract_x25519_public_hex(bundle: &PublicBundle) -> anyhow::Result<String> {
    bundle
        .components
        .iter()
        .find(|component| component.role == "kex" && component.algorithm == "x25519")
        .map(|component| component.public.clone())
        .filter(|value| is_hex_64(value))
        .ok_or_else(|| anyhow::anyhow!("public_bundle is missing x25519 public component"))
}

pub(crate) fn validate_v3_bundles(
    key_id: &str,
    version: u32,
    algorithm: &str,
    public_bundle: &PublicBundle,
    private_bundle: &PrivateBundle,
) -> anyhow::Result<String> {
    if version != 3 {
        return Err(anyhow::anyhow!("version must be 3"));
    }
    if public_bundle.version != 3 || private_bundle.version != 3 {
        return Err(anyhow::anyhow!("bundle version must be 3"));
    }
    if public_bundle.key_id != key_id || private_bundle.key_id != key_id {
        return Err(anyhow::anyhow!("bundle key_id mismatch"));
    }
    if public_bundle.algorithm != algorithm || private_bundle.algorithm != algorithm {
        return Err(anyhow::anyhow!("bundle algorithm mismatch"));
    }
    let computed = compute_key_id(public_bundle)?;
    if computed != key_id {
        return Err(anyhow::anyhow!("key_id does not match public_bundle"));
    }
    extract_x25519_public_hex(public_bundle)
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

    state.ui_states.lock().await.insert(
        state_token.clone(),
        UiAuthState {
            code_verifier,
            nonce: nonce.clone(),
            created_at: Instant::now(),
        },
    );

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
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "UI client_secret missing",
        )
            .into_response();
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

    let groups = claims.groups.map(groups_to_vec).unwrap_or_default();
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
    let expires =
        Instant::now() + Duration::from_secs(token.expires_in.unwrap_or(3600).max(300) as u64);
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
        jwks.get(&kid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown kid"))?
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

async fn ui_require(state: &AppState, headers: &HeaderMap) -> Result<UiSession, Response> {
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
        "select public_hex, tenant, status, note, tags, legacy_mode, pair_consistent, legacy_reason, created_at, updated_at from keys",
    );
    if !sess.is_admin {
        if sess.tenants.is_empty() {
            return (StatusCode::FORBIDDEN, "no tenant access").into_response();
        }
        builder
            .push(" where tenant = any(")
            .push_bind(sess.tenants.clone())
            .push(")");
    }
    builder.push(" order by created_at desc");
    let query = builder.build_query_as::<KeyRow>();
    let list = match query.fetch_all(&state.db).await {
        Ok(v) => v,
        Err(err) => return server_error(err),
    };
    for k in list {
        let tags = if k.tags.is_empty() {
            "-".to_string()
        } else {
            k.tags.join(", ")
        };
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
        "select public_hex, tenant, status, note, tags, legacy_mode, pair_consistent, legacy_reason, created_at, updated_at from keys where public_hex = $1",
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
    let encrypted = match encrypt_private_hex(&state.encryption_secret, form.private_hex.trim()) {
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

async fn ui_requests_list(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
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
        let tags = if r.tags.is_empty() {
            "-".to_string()
        } else {
            r.tags.join(", ")
        };
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
    let decrypted = match decrypt_private_hex(&state.encryption_secret, private_hex.trim()) {
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
    let encrypted_key = match encrypt_private_hex(&state.encryption_secret, decrypted.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "encrypt failed").into_response(),
    };
    let _ = sqlx::query(
        "insert into keys (public_hex, private_hex, tenant, status, note, tags, legacy_mode, pair_consistent, legacy_reason) \
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         on conflict (public_hex) do update \
         set private_hex = excluded.private_hex, tenant = excluded.tenant, \
             status = excluded.status, note = excluded.note, tags = excluded.tags, \
             legacy_mode = excluded.legacy_mode, pair_consistent = excluded.pair_consistent, \
             legacy_reason = excluded.legacy_reason, updated_at = now()",
    )
    .bind(&req.public_hex)
    .bind(encrypted_key)
    .bind(&req.tenant)
    .bind(STATUS_ACTIVE)
    .bind(&req.note)
    .bind(&req.tags)
    .bind(false)
    .bind(true)
    .bind(None::<String>)
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

async fn ui_tenants_list(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let sess = match ui_require(&state, &headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !sess.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let rows =
        sqlx::query_as::<_, TenantRow>("select id, name, created_at from tenants order by name")
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
pub(crate) struct AuthContext {
    pub(crate) is_admin: bool,
    pub(crate) is_scoped: bool,
    pub(crate) tenants: Vec<String>,
    pub(crate) subject: Option<String>,
    pub(crate) groups: Vec<String>,
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

async fn serve_mtls(addr: SocketAddr, app: Router, cfg: MtlsCfg) -> anyhow::Result<()> {
    let tls_cfg = build_tls_server_config(&cfg)?;
    let acceptor = TlsAcceptor::from(StdArc::new(tls_cfg));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    loop {
        let (tcp, _peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(err) => {
                    error!("tls handshake failed: {}", err);
                    return;
                }
            };
            let spiffe_ids = extract_spiffe_ids(&tls_stream);
            let io = TokioIo::new(tls_stream);
            let svc = service_fn(move |mut req: Request<hyper::body::Incoming>| {
                let app = app.clone();
                let spiffe_ids = spiffe_ids.clone();
                async move {
                    if let Some(spiffe) = spiffe_ids.first() {
                        req.extensions_mut().insert(MtlsSpiffeIdentity {
                            spiffe_id: spiffe.clone(),
                        });
                    }
                    let mut app = app;
                    app.call(req).await
                }
            });
            if let Err(err) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, svc)
                .await
            {
                error!("mtls connection error: {}", err);
            }
        });
    }
}

fn build_tls_server_config(cfg: &MtlsCfg) -> anyhow::Result<rustls::ServerConfig> {
    let certs = load_certs(&cfg.cert_path)?;
    let key = load_private_key(&cfg.key_path)?;
    let ca_certs = load_certs(&cfg.client_ca_path)?;
    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert)?;
    }
    let verifier = WebPkiClientVerifier::builder(StdArc::new(roots)).build()?;
    let server_cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    Ok(server_cfg)
}

fn load_certs(path: &str) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open cert file {}: {}", path, e))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to read certs from {}: {}", path, e))?;
    if certs.is_empty() {
        return Err(anyhow::anyhow!("no certificates found in {}", path));
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open key file {}: {}", path, e))?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| anyhow::anyhow!("failed to read private key from {}: {}", path, e))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path))?;
    Ok(key)
}

fn extract_spiffe_ids(
    stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Vec<String> {
    let (_, conn) = stream.get_ref();
    let Some(peer_certs) = conn.peer_certificates() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for cert in peer_certs {
        let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert.as_ref()) else {
            continue;
        };
        for ext in parsed.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in &san.general_names {
                    if let GeneralName::URI(uri) = name
                        && uri.starts_with("spiffe://")
                    {
                        out.push(uri.to_string());
                    }
                }
            }
        }
    }
    out
}

pub(crate) fn ensure_auth_spiffe_policy(
    state: &AppState,
    headers: &HeaderMap,
    action: &str,
    tenant: &str,
    spiffe_identity: Option<String>,
) -> Result<AuthContext, Box<Response>> {
    if !state.mtls_required {
        return Err(Box::new(
            (StatusCode::UNAUTHORIZED, "missing authorization").into_response(),
        ));
    }
    let Some(spiffe_id) = spiffe_identity else {
        return Err(Box::new(
            (
                StatusCode::UNAUTHORIZED,
                "missing SPIFFE identity from mTLS certificate",
            )
                .into_response(),
        ));
    };
    if !spiffe_id.starts_with("spiffe://") {
        return Err(Box::new(
            (StatusCode::UNAUTHORIZED, "invalid SPIFFE identity").into_response(),
        ));
    }
    let env = header_string(headers, "x-encjson-env");
    let Some(policy) = state.policy.as_ref() else {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "policy file not configured").into_response(),
        ));
    };

    let decision = evaluate(
        policy,
        &EngineInput {
            principal_spiffe_id: &spiffe_id,
            action,
            resource: ResourceInput::Scoped(ResourceScopedInput {
                tenant: Some(tenant),
                env: env.as_deref(),
                app: None,
                service: None,
                public_key: None,
            }),
        },
    );
    if !matches!(decision, Decision::Allow) {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "spiffe policy denied").into_response(),
        ));
    }

    Ok(AuthContext {
        is_admin: false,
        is_scoped: true,
        tenants: vec![tenant.to_string()],
        subject: Some(spiffe_id),
        groups: vec!["spiffe".to_string()],
    })
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub(crate) fn ensure_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthContext, Box<Response>> {
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
        return Err(Box::new(
            (StatusCode::UNAUTHORIZED, "missing authorization").into_response(),
        ));
    };
    let Ok(auth) = value.to_str() else {
        return Err(Box::new(
            (StatusCode::UNAUTHORIZED, "invalid authorization").into_response(),
        ));
    };
    if !auth.starts_with("Bearer ") {
        return Err(Box::new(
            (StatusCode::UNAUTHORIZED, "invalid authorization").into_response(),
        ));
    }
    let auth = auth.strip_prefix("Bearer ").unwrap_or(auth);
    let header = match decode_header(auth) {
        Ok(header) => header,
        Err(_) => {
            return Err(Box::new(
                (StatusCode::UNAUTHORIZED, "invalid token").into_response(),
            ));
        }
    };
    let kid = header
        .kid
        .ok_or_else(|| Box::new((StatusCode::UNAUTHORIZED, "missing kid").into_response()))?;
    let key = state
        .jwks
        .get(&kid)
        .ok_or_else(|| Box::new((StatusCode::UNAUTHORIZED, "unknown kid").into_response()))?;
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
        .map_err(|_| Box::new((StatusCode::UNAUTHORIZED, "token invalid").into_response()))?;
    let groups = token.claims.groups.map(groups_to_vec).unwrap_or_default();
    let is_admin = groups.iter().any(|g| g == "encjson:role:admin");
    let is_scoped = groups.iter().any(|g| g == "encjson:role:scoped");
    if !is_admin && !is_scoped {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "role not allowed").into_response(),
        ));
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
        Err(resp) => return *resp,
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

pub(crate) fn server_error(err: impl std::fmt::Display) -> axum::response::Response {
    error!("server error: {}", err);
    (StatusCode::INTERNAL_SERVER_ERROR, "server error").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use encjson_core::crypto::{generate_key_pair, generate_v3_key_bundle};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_suffix() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{}-{nanos}", std::process::id())
    }

    fn test_app_state(db: PgPool, encryption_secret: &str) -> AppState {
        AppState {
            db,
            encryption_secret: encryption_secret.to_string(),
            auth_required: false,
            jwt_issuer: None,
            jwt_audience: None,
            jwks: HashMap::new(),
            rate_limit: RateLimitCfg {
                per_minute: 1000,
                requests_per_minute: 1000,
            },
            rate_limiter: Arc::new(Mutex::new(RateLimiter::default())),
            ui: UiCfg {
                enabled: false,
                issuer: None,
                client_id: None,
                client_secret: None,
                base_url: None,
                cookie_secure: false,
            },
            ui_states: Arc::new(Mutex::new(HashMap::new())),
            ui_sessions: Arc::new(Mutex::new(HashMap::new())),
            policy: None,
            mtls_required: false,
            bootstrap: BootstrapCfg {
                source_options: None,
                default_status: STATUS_ACTIVE.to_string(),
                default_note: "bootstrap".to_string(),
            },
        }
    }

    #[test]
    fn validate_v3_bundles_accepts_consistent_bundle() {
        let bundle = generate_v3_key_bundle().unwrap();
        let recipient = bundle.to_recipient_key();
        let public_bundle = recipient.to_public_bundle();
        let private_bundle = PrivateBundle {
            version: bundle.version,
            key_id: bundle.key_id.clone(),
            algorithm: bundle.algorithm.clone(),
            components: vec![
                encjson_core::recipient::KeyComponentPrivate {
                    role: "kex".to_string(),
                    algorithm: "x25519".to_string(),
                    encoding: "hex".to_string(),
                    private: bundle.x25519.private_hex.clone(),
                },
                encjson_core::recipient::KeyComponentPrivate {
                    role: "kex".to_string(),
                    algorithm: "ml-kem-768".to_string(),
                    encoding: "base64".to_string(),
                    private: bundle.mlkem768.private_b64.clone(),
                },
            ],
        };

        let public_hex = validate_v3_bundles(
            &bundle.key_id,
            3,
            &bundle.algorithm,
            &public_bundle,
            &private_bundle,
        )
        .unwrap();

        assert_eq!(public_hex, bundle.x25519.public_hex);
    }

    #[test]
    fn validate_v3_bundles_rejects_wrong_key_id() {
        let bundle = generate_v3_key_bundle().unwrap();
        let recipient = bundle.to_recipient_key();
        let public_bundle = recipient.to_public_bundle();
        let private_bundle = PrivateBundle {
            version: bundle.version,
            key_id: bundle.key_id.clone(),
            algorithm: bundle.algorithm.clone(),
            components: vec![],
        };

        let err = validate_v3_bundles(
            "deadbeef",
            3,
            &bundle.algorithm,
            &public_bundle,
            &private_bundle,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("bundle key_id mismatch")
                || err.to_string().contains("key_id does not match")
        );
    }

    #[tokio::test]
    async fn bootstrap_import_from_dir_persists_encrypted_key() -> anyhow::Result<()> {
        let Some(database_url) = std::env::var("DATABASE_URL").ok() else {
            eprintln!("skip bootstrap integration test: DATABASE_URL is not set");
            return Ok(());
        };

        let db = PgPool::connect(&database_url).await?;
        sqlx::migrate!("../../migrations").run(&db).await?;

        let unique = unique_suffix();
        let tenant = format!("bootstrap-test-{unique}");
        let env_name = "test";
        let note = "bootstrap integration test";
        let keydir = std::env::temp_dir().join(format!("encjson-bootstrap-{unique}"));
        fs::create_dir_all(&keydir)?;
        let (private_hex, public_hex) = generate_key_pair();
        fs::write(keydir.join("public.key"), format!("{public_hex}\n"))?;
        fs::write(keydir.join("private.key"), format!("{private_hex}\n"))?;

        let options = KeySourceOptions {
            kind: KeySourceKind::Dir,
            keydir: Some(keydir.display().to_string()),
            remote_mtls: None,
            vault: None,
            conjur: None,
        };

        let encryption_secret = "bootstrap-integration-secret";
        let imported = bootstrap_key_from_source(
            &db,
            encryption_secret,
            &options,
            &tenant,
            env_name,
            STATUS_ACTIVE,
            note,
        )
        .await?;

        assert_eq!(imported.public_hex, public_hex);
        assert_eq!(imported.tenant, tenant);
        assert_eq!(imported.env, env_name);
        assert_eq!(imported.status, STATUS_ACTIVE);

        let row = sqlx::query_as::<_, (String, String, String, Vec<String>)>(
            "select public_hex, private_hex, tenant, tags from keys where public_hex = $1",
        )
        .bind(&public_hex)
        .fetch_one(&db)
        .await?;

        assert_eq!(row.0, public_hex);
        assert_eq!(row.2, tenant);
        assert!(row.3.iter().any(|t| t == "bootstrap"));
        assert!(row.3.iter().any(|t| t == "source:dir"));
        assert!(row.3.iter().any(|t| t == "env:test"));

        let decrypted = decrypt_private_hex(encryption_secret, &row.1)?;
        assert_eq!(decrypted, private_hex);

        let _ = sqlx::query("delete from keys where public_hex = $1")
            .bind(&public_hex)
            .execute(&db)
            .await;
        let _ = sqlx::query("delete from tenants where name = $1")
            .bind(&tenant)
            .execute(&db)
            .await;
        let _ = fs::remove_dir_all(&keydir);
        Ok(())
    }

    #[tokio::test]
    async fn v3_request_approve_and_bundle_fetch_roundtrip() -> anyhow::Result<()> {
        let Some(database_url) = std::env::var("DATABASE_URL").ok() else {
            eprintln!("skip v3 request integration test: DATABASE_URL is not set");
            return Ok(());
        };

        let db = PgPool::connect(&database_url).await?;
        sqlx::migrate!("../../migrations").run(&db).await?;

        let unique = unique_suffix();
        let encryption_secret = format!("v3-request-secret-{unique}");
        let state = test_app_state(db.clone(), &encryption_secret);

        let bundle = generate_v3_key_bundle()?;
        let recipient = bundle.to_recipient_key();
        let public_bundle = recipient.to_public_bundle();
        let private_bundle = PrivateBundle {
            version: bundle.version,
            key_id: bundle.key_id.clone(),
            algorithm: bundle.algorithm.clone(),
            components: vec![
                encjson_core::recipient::KeyComponentPrivate {
                    role: "kex".to_string(),
                    algorithm: "x25519".to_string(),
                    encoding: "hex".to_string(),
                    private: bundle.x25519.private_hex.clone(),
                },
                encjson_core::recipient::KeyComponentPrivate {
                    role: "kex".to_string(),
                    algorithm: "ml-kem-768".to_string(),
                    encoding: "base64".to_string(),
                    private: bundle.mlkem768.private_b64.clone(),
                },
            ],
        };
        let tenant = format!("tenant-{unique}");
        let note = format!("note-{unique}");
        let tags = vec!["smoke".to_string(), unique.clone()];

        let create_response = create_request(
            State(state.clone()),
            HeaderMap::new(),
            Json(RequestCreate::V3(RequestCreateV3 {
                key_id: bundle.key_id.clone(),
                version: bundle.version,
                algorithm: bundle.algorithm.clone(),
                public_bundle: public_bundle.clone(),
                private_bundle: private_bundle.clone(),
                tenant: tenant.clone(),
                note: note.clone(),
                tags: Some(tags.clone()),
            })),
        )
        .await
        .into_response();
        assert_eq!(create_response.status(), StatusCode::OK);
        let create_body = to_bytes(create_response.into_body(), usize::MAX).await?;
        let created: RequestRow = serde_json::from_slice(&create_body)?;
        assert_eq!(created.key_id.as_deref(), Some(bundle.key_id.as_str()));
        assert_eq!(created.bundle_version, Some(3));
        assert_eq!(
            created.algorithm.as_deref(),
            Some(bundle.algorithm.as_str())
        );
        assert_eq!(created.tenant, tenant);
        assert_eq!(created.tags, tags);

        let approve_response = approve_request(
            State(state.clone()),
            Path(created.id),
            HeaderMap::new(),
            Json(RequestApprove {
                tenant: None,
                status: Some(STATUS_ACTIVE.to_string()),
                note: Some("approved note".to_string()),
                tags: Some(vec!["approved".to_string()]),
            }),
        )
        .await
        .into_response();
        assert_eq!(approve_response.status(), StatusCode::OK);
        let approve_body = to_bytes(approve_response.into_body(), usize::MAX).await?;
        let approved: RequestRow = serde_json::from_slice(&approve_body)?;
        assert_eq!(approved.status, "approved");
        assert_eq!(approved.key_id.as_deref(), Some(bundle.key_id.as_str()));

        let bundle_response = get_key_bundle(
            State(state.clone()),
            Path(bundle.key_id.clone()),
            HeaderMap::new(),
            None,
        )
        .await
        .into_response();
        assert_eq!(bundle_response.status(), StatusCode::OK);
        let bundle_body = to_bytes(bundle_response.into_body(), usize::MAX).await?;
        let fetched: KeyBundleResponse = serde_json::from_slice(&bundle_body)?;
        assert_eq!(fetched.key_id, bundle.key_id);
        assert_eq!(fetched.version, 3);
        assert_eq!(fetched.algorithm, bundle.algorithm);
        assert_eq!(fetched.public_hex, bundle.x25519.public_hex);
        assert_eq!(fetched.public_bundle, public_bundle);
        assert_eq!(fetched.private_bundle, private_bundle);

        let _ = sqlx::query("delete from requests where id = $1")
            .bind(created.id)
            .execute(&db)
            .await;
        let _ = sqlx::query("delete from keys where key_id = $1")
            .bind(&bundle.key_id)
            .execute(&db)
            .await;
        let _ = sqlx::query("delete from tenants where name = $1")
            .bind(&tenant)
            .execute(&db)
            .await;

        Ok(())
    }
}
