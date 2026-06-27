use std::net::SocketAddr;

use axum::{
    Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, patch, post},
};
use clap::Parser;
use encjson_core::key_sources::{
    ConjurConfig, KeySourceOptions, RemoteMtlsConfig, VaultConfig, require_policy_context,
};
use encjson_core::policy_engine::{Policy, Profile, validate_for_profile};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};

mod api_error;
mod args;
mod auth;
mod authz;
mod crypto_store;
mod handlers_keys;
mod handlers_requests;
mod handlers_tenants;
mod key_validation;
mod maintenance;
mod models;
mod rate_limit;
mod state;
mod ui_handlers;
mod ui_html;
mod ui_state;

use args::{Args, KeySourceCli};
use auth::{ensure_auth, ensure_auth_spiffe_policy, get_me, load_jwks, serve_mtls};
use authz::BearerAuthzPolicy;
use handlers_keys::{get_key, get_key_bundle, get_private_key, list_keys, patch_key};
use handlers_requests::{
    approve_request, create_request, list_requests, reject_request, update_request,
};
use handlers_tenants::{create_tenant, delete_tenant, list_statuses, list_tenants, rename_tenant};
use key_validation::{is_hex_64, validate_v3_bundles};
use maintenance::{bootstrap_import, bootstrap_key_from_source, reencrypt_keys};
use rate_limit::{RateLimitCfg, RateLimiter};
use state::{
    AppState, AuthIssuer, AuthIssuerKind, BootstrapCfg, ISSUER_KUBE_SA_JWT, ISSUER_SIMPLE_IDM_JWT,
    MtlsCfg,
};
use ui_handlers::{
    ui_callback, ui_index, ui_key_detail, ui_key_edit, ui_keys, ui_keys_list, ui_login, ui_logout,
    ui_reencrypt, ui_request_approve, ui_request_create, ui_request_reject, ui_requests,
    ui_requests_list, ui_tenant_add, ui_tenant_delete, ui_tenant_rename, ui_tenants,
    ui_tenants_list,
};
use ui_state::UiCfg;

pub(crate) const STATUS_ACTIVE: &str = "active";
pub(crate) const STATUS_REVOKED: &str = "revoked";

pub(crate) fn is_valid_key_status(status: &str) -> bool {
    matches!(status, STATUS_ACTIVE | STATUS_REVOKED)
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

    let auth_issuers = if auth_required {
        let issuer = jwt_issuer.as_ref().ok_or_else(|| {
            anyhow::anyhow!("ENCJSON_KEYS_JWT_ISSUER is required when auth is enabled")
        })?;
        let url = jwks_url
            .clone()
            .unwrap_or_else(|| format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/')));
        info!(
            issuer_name = ISSUER_SIMPLE_IDM_JWT,
            issuer = issuer,
            jwks_url = url,
            "loading auth issuer JWKS"
        );
        let mut issuers = vec![AuthIssuer {
            name: ISSUER_SIMPLE_IDM_JWT.to_string(),
            kind: AuthIssuerKind::SimpleIdmJwt,
            issuer: issuer.clone(),
            audience: jwt_audience,
            jwks: load_jwks(&url).await?,
        }];
        if let Some(kube_issuer) = args
            .keys_kube_sa_issuer
            .as_ref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
        {
            let kube_jwks_url = args
                .keys_kube_sa_jwks_url
                .as_ref()
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "ENCJSON_KEYS_KUBE_SA_JWKS_URL is required when kube-sa-jwt auth is enabled"
                    )
                })?;
            info!(
                issuer_name = ISSUER_KUBE_SA_JWT,
                issuer = kube_issuer,
                jwks_url = kube_jwks_url,
                "loading auth issuer JWKS"
            );
            issuers.push(AuthIssuer {
                name: ISSUER_KUBE_SA_JWT.to_string(),
                kind: AuthIssuerKind::KubeSaJwt,
                issuer: kube_issuer.to_string(),
                audience: args.keys_kube_sa_audience.clone(),
                jwks: load_jwks(kube_jwks_url).await?,
            });
        }
        issuers
    } else {
        Vec::new()
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
    let bearer_authz = match args.keys_authz_file {
        Some(path) if !path.trim().is_empty() => {
            let parsed = BearerAuthzPolicy::from_file(std::path::Path::new(&path))
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            info!("loaded bearer authz file {}", path);
            Some(parsed)
        }
        _ => None,
    };

    let state = AppState {
        db,
        encryption_secret,
        auth_required,
        auth_issuers,
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
        bearer_authz,
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

pub(crate) fn server_error(err: impl std::fmt::Display) -> axum::response::Response {
    error!("server error: {}", err);
    (StatusCode::INTERNAL_SERVER_ERROR, "server error").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::body::to_bytes;
    use axum::extract::{Path, State};
    use axum::http::HeaderMap;
    use encjson_core::crypto::{generate_key_pair, generate_v3_key_bundle};
    use encjson_core::key_sources::KeySourceKind;
    use encjson_core::recipient::PrivateBundle;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::crypto_store::decrypt_private_hex;
    use crate::models::{
        KeyBundleResponse, RequestApprove, RequestCreate, RequestCreateV3, RequestRow,
    };

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
            auth_issuers: Vec::new(),
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
            bearer_authz: None,
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
