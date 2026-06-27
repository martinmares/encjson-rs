use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use encjson_core::key_sources::{KeySourceOptions, load_from_source};
use serde::Serialize;
use sqlx::PgPool;
use tracing::info;

use crate::api_error::{api_error, api_server_error};
use crate::crypto_store::{ENC_PREFIX, encrypt_private_hex};
use crate::models::{BootstrapImportRequest, BootstrapImportResponse};
use crate::state::AppState;
use crate::{STATUS_ACTIVE, STATUS_REVOKED, ensure_auth, is_valid_key_status};

pub(crate) async fn bootstrap_key_from_source(
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

#[derive(Serialize)]
struct ReencryptResult {
    keys_updated: i64,
    requests_updated: i64,
}

pub(crate) async fn reencrypt_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return *resp,
    };
    if !auth.is_admin {
        return api_error(StatusCode::FORBIDDEN, "admin required");
    }

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => return api_server_error(err),
    };

    let rows = sqlx::query_as::<_, (String, String)>(
        "select public_hex, private_hex from keys where private_hex is not null",
    )
    .fetch_all(&mut *tx)
    .await;
    let rows = match rows {
        Ok(v) => v,
        Err(err) => return api_server_error(err),
    };

    let mut keys_updated = 0i64;
    for (public_hex, private_hex) in rows {
        if private_hex.starts_with(ENC_PREFIX) {
            continue;
        }
        let encrypted = match encrypt_private_hex(&state.encryption_secret, &private_hex) {
            Ok(v) => v,
            Err(err) => return api_server_error(err),
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
        Err(err) => return api_server_error(err),
    };

    let mut requests_updated = 0i64;
    for (id, private_hex) in rows {
        if private_hex.starts_with(ENC_PREFIX) {
            continue;
        }
        let encrypted = match encrypt_private_hex(&state.encryption_secret, &private_hex) {
            Ok(v) => v,
            Err(err) => return api_server_error(err),
        };
        let _ = sqlx::query("update requests set private_hex = $2 where id = $1")
            .bind(id)
            .bind(encrypted)
            .execute(&mut *tx)
            .await;
        requests_updated += 1;
    }

    if let Err(err) = tx.commit().await {
        return api_server_error(err);
    }

    Json(ReencryptResult {
        keys_updated,
        requests_updated,
    })
    .into_response()
}

pub(crate) async fn bootstrap_import(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<BootstrapImportRequest>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return *resp,
    };
    if !auth.is_admin {
        return api_error(StatusCode::FORBIDDEN, "admin required");
    }
    let Some(source) = state.bootstrap.source_options.as_ref() else {
        return api_error(StatusCode::BAD_REQUEST, "key source is not configured");
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
        Err(err) => return api_server_error(err),
    };
    Json(imported).into_response()
}
