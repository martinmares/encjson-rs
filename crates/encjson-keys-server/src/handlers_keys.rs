use std::time::Duration;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use encjson_core::recipient::{PrivateBundle, PublicBundle};
use sqlx::{Postgres, QueryBuilder};

use crate::api_error::{api_error, api_server_error};
use crate::crypto_store::decrypt_private_hex;
use crate::models::*;
use crate::state::{AppState, MtlsSpiffeIdentity};
use crate::{ensure_auth, ensure_auth_spiffe_policy, is_valid_key_status};

pub(crate) async fn list_keys(
    State(state): State<AppState>,
    Query(query): Query<KeyQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return *resp,
    };
    let mut builder = QueryBuilder::<Postgres>::new(
        "select public_hex, key_id, bundle_version, algorithm, public_bundle, tenant, status, note, tags, legacy_mode, pair_consistent, legacy_reason, created_at, updated_at from keys",
    );
    let mut has_where = false;
    let tenant_filter = if auth.is_admin {
        query.tenant
    } else if let Some(tenant) = query.tenant {
        if !auth.tenants.contains(&tenant) {
            return api_error(StatusCode::FORBIDDEN, "tenant not allowed");
        }
        Some(tenant)
    } else {
        None
    };

    if let Some(tenant) = tenant_filter {
        builder.push(if has_where { " and " } else { " where " });
        has_where = true;
        builder.push("tenant = ").push_bind(tenant);
    } else if !auth.is_admin {
        if auth.tenants.is_empty() {
            return api_error(StatusCode::FORBIDDEN, "no tenant access");
        }
        builder.push(if has_where { " and " } else { " where " });
        has_where = true;
        builder
            .push("tenant = any(")
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
        Err(err) => return api_server_error(err),
    };
    Json(rows).into_response()
}

pub(crate) async fn get_key(
    State(state): State<AppState>,
    Path(public_hex): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return *resp,
    };
    let row = sqlx::query_as::<_, KeyRow>(
        "select public_hex, key_id, bundle_version, algorithm, public_bundle, tenant, status, note, tags, legacy_mode, pair_consistent, legacy_reason, created_at, updated_at from keys where public_hex = $1",
    )
    .bind(public_hex)
    .fetch_optional(&state.db)
    .await;
    match row {
        Ok(Some(row)) => {
            if !auth.is_admin && !auth.tenants.contains(&row.tenant) {
                return api_error(StatusCode::FORBIDDEN, "tenant not allowed");
            }
            Json(row).into_response()
        }
        Ok(None) => api_error(StatusCode::NOT_FOUND, "not found"),
        Err(err) => api_server_error(err),
    }
}

pub(crate) async fn get_private_key(
    State(state): State<AppState>,
    Path(public_hex): Path<String>,
    headers: HeaderMap,
    mtls_spiffe: Option<axum::Extension<MtlsSpiffeIdentity>>,
) -> impl IntoResponse {
    let row = sqlx::query_as::<_, KeyPrivateRow>(
        "select public_hex, tenant, private_hex from keys where public_hex = $1",
    )
    .bind(public_hex)
    .fetch_optional(&state.db)
    .await;

    match row {
        Ok(Some(row)) => {
            let auth = if headers.contains_key(axum::http::header::AUTHORIZATION) {
                match ensure_auth(&state, &headers) {
                    Ok(auth) => auth,
                    Err(resp) => return *resp,
                }
            } else {
                let spiffe_id = mtls_spiffe.map(|x| x.0.spiffe_id);
                match ensure_auth_spiffe_policy(
                    &state,
                    &headers,
                    "keys.private.read",
                    &row.tenant,
                    spiffe_id,
                ) {
                    Ok(auth) => auth,
                    Err(resp) => return *resp,
                }
            };

            if !auth.is_admin && !auth.tenants.contains(&row.tenant) {
                return api_error(StatusCode::FORBIDDEN, "tenant not allowed");
            }

            let limiter_key = format!(
                "{}:{}",
                auth.subject.clone().unwrap_or_else(|| "anon".to_string()),
                row.public_hex
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
                return api_error(StatusCode::TOO_MANY_REQUESTS, "rate limit");
            }
            let Some(private_hex) = row.private_hex else {
                return api_error(StatusCode::NOT_FOUND, "private key not available");
            };
            let private_hex = match decrypt_private_hex(&state.encryption_secret, &private_hex) {
                Ok(v) => v,
                Err(_) => {
                    return api_error(StatusCode::INTERNAL_SERVER_ERROR, "decrypt failed");
                }
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
        Ok(None) => api_error(StatusCode::NOT_FOUND, "not found"),
        Err(err) => api_server_error(err),
    }
}

pub(crate) async fn get_key_bundle(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    mtls_spiffe: Option<axum::Extension<MtlsSpiffeIdentity>>,
) -> impl IntoResponse {
    let row = sqlx::query_as::<_, KeyBundleRow>(
        "select public_hex, key_id, bundle_version, algorithm, public_bundle, private_bundle, tenant, status, note, tags \
         from keys where key_id = $1",
    )
    .bind(key_id)
    .fetch_optional(&state.db)
    .await;

    match row {
        Ok(Some(row)) => {
            let auth = if headers.contains_key(axum::http::header::AUTHORIZATION) {
                match ensure_auth(&state, &headers) {
                    Ok(auth) => auth,
                    Err(resp) => return *resp,
                }
            } else {
                let spiffe_id = mtls_spiffe.map(|x| x.0.spiffe_id);
                match ensure_auth_spiffe_policy(
                    &state,
                    &headers,
                    "keys.private.read",
                    &row.tenant,
                    spiffe_id,
                ) {
                    Ok(auth) => auth,
                    Err(resp) => return *resp,
                }
            };

            if !auth.is_admin && !auth.tenants.contains(&row.tenant) {
                return api_error(StatusCode::FORBIDDEN, "tenant not allowed");
            }

            let Some(key_id) = row.key_id.clone() else {
                return api_error(StatusCode::BAD_REQUEST, "legacy key has no v3 bundle");
            };
            let Some(bundle_version) = row.bundle_version else {
                return api_error(StatusCode::BAD_REQUEST, "legacy key has no v3 bundle");
            };
            let Some(algorithm) = row.algorithm.clone() else {
                return api_error(StatusCode::BAD_REQUEST, "legacy key has no v3 bundle");
            };
            let Some(public_bundle_value) = row.public_bundle.clone() else {
                return api_error(StatusCode::BAD_REQUEST, "public bundle missing");
            };
            let Some(private_bundle_enc) = row.private_bundle.clone() else {
                return api_error(StatusCode::BAD_REQUEST, "private bundle missing");
            };
            let public_bundle: PublicBundle = match serde_json::from_value(public_bundle_value) {
                Ok(v) => v,
                Err(_) => {
                    return api_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid public bundle");
                }
            };
            let private_bundle_json =
                match decrypt_private_hex(&state.encryption_secret, &private_bundle_enc) {
                    Ok(v) => v,
                    Err(_) => {
                        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "decrypt failed");
                    }
                };
            let private_bundle: PrivateBundle = match serde_json::from_str(&private_bundle_json) {
                Ok(v) => v,
                Err(_) => {
                    return api_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid private bundle");
                }
            };

            Json(KeyBundleResponse {
                public_hex: row.public_hex,
                key_id,
                version: bundle_version as u32,
                algorithm,
                public_bundle,
                private_bundle,
                tenant: row.tenant,
                status: row.status,
                note: row.note,
                tags: row.tags,
            })
            .into_response()
        }
        Ok(None) => api_error(StatusCode::NOT_FOUND, "not found"),
        Err(err) => api_server_error(err),
    }
}

pub(crate) async fn patch_key(
    State(state): State<AppState>,
    Path(public_hex): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<KeyPatch>,
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
    let existing = match sqlx::query_as::<_, KeyRow>(
        "select public_hex, key_id, bundle_version, algorithm, public_bundle, tenant, status, note, tags, legacy_mode, pair_consistent, legacy_reason, created_at, updated_at from keys where public_hex = $1",
    )
    .bind(&public_hex)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "not found"),
        Err(err) => return api_server_error(err),
    };

    let tenant = payload.tenant.unwrap_or(existing.tenant);
    if let Some(ref status) = payload.status
        && !is_valid_key_status(status)
    {
        return api_error(StatusCode::BAD_REQUEST, "invalid status");
    }
    let status = payload.status.unwrap_or(existing.status);
    let note = payload.note.or(existing.note);
    let tags = payload.tags.unwrap_or(existing.tags);

    let updated = sqlx::query_as::<_, KeyRow>(
        "update keys set tenant = $2, status = $3, note = $4, tags = $5, updated_at = now() \
         where public_hex = $1 returning public_hex, key_id, bundle_version, algorithm, public_bundle, tenant, status, note, tags, legacy_mode, pair_consistent, legacy_reason, created_at, updated_at",
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
                return api_server_error(err);
            }
            Json(row).into_response()
        }
        Err(err) => api_server_error(err),
    }
}
