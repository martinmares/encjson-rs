use std::time::Duration;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;

use crate::crypto_store::{decrypt_private_hex, encrypt_private_hex, public_from_private_hex};
use crate::models::*;
use crate::state::AppState;
use crate::{
    STATUS_ACTIVE, ensure_auth, is_hex_64, is_valid_key_status, server_error, validate_v3_bundles,
};

pub(crate) async fn create_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RequestCreate>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return *resp,
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
    let requested_by = headers
        .get("x-user")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or(auth.subject.clone());

    let row = match payload {
        RequestCreate::Legacy(payload) => {
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
            let encrypted =
                match encrypt_private_hex(&state.encryption_secret, payload.private_hex.trim()) {
                    Ok(v) => v,
                    Err(_) => {
                        return (StatusCode::INTERNAL_SERVER_ERROR, "encrypt failed")
                            .into_response();
                    }
                };

            sqlx::query_as::<_, RequestRow>(
                "insert into requests (public_hex, private_hex, tenant, note, tags, requested_by, key_id, bundle_version, algorithm, public_bundle, private_bundle) \
                 values ($1, $2, $3, $4, $5, $6, null, null, null, null, null) \
                 returning id, public_hex, key_id, bundle_version, algorithm, public_bundle, tenant, note, tags, status, requested_by, \
                           requested_at, decided_by, decided_at, decision_note",
            )
            .bind(payload.public_hex)
            .bind(encrypted)
            .bind(payload.tenant)
            .bind(payload.note)
            .bind(tags)
            .bind(requested_by)
            .fetch_one(&state.db)
            .await
        }
        RequestCreate::V3(payload) => {
            let public_hex = match validate_v3_bundles(
                &payload.key_id,
                payload.version,
                &payload.algorithm,
                &payload.public_bundle,
                &payload.private_bundle,
            ) {
                Ok(v) => v,
                Err(_) => {
                    return (StatusCode::BAD_REQUEST, "invalid v3 key bundle").into_response();
                }
            };
            let tags = payload.tags.unwrap_or_default();
            let public_bundle_value = match serde_json::to_value(&payload.public_bundle) {
                Ok(v) => v,
                Err(_) => {
                    return (StatusCode::BAD_REQUEST, "invalid public_bundle").into_response();
                }
            };
            let private_bundle_json = match serde_json::to_string(&payload.private_bundle) {
                Ok(v) => v,
                Err(_) => {
                    return (StatusCode::BAD_REQUEST, "invalid private_bundle").into_response();
                }
            };
            let private_bundle_enc =
                match encrypt_private_hex(&state.encryption_secret, &private_bundle_json) {
                    Ok(v) => v,
                    Err(_) => {
                        return (StatusCode::INTERNAL_SERVER_ERROR, "encrypt failed")
                            .into_response();
                    }
                };

            sqlx::query_as::<_, RequestRow>(
                "insert into requests (public_hex, private_hex, tenant, note, tags, requested_by, key_id, bundle_version, algorithm, public_bundle, private_bundle) \
                 values ($1, null, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                 returning id, public_hex, key_id, bundle_version, algorithm, public_bundle, tenant, note, tags, status, requested_by, \
                           requested_at, decided_by, decided_at, decision_note",
            )
            .bind(public_hex)
            .bind(payload.tenant)
            .bind(payload.note)
            .bind(tags)
            .bind(requested_by)
            .bind(payload.key_id)
            .bind(payload.version as i32)
            .bind(payload.algorithm)
            .bind(public_bundle_value)
            .bind(private_bundle_enc)
            .fetch_one(&state.db)
            .await
        }
    };

    match row {
        Ok(row) => Json(row).into_response(),
        Err(err) => server_error(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct RequestListQuery {
    status: Option<String>,
}

pub(crate) async fn list_requests(
    State(state): State<AppState>,
    Query(query): Query<RequestListQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return *resp,
    };
    if !auth.is_admin {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let rows = if let Some(status) = query.status {
        sqlx::query_as::<_, RequestRow>(
            "select id, public_hex, key_id, bundle_version, algorithm, public_bundle, tenant, note, tags, status, requested_by, requested_at, \
                    decided_by, decided_at, decision_note \
             from requests where status = $1 order by requested_at desc",
        )
        .bind(status)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, RequestRow>(
            "select id, public_hex, key_id, bundle_version, algorithm, public_bundle, tenant, note, tags, status, requested_by, requested_at, \
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

pub(crate) async fn update_request(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<RequestPatch>,
) -> impl IntoResponse {
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
    let req = match sqlx::query_as::<_, RequestRow>(
        "select id, public_hex, key_id, bundle_version, algorithm, public_bundle, tenant, note, tags, status, requested_by, requested_at, \
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
         returning id, public_hex, key_id, bundle_version, algorithm, public_bundle, tenant, note, tags, status, requested_by, requested_at, \
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

pub(crate) async fn approve_request(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<RequestApprove>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return *resp,
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
        "select public_hex, private_hex, key_id, bundle_version, algorithm, public_bundle, private_bundle, tenant, note, tags from requests where id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(err) => return server_error(err),
    };
    let tenant = payload.tenant.unwrap_or(req.tenant.clone());
    let status = payload.status.unwrap_or_else(|| STATUS_ACTIVE.to_string());
    if !is_valid_key_status(&status) {
        return (StatusCode::BAD_REQUEST, "invalid status").into_response();
    }
    let note = payload.note.unwrap_or(req.note.clone());
    let tags = payload.tags.unwrap_or(req.tags.clone());

    if let Some(private_hex) = req.private_hex.clone() {
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
            "insert into keys (public_hex, private_hex, key_id, bundle_version, algorithm, public_bundle, private_bundle, tenant, status, note, tags, legacy_mode, pair_consistent, legacy_reason) \
             values ($1, $2, null, null, null, null, null, $3, $4, $5, $6, $7, $8, $9) \
             on conflict (public_hex) do update \
             set private_hex = excluded.private_hex, tenant = excluded.tenant, \
                 status = excluded.status, note = excluded.note, tags = excluded.tags, \
                 legacy_mode = excluded.legacy_mode, pair_consistent = excluded.pair_consistent, \
                 legacy_reason = excluded.legacy_reason, updated_at = now()",
        )
        .bind(&req.public_hex)
        .bind(encrypted_key)
        .bind(&tenant)
        .bind(&status)
        .bind(&note)
        .bind(&tags)
        .bind(false)
        .bind(true)
        .bind(None::<String>)
        .execute(&mut *tx)
        .await;
    } else {
        let Some(key_id) = req.key_id.clone() else {
            return (StatusCode::BAD_REQUEST, "v3 request missing key_id").into_response();
        };
        let Some(bundle_version) = req.bundle_version else {
            return (StatusCode::BAD_REQUEST, "v3 request missing version").into_response();
        };
        let Some(algorithm) = req.algorithm.clone() else {
            return (StatusCode::BAD_REQUEST, "v3 request missing algorithm").into_response();
        };
        let Some(public_bundle) = req.public_bundle.clone() else {
            return (StatusCode::BAD_REQUEST, "v3 request missing public_bundle").into_response();
        };
        let Some(private_bundle) = req.private_bundle.clone() else {
            return (StatusCode::BAD_REQUEST, "v3 request missing private_bundle").into_response();
        };

        let _ = sqlx::query(
            "insert into keys (public_hex, private_hex, key_id, bundle_version, algorithm, public_bundle, private_bundle, tenant, status, note, tags, legacy_mode, pair_consistent, legacy_reason) \
             values ($1, null, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             on conflict (public_hex) do update \
             set key_id = excluded.key_id, bundle_version = excluded.bundle_version, algorithm = excluded.algorithm, \
                 public_bundle = excluded.public_bundle, private_bundle = excluded.private_bundle, tenant = excluded.tenant, \
                 status = excluded.status, note = excluded.note, tags = excluded.tags, \
                 legacy_mode = excluded.legacy_mode, pair_consistent = excluded.pair_consistent, \
                 legacy_reason = excluded.legacy_reason, updated_at = now()",
        )
        .bind(&req.public_hex)
        .bind(&key_id)
        .bind(bundle_version)
        .bind(&algorithm)
        .bind(public_bundle)
        .bind(private_bundle)
        .bind(&tenant)
        .bind(&status)
        .bind(&note)
        .bind(&tags)
        .bind(false)
        .bind(true)
        .bind(None::<String>)
        .execute(&mut *tx)
        .await;
    }

    let updated = sqlx::query_as::<_, RequestRow>(
        "update requests set status = 'approved', tenant = $2, note = $3, tags = $4, \
         decided_by = $5, decided_at = now(), decision_note = $6 where id = $1 \
         returning id, public_hex, key_id, bundle_version, algorithm, public_bundle, tenant, note, tags, status, requested_by, requested_at, \
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

pub(crate) async fn reject_request(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<RequestReject>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return *resp,
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
         returning id, public_hex, key_id, bundle_version, algorithm, public_bundle, tenant, note, tags, status, requested_by, requested_at, \
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
