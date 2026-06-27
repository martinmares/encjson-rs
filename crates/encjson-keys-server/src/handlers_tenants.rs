use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::api_error::{api_error, api_server_error};
use crate::models::{TenantCreate, TenantRename, TenantRow};
use crate::state::AppState;
use crate::{STATUS_ACTIVE, STATUS_REVOKED, ensure_auth};

pub(crate) async fn list_tenants(
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
    let rows =
        sqlx::query_as::<_, TenantRow>("select id, name, created_at from tenants order by name")
            .fetch_all(&state.db)
            .await;
    match rows {
        Ok(rows) => Json(rows).into_response(),
        Err(err) => api_server_error(err),
    }
}

pub(crate) async fn create_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TenantCreate>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return *resp,
    };
    if !auth.is_admin {
        return api_error(StatusCode::FORBIDDEN, "admin required");
    }
    let name = payload.name.trim();
    if name.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "name required");
    }
    let row = sqlx::query_as::<_, TenantRow>(
        "insert into tenants (name) values ($1) returning id, name, created_at",
    )
    .bind(name)
    .fetch_one(&state.db)
    .await;
    match row {
        Ok(row) => Json(row).into_response(),
        Err(err) => api_server_error(err),
    }
}

pub(crate) async fn rename_tenant(
    State(state): State<AppState>,
    Path(old_name): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<TenantRename>,
) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers) {
        Ok(auth) => auth,
        Err(resp) => return *resp,
    };
    if !auth.is_admin {
        return api_error(StatusCode::FORBIDDEN, "admin required");
    }
    let new_name = payload.name.trim();
    if new_name.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "name required");
    }

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => return api_server_error(err),
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
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "tenant not found"),
        Err(err) => return api_server_error(err),
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
        return api_server_error(err);
    }
    Json(row).into_response()
}

pub(crate) async fn delete_tenant(
    State(state): State<AppState>,
    Path(name): Path<String>,
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

    let tenant = match sqlx::query_scalar::<_, i64>("select count(*) from tenants where name = $1")
        .bind(&name)
        .fetch_one(&mut *tx)
        .await
    {
        Ok(count) => count,
        Err(err) => return api_server_error(err),
    };
    if tenant == 0 {
        return api_error(StatusCode::NOT_FOUND, "tenant not found");
    }

    let keys_count =
        match sqlx::query_scalar::<_, i64>("select count(*) from keys where tenant = $1")
            .bind(&name)
            .fetch_one(&mut *tx)
            .await
        {
            Ok(count) => count,
            Err(err) => return api_server_error(err),
        };
    if keys_count > 0 {
        return api_error(StatusCode::CONFLICT, "tenant has associated keys");
    }
    let requests_count =
        match sqlx::query_scalar::<_, i64>("select count(*) from requests where tenant = $1")
            .bind(&name)
            .fetch_one(&mut *tx)
            .await
        {
            Ok(count) => count,
            Err(err) => return api_server_error(err),
        };
    if requests_count > 0 {
        return api_error(StatusCode::CONFLICT, "tenant has associated requests");
    }

    let delete = sqlx::query("delete from tenants where name = $1")
        .bind(&name)
        .execute(&mut *tx)
        .await;
    if let Err(err) = delete {
        return api_server_error(err);
    }
    if let Err(err) = tx.commit().await {
        return api_server_error(err);
    }

    StatusCode::NO_CONTENT.into_response()
}

pub(crate) async fn list_statuses(
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
    Json(vec![STATUS_ACTIVE, STATUS_REVOKED]).into_response()
}
