use std::fmt::Write as _;
use std::time::{Duration, Instant};

use axum::{
    extract::{Form, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::Digest;
use sqlx::{Postgres, QueryBuilder};
use urlencoding::encode;

use crate::auth::{decode_id_token, groups_to_vec};
use crate::crypto_store::{
    decrypt_private_hex, encrypt_private_hex, public_from_private_hex, random_token,
};
use crate::models::{KeyRow, RequestRow, RequestRowSecret, TenantRow};
use crate::state::AppState;
use crate::ui_html::{get_cookie, html_escape, layout, set_cookie, tabs};
use crate::ui_state::{UiAuthState, UiSession};
use crate::{STATUS_ACTIVE, is_hex_64, reencrypt_keys, server_error};

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

#[derive(Deserialize)]
pub(crate) struct UiCallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
pub(crate) struct UiKeyEditForm {
    tenant: String,
    status: String,
    note: String,
    tags: String,
}

#[derive(Deserialize)]
pub(crate) struct UiTenantForm {
    name: String,
}

#[derive(Deserialize)]
pub(crate) struct UiTenantRenameForm {
    name: String,
}

#[derive(Deserialize)]
pub(crate) struct UiRequestCreateForm {
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

pub(crate) async fn ui_index() -> impl IntoResponse {
    Redirect::to("/ui/keys")
}

pub(crate) async fn ui_login(State(state): State<AppState>) -> impl IntoResponse {
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

pub(crate) async fn ui_callback(
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

pub(crate) async fn ui_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
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

pub(crate) async fn ui_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
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

pub(crate) async fn ui_keys_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
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

pub(crate) async fn ui_key_detail(
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

pub(crate) async fn ui_key_edit(
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

pub(crate) async fn ui_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
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

pub(crate) async fn ui_request_create(
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

pub(crate) async fn ui_requests_list(
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

pub(crate) async fn ui_request_approve(
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

pub(crate) async fn ui_request_reject(
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

pub(crate) async fn ui_tenants(
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

pub(crate) async fn ui_tenants_list(
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

pub(crate) async fn ui_tenant_add(
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

pub(crate) async fn ui_tenant_rename(
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

pub(crate) async fn ui_tenant_delete(
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

pub(crate) async fn ui_reencrypt(
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
    let _ = reencrypt_keys(State(state), headers).await;
    Redirect::to("/ui/keys").into_response()
}
