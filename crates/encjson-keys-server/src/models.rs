use chrono::{DateTime, Utc};
use encjson_core::recipient::{PrivateBundle, PublicBundle};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(crate) struct KeyQuery {
    pub(crate) tenant: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) q: Option<String>,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub(crate) struct KeyRow {
    pub(crate) public_hex: String,
    pub(crate) key_id: Option<String>,
    pub(crate) bundle_version: Option<i32>,
    pub(crate) algorithm: Option<String>,
    pub(crate) public_bundle: Option<serde_json::Value>,
    pub(crate) tenant: String,
    pub(crate) status: String,
    pub(crate) note: Option<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) legacy_mode: bool,
    pub(crate) pair_consistent: bool,
    pub(crate) legacy_reason: Option<String>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub(crate) struct KeyPatch {
    pub(crate) tenant: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) note: Option<String>,
    pub(crate) tags: Option<Vec<String>>,
}

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct TenantRow {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub(crate) struct TenantCreate {
    pub(crate) name: String,
}

#[derive(Deserialize)]
pub(crate) struct TenantRename {
    pub(crate) name: String,
}

#[derive(Deserialize)]
pub(crate) struct RequestCreateLegacy {
    pub(crate) public_hex: String,
    pub(crate) private_hex: String,
    pub(crate) tenant: String,
    pub(crate) note: String,
    pub(crate) tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub(crate) struct RequestCreateV3 {
    pub(crate) key_id: String,
    pub(crate) version: u32,
    pub(crate) algorithm: String,
    pub(crate) public_bundle: PublicBundle,
    pub(crate) private_bundle: PrivateBundle,
    pub(crate) tenant: String,
    pub(crate) note: String,
    pub(crate) tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum RequestCreate {
    Legacy(RequestCreateLegacy),
    V3(RequestCreateV3),
}

#[derive(Deserialize)]
pub(crate) struct RequestApprove {
    pub(crate) tenant: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) note: Option<String>,
    pub(crate) tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub(crate) struct RequestReject {
    pub(crate) reason: String,
}

#[derive(Deserialize)]
pub(crate) struct RequestPatch {
    pub(crate) tenant: Option<String>,
    pub(crate) note: Option<String>,
    pub(crate) tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub(crate) struct BootstrapImportRequest {
    pub(crate) tenant: String,
    #[serde(rename = "env")]
    pub(crate) env_name: String,
    pub(crate) status: Option<String>,
    pub(crate) note: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct BootstrapImportResponse {
    pub(crate) public_hex: String,
    pub(crate) tenant: String,
    pub(crate) env: String,
    pub(crate) status: String,
    pub(crate) note: String,
    pub(crate) tags: Vec<String>,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub(crate) struct RequestRow {
    pub(crate) id: i64,
    pub(crate) public_hex: String,
    pub(crate) key_id: Option<String>,
    pub(crate) bundle_version: Option<i32>,
    pub(crate) algorithm: Option<String>,
    pub(crate) public_bundle: Option<serde_json::Value>,
    pub(crate) tenant: String,
    pub(crate) note: String,
    pub(crate) tags: Vec<String>,
    pub(crate) status: String,
    pub(crate) requested_by: Option<String>,
    pub(crate) requested_at: DateTime<Utc>,
    pub(crate) decided_by: Option<String>,
    pub(crate) decided_at: Option<DateTime<Utc>>,
    pub(crate) decision_note: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct RequestRowSecret {
    pub(crate) public_hex: String,
    pub(crate) private_hex: Option<String>,
    pub(crate) key_id: Option<String>,
    pub(crate) bundle_version: Option<i32>,
    pub(crate) algorithm: Option<String>,
    pub(crate) public_bundle: Option<serde_json::Value>,
    pub(crate) private_bundle: Option<String>,
    pub(crate) tenant: String,
    pub(crate) note: String,
    pub(crate) tags: Vec<String>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct KeyPrivateRow {
    pub(crate) public_hex: String,
    pub(crate) tenant: String,
    pub(crate) private_hex: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct KeyPrivateResponse {
    pub(crate) public_hex: String,
    pub(crate) private_hex: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct KeyBundleRow {
    pub(crate) public_hex: String,
    pub(crate) key_id: Option<String>,
    pub(crate) bundle_version: Option<i32>,
    pub(crate) algorithm: Option<String>,
    pub(crate) public_bundle: Option<serde_json::Value>,
    pub(crate) private_bundle: Option<String>,
    pub(crate) tenant: String,
    pub(crate) status: String,
    pub(crate) note: Option<String>,
    pub(crate) tags: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct KeyBundleResponse {
    pub(crate) public_hex: String,
    pub(crate) key_id: String,
    pub(crate) version: u32,
    pub(crate) algorithm: String,
    pub(crate) public_bundle: PublicBundle,
    pub(crate) private_bundle: PrivateBundle,
    pub(crate) tenant: String,
    pub(crate) status: String,
    pub(crate) note: Option<String>,
    pub(crate) tags: Vec<String>,
}
