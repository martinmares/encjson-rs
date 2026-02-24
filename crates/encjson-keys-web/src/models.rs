use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeResponse {
    pub auth_mode: String,
    pub subject: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyItem {
    pub public_hex: String,
    pub tenant: String,
    pub status: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub legacy_mode: bool,
    #[serde(default = "default_true")]
    pub pair_consistent: bool,
    #[serde(default)]
    pub legacy_reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPatch {
    #[serde(default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantItem {
    pub id: i64,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCreate {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRename {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestItem {
    pub id: i64,
    pub public_hex: String,
    pub tenant: String,
    pub note: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub status: String,
    #[serde(default)]
    pub requested_by: Option<String>,
    pub requested_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestCreate {
    pub public_hex: String,
    pub private_hex: String,
    pub tenant: String,
    pub note: String,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestDecision {
    #[serde(default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReencryptResponse {
    pub updated: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapImportRequest {
    pub tenant: String,
    #[serde(rename = "env")]
    pub env_name: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapImportResponse {
    pub public_hex: String,
    pub tenant: String,
    pub env: String,
    pub status: String,
    pub note: String,
    #[serde(default)]
    pub tags: Vec<String>,
}
