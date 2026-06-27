use std::collections::HashMap;
use std::sync::Arc;

use encjson_core::key_sources::KeySourceOptions;
use encjson_core::policy_engine::Policy;
use jsonwebtoken::DecodingKey;
use sqlx::PgPool;
use tokio::sync::Mutex;

use crate::rate_limit::{RateLimitCfg, RateLimiter};
use crate::ui_state::{UiAuthState, UiCfg, UiSession};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: PgPool,
    pub(crate) encryption_secret: String,
    pub(crate) auth_required: bool,
    pub(crate) jwt_issuer: Option<String>,
    pub(crate) jwt_audience: Option<String>,
    pub(crate) jwks: HashMap<String, DecodingKey>,
    pub(crate) rate_limit: RateLimitCfg,
    pub(crate) rate_limiter: Arc<Mutex<RateLimiter>>,
    pub(crate) ui: UiCfg,
    pub(crate) ui_states: Arc<Mutex<HashMap<String, UiAuthState>>>,
    pub(crate) ui_sessions: Arc<Mutex<HashMap<String, UiSession>>>,
    pub(crate) policy: Option<Policy>,
    pub(crate) mtls_required: bool,
    pub(crate) bootstrap: BootstrapCfg,
}

#[derive(Clone, Debug)]
pub(crate) struct BootstrapCfg {
    pub(crate) source_options: Option<KeySourceOptions>,
    pub(crate) default_status: String,
    pub(crate) default_note: String,
}

#[derive(Clone, Debug)]
pub(crate) struct MtlsCfg {
    pub(crate) cert_path: String,
    pub(crate) key_path: String,
    pub(crate) client_ca_path: String,
}

#[derive(Clone, Debug)]
pub(crate) struct MtlsSpiffeIdentity {
    pub(crate) spiffe_id: String,
}
