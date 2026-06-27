use std::collections::HashMap;
use std::sync::Arc;

use encjson_core::key_sources::KeySourceOptions;
use encjson_core::policy_engine::Policy;
use jsonwebtoken::DecodingKey;
use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::Mutex;

use crate::authz::BearerAuthzPolicy;
use crate::rate_limit::{RateLimitCfg, RateLimiter};
use crate::ui_state::{UiAuthState, UiCfg, UiSession};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: PgPool,
    pub(crate) encryption_secret: String,
    pub(crate) auth_required: bool,
    pub(crate) auth_issuers: Vec<AuthIssuer>,
    pub(crate) rate_limit: RateLimitCfg,
    pub(crate) rate_limiter: Arc<Mutex<RateLimiter>>,
    pub(crate) ui: UiCfg,
    pub(crate) ui_states: Arc<Mutex<HashMap<String, UiAuthState>>>,
    pub(crate) ui_sessions: Arc<Mutex<HashMap<String, UiSession>>>,
    pub(crate) policy: Option<Policy>,
    pub(crate) bearer_authz: Option<BearerAuthzPolicy>,
    pub(crate) mtls_required: bool,
    pub(crate) bootstrap: BootstrapCfg,
}

pub(crate) const ISSUER_SIMPLE_IDM_JWT: &str = "simple-idm-jwt";
pub(crate) const ISSUER_KUBE_SA_JWT: &str = "kube-sa-jwt";

#[derive(Clone, Debug)]
pub(crate) struct AuthIssuer {
    pub(crate) name: String,
    pub(crate) kind: AuthIssuerKind,
    pub(crate) issuer: String,
    pub(crate) audience: Option<String>,
    pub(crate) jwks: HashMap<String, DecodingKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AuthIssuerKind {
    SimpleIdmJwt,
    KubeSaJwt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Principal {
    pub(crate) auth_method: AuthMethod,
    pub(crate) issuer: String,
    pub(crate) kind: PrincipalKind,
    pub(crate) subject: Option<String>,
    pub(crate) groups: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) audience: Vec<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) namespace: Option<String>,
    pub(crate) service_account: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuthMethod {
    BearerToken,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrincipalKind {
    User,
    Service,
    Workload,
    Unknown,
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
