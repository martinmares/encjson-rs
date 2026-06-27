use std::time::Instant;

#[derive(Clone, Debug)]
pub(crate) struct UiCfg {
    pub(crate) enabled: bool,
    pub(crate) issuer: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<String>,
    pub(crate) base_url: Option<String>,
    pub(crate) cookie_secure: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct UiAuthState {
    pub(crate) code_verifier: String,
    pub(crate) nonce: String,
    pub(crate) created_at: Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct UiSession {
    pub(crate) subject: String,
    #[allow(dead_code)]
    pub(crate) groups: Vec<String>,
    pub(crate) tenants: Vec<String>,
    pub(crate) is_admin: bool,
    pub(crate) is_scoped: bool,
    pub(crate) expires_at: Instant,
}
