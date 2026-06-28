use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize};

use crate::api_error::api_error;
use crate::authz::BearerAuthzPolicy;
use crate::state::{
    AppState, AuthIssuer, AuthIssuerKind, AuthMethod, ISSUER_PROXY, Principal, PrincipalKind,
};

#[derive(Debug, Clone)]
pub(crate) struct AuthContext {
    pub(crate) is_admin: bool,
    pub(crate) is_scoped: bool,
    pub(crate) tenants: Vec<String>,
    pub(crate) subject: Option<String>,
    pub(crate) groups: Vec<String>,
    pub(crate) principal: Principal,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct Claims {
    pub(crate) sub: Option<String>,
    pub(crate) iss: Option<String>,
    pub(crate) aud: Option<serde_json::Value>,
    pub(crate) exp: usize,
    pub(crate) scope: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) preferred_username: Option<String>,
    pub(crate) groups: Option<Groups>,
    pub(crate) nonce: Option<String>,
    #[serde(rename = "kubernetes.io")]
    pub(crate) kubernetes: Option<KubernetesClaims>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct KubernetesClaims {
    pub(crate) namespace: Option<String>,
    pub(crate) serviceaccount: Option<KubernetesServiceAccountClaims>,
    pub(crate) pod: Option<KubernetesPodClaims>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct KubernetesServiceAccountClaims {
    pub(crate) name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct KubernetesPodClaims {
    pub(crate) name: Option<String>,
    pub(crate) uid: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum Groups {
    One(String),
    Many(Vec<String>),
}

pub(crate) async fn ensure_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthContext, Box<Response>> {
    if !state.auth_required {
        let principal = Principal {
            auth_method: AuthMethod::Disabled,
            issuer: "disabled".to_string(),
            kind: PrincipalKind::Unknown,
            subject: None,
            groups: Vec::new(),
            scopes: Vec::new(),
            audience: Vec::new(),
            client_id: None,
            email: None,
            username: None,
            namespace: None,
            service_account: None,
        };
        return Ok(AuthContext {
            is_admin: true,
            is_scoped: true,
            tenants: Vec::new(),
            subject: None,
            groups: Vec::new(),
            principal,
        });
    }
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        if state.trusted_proxy_headers {
            return auth_context_from_proxy_headers(state.bearer_authz.as_ref(), headers);
        }
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "missing authorization",
        )));
    };
    let Ok(auth) = value.to_str() else {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid authorization",
        )));
    };
    if !auth.starts_with("Bearer ") {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid authorization",
        )));
    }
    let auth = auth.strip_prefix("Bearer ").unwrap_or(auth);
    let header = match decode_header(auth) {
        Ok(header) => header,
        Err(_) => {
            return Err(Box::new(api_error(
                StatusCode::UNAUTHORIZED,
                "invalid token",
            )));
        }
    };
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| Box::new(api_error(StatusCode::UNAUTHORIZED, "missing kid")))?;

    match try_auth_with_issuers(state, auth, &header, kid).await {
        AuthAttempt::Allowed(ctx) => return Ok(*ctx),
        AuthAttempt::Denied(resp) => return Err(resp),
        AuthAttempt::InvalidToken => {
            return Err(Box::new(api_error(
                StatusCode::UNAUTHORIZED,
                "token invalid",
            )));
        }
        AuthAttempt::UnknownKid => {}
    }

    refresh_issuer_jwks_for_unknown_kid(state).await?;
    match try_auth_with_issuers(state, auth, &header, kid).await {
        AuthAttempt::Allowed(ctx) => Ok(*ctx),
        AuthAttempt::Denied(resp) => Err(resp),
        AuthAttempt::InvalidToken => Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "token invalid",
        ))),
        AuthAttempt::UnknownKid => {
            Err(Box::new(api_error(StatusCode::UNAUTHORIZED, "unknown kid")))
        }
    }
}

enum AuthAttempt {
    Allowed(Box<AuthContext>),
    Denied(Box<Response>),
    UnknownKid,
    InvalidToken,
}

async fn try_auth_with_issuers(
    state: &AppState,
    auth: &str,
    header: &jsonwebtoken::Header,
    kid: &str,
) -> AuthAttempt {
    let issuers = state.auth_issuers.read().await;
    let mut saw_kid = false;
    for issuer in issuers.iter() {
        let Some(key) = issuer.jwks.get(kid) else {
            continue;
        };
        saw_kid = true;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[issuer.issuer.as_str()]);
        if let Some(aud) = issuer.audience.as_ref() {
            validation.set_audience(&[aud.as_str()]);
        } else {
            validation.validate_aud = false;
        }
        let token = match decode::<Claims>(auth, key, &validation) {
            Ok(token) => token,
            Err(_) => continue,
        };
        match auth_context_from_claims(state.bearer_authz.as_ref(), issuer, token.claims) {
            Ok(ctx) => return AuthAttempt::Allowed(Box::new(ctx)),
            Err(resp) => return AuthAttempt::Denied(resp),
        }
    }
    if saw_kid {
        AuthAttempt::InvalidToken
    } else {
        AuthAttempt::UnknownKid
    }
}

async fn refresh_issuer_jwks_for_unknown_kid(state: &AppState) -> Result<(), Box<Response>> {
    let refresh_targets = {
        let issuers = state.auth_issuers.read().await;
        issuers
            .iter()
            .map(|issuer| (issuer.name.clone(), issuer.jwks_url.clone()))
            .collect::<Vec<_>>()
    };

    let mut refreshed = Vec::with_capacity(refresh_targets.len());
    for (name, jwks_url) in refresh_targets {
        if let Ok(jwks) = load_jwks(&jwks_url).await {
            refreshed.push((name, jwks));
        }
    }
    if refreshed.is_empty() {
        return Err(Box::new(api_error(StatusCode::UNAUTHORIZED, "unknown kid")));
    }

    let mut issuers = state.auth_issuers.write().await;
    for (name, jwks) in refreshed {
        if let Some(issuer) = issuers.iter_mut().find(|issuer| issuer.name == name) {
            issuer.jwks = jwks;
        }
    }
    Ok(())
}

fn auth_context_from_claims(
    policy: Option<&BearerAuthzPolicy>,
    issuer: &AuthIssuer,
    claims: Claims,
) -> Result<AuthContext, Box<Response>> {
    let groups = claims.groups.clone().map(groups_to_vec).unwrap_or_default();
    if issuer.kind == AuthIssuerKind::KubeSaJwt {
        validate_kube_service_account_claims(&claims)?;
    }
    let mut is_admin = groups.iter().any(|g| g == "encjson:role:admin");
    let mut is_scoped = groups.iter().any(|g| g == "encjson:role:scoped");
    let mut tenants = groups
        .iter()
        .filter_map(|g| g.strip_prefix("encjson:tenant:").map(|v| v.to_string()))
        .collect::<Vec<_>>();
    let subject = claims.sub.clone();
    let principal = principal_from_claims(issuer, &claims, groups.clone());

    if let Some(policy) = policy {
        let grant = policy.evaluate(&principal);
        is_admin = is_admin || grant.is_admin;
        is_scoped = is_scoped || grant.is_scoped;
        tenants.extend(grant.tenants);
        tenants.sort();
        tenants.dedup();
    }

    if !is_admin && !is_scoped {
        return Err(Box::new(api_error(
            StatusCode::FORBIDDEN,
            "role not allowed",
        )));
    }
    Ok(AuthContext {
        is_admin,
        is_scoped,
        tenants,
        subject,
        groups,
        principal,
    })
}

fn auth_context_from_proxy_headers(
    policy: Option<&BearerAuthzPolicy>,
    headers: &HeaderMap,
) -> Result<AuthContext, Box<Response>> {
    let subject = header_str(headers, "x-auth-subject")
        .or_else(|| header_str(headers, "x-auth-user"))
        .map(str::to_string);
    if subject.as_deref().unwrap_or("").trim().is_empty() {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "missing proxy identity",
        )));
    }

    let groups = header_str(headers, "x-auth-groups")
        .map(split_csv_header)
        .unwrap_or_default();
    let username = header_str(headers, "x-auth-user").map(str::to_string);
    let email = header_str(headers, "x-auth-email").map(str::to_string);

    let mut is_admin = groups.iter().any(|g| g == "encjson:role:admin");
    let mut is_scoped = groups.iter().any(|g| g == "encjson:role:scoped");
    let mut tenants = groups
        .iter()
        .filter_map(|g| g.strip_prefix("encjson:tenant:").map(str::to_string))
        .collect::<Vec<_>>();

    let principal = Principal {
        auth_method: AuthMethod::TrustedProxyHeaders,
        issuer: ISSUER_PROXY.to_string(),
        kind: PrincipalKind::User,
        subject: subject.clone(),
        groups: groups.clone(),
        scopes: Vec::new(),
        audience: Vec::new(),
        client_id: None,
        email,
        username,
        namespace: None,
        service_account: None,
    };

    if let Some(policy) = policy {
        let grant = policy.evaluate(&principal);
        is_admin = is_admin || grant.is_admin;
        is_scoped = is_scoped || grant.is_scoped;
        tenants.extend(grant.tenants);
        tenants.sort();
        tenants.dedup();
    }

    if !is_admin && !is_scoped {
        return Err(Box::new(api_error(
            StatusCode::FORBIDDEN,
            "role not allowed",
        )));
    }

    Ok(AuthContext {
        is_admin,
        is_scoped,
        tenants,
        subject,
        groups,
        principal,
    })
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn split_csv_header(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn validate_kube_service_account_claims(claims: &Claims) -> Result<(), Box<Response>> {
    let Some(subject) = claims.sub.as_deref() else {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "missing subject",
        )));
    };
    let Some(rest) = subject.strip_prefix("system:serviceaccount:") else {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid service account subject",
        )));
    };
    let mut parts = rest.split(':');
    let Some(subject_namespace) = parts.next().filter(|v| !v.is_empty()) else {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid service account subject",
        )));
    };
    let Some(subject_service_account) = parts.next().filter(|v| !v.is_empty()) else {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid service account subject",
        )));
    };
    if parts.next().is_some() {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid service account subject",
        )));
    }
    let namespace = claims
        .kubernetes
        .as_ref()
        .and_then(|k| k.namespace.as_deref())
        .ok_or_else(|| {
            Box::new(api_error(
                StatusCode::UNAUTHORIZED,
                "missing namespace claim",
            ))
        })?;
    let service_account = claims
        .kubernetes
        .as_ref()
        .and_then(|k| k.serviceaccount.as_ref())
        .and_then(|sa| sa.name.as_deref())
        .ok_or_else(|| {
            Box::new(api_error(
                StatusCode::UNAUTHORIZED,
                "missing service account claim",
            ))
        })?;
    if namespace != subject_namespace || service_account != subject_service_account {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "service account claim mismatch",
        )));
    }
    Ok(())
}

fn principal_from_claims(issuer: &AuthIssuer, claims: &Claims, groups: Vec<String>) -> Principal {
    let scopes = claims
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
        .collect();
    let audience = audience_to_vec(claims.aud.as_ref());
    let namespace = claims.kubernetes.as_ref().and_then(|k| k.namespace.clone());
    let service_account = claims
        .kubernetes
        .as_ref()
        .and_then(|k| k.serviceaccount.as_ref())
        .and_then(|sa| sa.name.clone());
    let kind = match issuer.kind {
        AuthIssuerKind::SimpleIdmJwt => {
            if claims.client_id.is_some() {
                PrincipalKind::Service
            } else {
                PrincipalKind::User
            }
        }
        AuthIssuerKind::KubeSaJwt => PrincipalKind::Workload,
    };

    Principal {
        auth_method: AuthMethod::BearerToken,
        issuer: issuer.name.clone(),
        kind,
        subject: claims.sub.clone(),
        groups,
        scopes,
        audience,
        client_id: claims.client_id.clone(),
        email: claims.email.clone(),
        username: claims.preferred_username.clone(),
        namespace,
        service_account,
    }
}

fn audience_to_vec(aud: Option<&serde_json::Value>) -> Vec<String> {
    match aud {
        Some(serde_json::Value::String(value)) => vec![value.clone()],
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

#[derive(Serialize)]
struct MeResponse {
    subject: Option<String>,
    groups: Vec<String>,
    tenants: Vec<String>,
    is_admin: bool,
    is_scoped: bool,
    principal: Principal,
}

pub(crate) async fn get_me(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let auth = match ensure_auth(&state, &headers).await {
        Ok(auth) => auth,
        Err(resp) => return *resp,
    };
    Json(MeResponse {
        subject: auth.subject,
        groups: auth.groups,
        tenants: auth.tenants,
        is_admin: auth.is_admin,
        is_scoped: auth.is_scoped,
        principal: auth.principal,
    })
    .into_response()
}

pub(crate) fn groups_to_vec(groups: Groups) -> Vec<String> {
    match groups {
        Groups::One(value) => vec![value],
        Groups::Many(values) => values,
    }
}

pub(crate) async fn load_jwks(
    url: &str,
) -> anyhow::Result<std::collections::HashMap<String, DecodingKey>> {
    let body = reqwest::get(url).await?.text().await?;
    let set: JwkSet = serde_json::from_str(&body)?;
    let mut map = std::collections::HashMap::new();
    for jwk in set.keys {
        if let Some(kid) = jwk.common.key_id.clone() {
            let key = DecodingKey::from_jwk(&jwk)?;
            map.insert(kid, key);
        }
    }
    Ok(map)
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    jwks_uri: String,
}

pub(crate) async fn discover_jwks_uri(url: &str) -> anyhow::Result<String> {
    let body = reqwest::get(url).await?.text().await?;
    parse_discovery_jwks_uri(&body)
}

fn parse_discovery_jwks_uri(body: &str) -> anyhow::Result<String> {
    let doc: OidcDiscoveryDocument = serde_json::from_str(body)?;
    let jwks_uri = doc.jwks_uri.trim();
    if jwks_uri.is_empty() {
        anyhow::bail!("OIDC discovery document has empty jwks_uri");
    }
    Ok(jwks_uri.to_string())
}

pub(crate) async fn decode_id_token(
    state: &AppState,
    token: &str,
    issuer: &str,
    audience: &str,
) -> anyhow::Result<Claims> {
    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| anyhow::anyhow!("missing kid"))?;

    let key = {
        let issuers = state.auth_issuers.read().await;
        issuers
            .iter()
            .find(|configured| configured.issuer == issuer)
            .and_then(|configured| configured.jwks.get(&kid))
            .cloned()
    };
    let key = if let Some(key) = key {
        key
    } else {
        let url = format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/'));
        let jwks = load_jwks(&url).await?;
        jwks.get(&kid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown kid"))?
    };

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    let token = decode::<Claims>(token, &key, &validation)?;
    Ok(token.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ISSUER_KUBE_SA_JWT, ISSUER_SIMPLE_IDM_JWT};
    use std::collections::HashMap;

    fn simple_issuer() -> AuthIssuer {
        AuthIssuer {
            name: ISSUER_SIMPLE_IDM_JWT.to_string(),
            kind: AuthIssuerKind::SimpleIdmJwt,
            issuer: "https://sso.example.com".to_string(),
            audience: Some("encjson-keys-server".to_string()),
            jwks_url: "https://sso.example.com/.well-known/jwks.json".to_string(),
            jwks: HashMap::new(),
        }
    }

    fn kube_issuer() -> AuthIssuer {
        AuthIssuer {
            name: ISSUER_KUBE_SA_JWT.to_string(),
            kind: AuthIssuerKind::KubeSaJwt,
            issuer: "https://kubernetes.default.svc".to_string(),
            audience: Some("key-server".to_string()),
            jwks_url: "https://kubernetes.default.svc/openid/v1/jwks".to_string(),
            jwks: HashMap::new(),
        }
    }

    #[test]
    fn simple_idm_claims_normalize_to_user_principal() {
        let claims = Claims {
            sub: Some("user-1".to_string()),
            iss: Some("https://sso.example.com".to_string()),
            aud: Some(serde_json::json!(["encjson-keys-server"])),
            exp: 123,
            scope: Some("openid keys:read".to_string()),
            client_id: None,
            email: Some("mares@example.com".to_string()),
            preferred_username: Some("mares".to_string()),
            groups: Some(Groups::Many(vec![
                "encjson:role:scoped".to_string(),
                "encjson:tenant:o2".to_string(),
            ])),
            nonce: None,
            kubernetes: None,
        };

        let ctx = auth_context_from_claims(None, &simple_issuer(), claims).unwrap();
        assert!(!ctx.is_admin);
        assert!(ctx.is_scoped);
        assert_eq!(ctx.tenants, vec!["o2"]);
        assert_eq!(ctx.principal.issuer, ISSUER_SIMPLE_IDM_JWT);
        assert_eq!(ctx.principal.kind, PrincipalKind::User);
        assert_eq!(ctx.principal.scopes, vec!["openid", "keys:read"]);
        assert_eq!(ctx.principal.username.as_deref(), Some("mares"));
    }

    #[test]
    fn kube_sa_claims_normalize_to_workload_principal() {
        let claims = Claims {
            sub: Some("system:serviceaccount:zis-test:order-api".to_string()),
            iss: Some("https://kubernetes.default.svc".to_string()),
            aud: Some(serde_json::json!("key-server")),
            exp: 123,
            scope: None,
            client_id: None,
            email: None,
            preferred_username: None,
            groups: Some(Groups::Many(vec!["encjson:role:scoped".to_string()])),
            nonce: None,
            kubernetes: Some(KubernetesClaims {
                namespace: Some("zis-test".to_string()),
                serviceaccount: Some(KubernetesServiceAccountClaims {
                    name: Some("order-api".to_string()),
                }),
                pod: Some(KubernetesPodClaims {
                    name: Some("order-api-abc".to_string()),
                    uid: Some("pod-uid".to_string()),
                }),
            }),
        };

        let ctx = auth_context_from_claims(None, &kube_issuer(), claims).unwrap();
        assert_eq!(ctx.principal.issuer, ISSUER_KUBE_SA_JWT);
        assert_eq!(ctx.principal.kind, PrincipalKind::Workload);
        assert_eq!(ctx.principal.namespace.as_deref(), Some("zis-test"));
        assert_eq!(ctx.principal.service_account.as_deref(), Some("order-api"));
    }

    #[test]
    fn kube_sa_claims_reject_subject_claim_mismatch() {
        let claims = Claims {
            sub: Some("system:serviceaccount:zis-test:order-api".to_string()),
            iss: Some("https://kubernetes.default.svc".to_string()),
            aud: Some(serde_json::json!("key-server")),
            exp: 123,
            scope: None,
            client_id: None,
            email: None,
            preferred_username: None,
            groups: Some(Groups::Many(vec!["encjson:role:scoped".to_string()])),
            nonce: None,
            kubernetes: Some(KubernetesClaims {
                namespace: Some("zis-prod".to_string()),
                serviceaccount: Some(KubernetesServiceAccountClaims {
                    name: Some("order-api".to_string()),
                }),
                pod: None,
            }),
        };

        let err = auth_context_from_claims(None, &kube_issuer(), claims).unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn kube_sa_claims_can_be_authorized_by_local_policy_without_groups() {
        let policy = BearerAuthzPolicy::from_yaml(
            r#"
authz:
  rules:
    - principal:
        issuer: kube-sa-jwt
        kind: workload
        namespace: zis-test
        service_account: order-api
      allow:
        - keys:read
      tenants:
        - o2
"#,
        )
        .unwrap();
        let claims = Claims {
            sub: Some("system:serviceaccount:zis-test:order-api".to_string()),
            iss: Some("https://kubernetes.default.svc".to_string()),
            aud: Some(serde_json::json!("key-server")),
            exp: 123,
            scope: None,
            client_id: None,
            email: None,
            preferred_username: None,
            groups: None,
            nonce: None,
            kubernetes: Some(KubernetesClaims {
                namespace: Some("zis-test".to_string()),
                serviceaccount: Some(KubernetesServiceAccountClaims {
                    name: Some("order-api".to_string()),
                }),
                pod: None,
            }),
        };

        let ctx = auth_context_from_claims(Some(&policy), &kube_issuer(), claims).unwrap();
        assert!(!ctx.is_admin);
        assert!(ctx.is_scoped);
        assert_eq!(ctx.tenants, vec!["o2"]);
        assert_eq!(ctx.groups, Vec::<String>::new());
    }

    #[test]
    fn proxy_headers_normalize_to_user_principal() {
        let mut headers = HeaderMap::new();
        headers.insert("x-auth-subject", "user-1".parse().unwrap());
        headers.insert("x-auth-user", "mares".parse().unwrap());
        headers.insert("x-auth-email", "mares@example.com".parse().unwrap());
        headers.insert(
            "x-auth-groups",
            "encjson:role:scoped, encjson:tenant:o2".parse().unwrap(),
        );

        let ctx = auth_context_from_proxy_headers(None, &headers).unwrap();
        assert!(!ctx.is_admin);
        assert!(ctx.is_scoped);
        assert_eq!(ctx.tenants, vec!["o2"]);
        assert_eq!(ctx.subject.as_deref(), Some("user-1"));
        assert_eq!(ctx.principal.auth_method, AuthMethod::TrustedProxyHeaders);
        assert_eq!(ctx.principal.issuer, ISSUER_PROXY);
        assert_eq!(ctx.principal.kind, PrincipalKind::User);
        assert_eq!(ctx.principal.username.as_deref(), Some("mares"));
        assert_eq!(ctx.principal.email.as_deref(), Some("mares@example.com"));
    }

    #[test]
    fn proxy_headers_can_be_authorized_by_local_policy() {
        let policy = BearerAuthzPolicy::from_yaml(
            r#"
authz:
  rules:
    - principal:
        issuer: proxy
        groups:
          - app:role:support
      allow:
        - keys:read
      tenants:
        - cetin
"#,
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-auth-user", "support-user".parse().unwrap());
        headers.insert("x-auth-groups", "app:role:support".parse().unwrap());

        let ctx = auth_context_from_proxy_headers(Some(&policy), &headers).unwrap();
        assert!(!ctx.is_admin);
        assert!(ctx.is_scoped);
        assert_eq!(ctx.tenants, vec!["cetin"]);
        assert_eq!(ctx.groups, vec!["app:role:support"]);
    }

    #[test]
    fn proxy_headers_without_role_are_forbidden() {
        let mut headers = HeaderMap::new();
        headers.insert("x-auth-user", "viewer".parse().unwrap());

        let err = auth_context_from_proxy_headers(None, &headers).unwrap_err();
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn discovery_document_parses_jwks_uri() {
        let uri = parse_discovery_jwks_uri(
            r#"{
              "issuer": "https://kubernetes.default.svc",
              "jwks_uri": "https://kubernetes.default.svc/openid/v1/jwks"
            }"#,
        )
        .unwrap();
        assert_eq!(uri, "https://kubernetes.default.svc/openid/v1/jwks");
    }

    #[test]
    fn discovery_document_rejects_empty_jwks_uri() {
        let err = parse_discovery_jwks_uri(r#"{"jwks_uri": ""}"#).unwrap_err();
        assert!(err.to_string().contains("empty jwks_uri"));
    }
}
