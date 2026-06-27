use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc as StdArc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
};
use encjson_core::policy_engine::{
    Decision, EngineInput, ResourceInput, ResourceScopedInput, evaluate,
};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use serde::{Deserialize, Serialize};
use tokio_rustls::TlsAcceptor;
use tower_service::Service;
use tracing::error;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::ParsedExtension;

use crate::api_error::api_error;
use crate::authz::BearerAuthzPolicy;
use crate::state::{
    AppState, AuthIssuer, AuthIssuerKind, AuthMethod, MtlsCfg, MtlsSpiffeIdentity, Principal,
    PrincipalKind,
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

pub(crate) async fn serve_mtls(addr: SocketAddr, app: Router, cfg: MtlsCfg) -> anyhow::Result<()> {
    let tls_cfg = build_tls_server_config(&cfg)?;
    let acceptor = TlsAcceptor::from(StdArc::new(tls_cfg));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    loop {
        let (tcp, _peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(err) => {
                    error!("tls handshake failed: {}", err);
                    return;
                }
            };
            let spiffe_ids = extract_spiffe_ids(&tls_stream);
            let io = TokioIo::new(tls_stream);
            let svc = service_fn(move |mut req: Request<hyper::body::Incoming>| {
                let app = app.clone();
                let spiffe_ids = spiffe_ids.clone();
                async move {
                    if let Some(spiffe) = spiffe_ids.first() {
                        req.extensions_mut().insert(MtlsSpiffeIdentity {
                            spiffe_id: spiffe.clone(),
                        });
                    }
                    let mut app = app;
                    app.call(req).await
                }
            });
            if let Err(err) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, svc)
                .await
            {
                error!("mtls connection error: {}", err);
            }
        });
    }
}

fn build_tls_server_config(cfg: &MtlsCfg) -> anyhow::Result<rustls::ServerConfig> {
    let certs = load_certs(&cfg.cert_path)?;
    let key = load_private_key(&cfg.key_path)?;
    let ca_certs = load_certs(&cfg.client_ca_path)?;
    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert)?;
    }
    let verifier = WebPkiClientVerifier::builder(StdArc::new(roots)).build()?;
    let server_cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    Ok(server_cfg)
}

fn load_certs(path: &str) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open cert file {}: {}", path, e))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to read certs from {}: {}", path, e))?;
    if certs.is_empty() {
        return Err(anyhow::anyhow!("no certificates found in {}", path));
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open key file {}: {}", path, e))?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| anyhow::anyhow!("failed to read private key from {}: {}", path, e))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path))?;
    Ok(key)
}

fn extract_spiffe_ids(
    stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Vec<String> {
    let (_, conn) = stream.get_ref();
    let Some(peer_certs) = conn.peer_certificates() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for cert in peer_certs {
        let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert.as_ref()) else {
            continue;
        };
        for ext in parsed.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in &san.general_names {
                    if let GeneralName::URI(uri) = name
                        && uri.starts_with("spiffe://")
                    {
                        out.push(uri.to_string());
                    }
                }
            }
        }
    }
    out
}

pub(crate) fn ensure_auth_spiffe_policy(
    state: &AppState,
    headers: &HeaderMap,
    action: &str,
    tenant: &str,
    spiffe_identity: Option<String>,
) -> Result<AuthContext, Box<Response>> {
    if !state.mtls_required {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "missing authorization",
        )));
    }
    let Some(spiffe_id) = spiffe_identity else {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "missing SPIFFE identity from mTLS certificate",
        )));
    };
    if !spiffe_id.starts_with("spiffe://") {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid SPIFFE identity",
        )));
    }
    let env = header_string(headers, "x-encjson-env");
    let Some(policy) = state.policy.as_ref() else {
        return Err(Box::new(api_error(
            StatusCode::FORBIDDEN,
            "policy file not configured",
        )));
    };

    let decision = evaluate(
        policy,
        &EngineInput {
            principal_spiffe_id: &spiffe_id,
            action,
            resource: ResourceInput::Scoped(ResourceScopedInput {
                tenant: Some(tenant),
                env: env.as_deref(),
                app: None,
                service: None,
                public_key: None,
            }),
        },
    );
    if !matches!(decision, Decision::Allow) {
        return Err(Box::new(api_error(
            StatusCode::FORBIDDEN,
            "spiffe policy denied",
        )));
    }

    Ok(AuthContext {
        is_admin: false,
        is_scoped: true,
        tenants: vec![tenant.to_string()],
        subject: Some(spiffe_id),
        groups: vec!["spiffe".to_string()],
        principal: Principal {
            auth_method: AuthMethod::BearerToken,
            issuer: "spiffe".to_string(),
            kind: PrincipalKind::Workload,
            subject: Some(tenant.to_string()),
            groups: vec!["spiffe".to_string()],
            scopes: Vec::new(),
            audience: Vec::new(),
            client_id: None,
            email: None,
            username: None,
            namespace: None,
            service_account: None,
        },
    })
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub(crate) fn ensure_auth(
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
        .ok_or_else(|| Box::new(api_error(StatusCode::UNAUTHORIZED, "missing kid")))?;
    let mut last_token_error = false;
    let mut unknown_kid = true;
    for issuer in &state.auth_issuers {
        let Some(key) = issuer.jwks.get(&kid) else {
            continue;
        };
        unknown_kid = false;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[issuer.issuer.as_str()]);
        if let Some(aud) = issuer.audience.as_ref() {
            validation.set_audience(&[aud.as_str()]);
        } else {
            validation.validate_aud = false;
        }
        let token = match decode::<Claims>(auth, key, &validation) {
            Ok(token) => token,
            Err(_) => {
                last_token_error = true;
                continue;
            }
        };
        return auth_context_from_claims(state.bearer_authz.as_ref(), issuer, token.claims);
    }
    if unknown_kid {
        return Err(Box::new(api_error(StatusCode::UNAUTHORIZED, "unknown kid")));
    }
    if last_token_error {
        return Err(Box::new(api_error(
            StatusCode::UNAUTHORIZED,
            "token invalid",
        )));
    }
    Err(Box::new(api_error(
        StatusCode::UNAUTHORIZED,
        "token invalid",
    )))
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
    let auth = match ensure_auth(&state, &headers) {
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

    let key = if let Some(k) = state
        .auth_issuers
        .iter()
        .find(|configured| configured.issuer == issuer)
        .and_then(|configured| configured.jwks.get(&kid))
    {
        k.clone()
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
            jwks: HashMap::new(),
        }
    }

    fn kube_issuer() -> AuthIssuer {
        AuthIssuer {
            name: ISSUER_KUBE_SA_JWT.to_string(),
            kind: AuthIssuerKind::KubeSaJwt,
            issuer: "https://kubernetes.default.svc".to_string(),
            audience: Some("key-server".to_string()),
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
