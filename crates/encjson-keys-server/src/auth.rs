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

use crate::state::{AppState, MtlsCfg, MtlsSpiffeIdentity};

#[derive(Debug, Clone)]
pub(crate) struct AuthContext {
    pub(crate) is_admin: bool,
    pub(crate) is_scoped: bool,
    pub(crate) tenants: Vec<String>,
    pub(crate) subject: Option<String>,
    pub(crate) groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct Claims {
    pub(crate) sub: Option<String>,
    pub(crate) iss: Option<String>,
    pub(crate) aud: Option<serde_json::Value>,
    pub(crate) exp: usize,
    pub(crate) groups: Option<Groups>,
    pub(crate) nonce: Option<String>,
}

#[derive(Debug, Deserialize)]
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
        return Err(Box::new(
            (StatusCode::UNAUTHORIZED, "missing authorization").into_response(),
        ));
    }
    let Some(spiffe_id) = spiffe_identity else {
        return Err(Box::new(
            (
                StatusCode::UNAUTHORIZED,
                "missing SPIFFE identity from mTLS certificate",
            )
                .into_response(),
        ));
    };
    if !spiffe_id.starts_with("spiffe://") {
        return Err(Box::new(
            (StatusCode::UNAUTHORIZED, "invalid SPIFFE identity").into_response(),
        ));
    }
    let env = header_string(headers, "x-encjson-env");
    let Some(policy) = state.policy.as_ref() else {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "policy file not configured").into_response(),
        ));
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
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "spiffe policy denied").into_response(),
        ));
    }

    Ok(AuthContext {
        is_admin: false,
        is_scoped: true,
        tenants: vec![tenant.to_string()],
        subject: Some(spiffe_id),
        groups: vec!["spiffe".to_string()],
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
        return Ok(AuthContext {
            is_admin: true,
            is_scoped: true,
            tenants: Vec::new(),
            subject: None,
            groups: Vec::new(),
        });
    }
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err(Box::new(
            (StatusCode::UNAUTHORIZED, "missing authorization").into_response(),
        ));
    };
    let Ok(auth) = value.to_str() else {
        return Err(Box::new(
            (StatusCode::UNAUTHORIZED, "invalid authorization").into_response(),
        ));
    };
    if !auth.starts_with("Bearer ") {
        return Err(Box::new(
            (StatusCode::UNAUTHORIZED, "invalid authorization").into_response(),
        ));
    }
    let auth = auth.strip_prefix("Bearer ").unwrap_or(auth);
    let header = match decode_header(auth) {
        Ok(header) => header,
        Err(_) => {
            return Err(Box::new(
                (StatusCode::UNAUTHORIZED, "invalid token").into_response(),
            ));
        }
    };
    let kid = header
        .kid
        .ok_or_else(|| Box::new((StatusCode::UNAUTHORIZED, "missing kid").into_response()))?;
    let key = state
        .jwks
        .get(&kid)
        .ok_or_else(|| Box::new((StatusCode::UNAUTHORIZED, "unknown kid").into_response()))?;
    let mut validation = Validation::new(header.alg);
    if let Some(issuer) = state.jwt_issuer.as_ref() {
        validation.set_issuer(&[issuer.as_str()]);
    }
    if let Some(aud) = state.jwt_audience.as_ref() {
        validation.set_audience(&[aud.as_str()]);
    } else {
        validation.validate_aud = false;
    }
    let token = decode::<Claims>(auth, key, &validation)
        .map_err(|_| Box::new((StatusCode::UNAUTHORIZED, "token invalid").into_response()))?;
    let groups = token.claims.groups.map(groups_to_vec).unwrap_or_default();
    let is_admin = groups.iter().any(|g| g == "encjson:role:admin");
    let is_scoped = groups.iter().any(|g| g == "encjson:role:scoped");
    if !is_admin && !is_scoped {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "role not allowed").into_response(),
        ));
    }
    let tenants = groups
        .iter()
        .filter_map(|g| g.strip_prefix("encjson:tenant:").map(|v| v.to_string()))
        .collect();
    Ok(AuthContext {
        is_admin,
        is_scoped,
        tenants,
        subject: token.claims.sub,
        groups,
    })
}

#[derive(Serialize)]
struct MeResponse {
    subject: Option<String>,
    groups: Vec<String>,
    tenants: Vec<String>,
    is_admin: bool,
    is_scoped: bool,
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

pub(crate) async fn decode_id_token(
    state: &AppState,
    token: &str,
    issuer: &str,
    audience: &str,
) -> anyhow::Result<Claims> {
    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| anyhow::anyhow!("missing kid"))?;

    let key = if let Some(k) = state.jwks.get(&kid) {
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
