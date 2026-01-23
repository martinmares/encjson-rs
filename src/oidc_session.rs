use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Duration, Utc};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreProviderMetadata},
    reqwest::async_http_client,
    AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use base64::Engine as _;
use openidconnect::TokenResponse as OidcTokenResponseTrait;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tokio::sync::oneshot;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub base_url: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub user_groups: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionsConfig {
    pub active: String,
    pub servers: HashMap<String, Session>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: String,
}

pub fn sessions_file_path(app_name: &str) -> Result<PathBuf> {
    let dir = dirs::config_dir().ok_or_else(|| anyhow!("Could not determine config directory"))?;
    Ok(dir.join(app_name).join("sessions.json"))
}

pub fn load_sessions(app_name: &str) -> Result<SessionsConfig> {
    let path = sessions_file_path(app_name)?;
    if !path.exists() {
        return Ok(SessionsConfig {
            active: "default".to_string(),
            servers: HashMap::new(),
        });
    }
    let content = fs::read_to_string(&path)?;
    let config = serde_json::from_str(&content)?;
    Ok(config)
}

pub fn save_sessions(app_name: &str, config: &SessionsConfig) -> Result<()> {
    let path = sessions_file_path(app_name)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(config)?;
    fs::write(&path, content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

pub fn save_session(app_name: &str, server_name: &str, session: Session) -> Result<()> {
    let mut config = load_sessions(app_name)?;
    config.servers.insert(server_name.to_string(), session);
    config.active = server_name.to_string();
    save_sessions(app_name, &config)
}

pub fn delete_session(app_name: &str, server_name: Option<&str>) -> Result<()> {
    let mut config = load_sessions(app_name)?;
    if let Some(name) = server_name {
        config.servers.remove(name);
        if config.active == name && !config.servers.is_empty() {
            config.active = config.servers.keys().next().unwrap().clone();
        }
    } else {
        config.servers.clear();
    }
    save_sessions(app_name, &config)
}

pub fn is_session_valid(session: &Session) -> bool {
    session.expires_at > Utc::now() + Duration::seconds(60)
}

#[allow(dead_code)]
pub async fn ensure_valid_session(app_name: &str) -> Result<(Session, String)> {
    let config = load_sessions(app_name)?;
    let server_name = config.active.clone();
    let mut session = config
        .servers
        .get(&server_name)
        .cloned()
        .ok_or_else(|| anyhow!("Not logged in. Run '{app_name} login --url <SERVER_URL>' first."))?;

    if !is_session_valid(&session) || (session.expires_at - Utc::now()).num_seconds() < 300 {
        session = refresh_session_async(session).await?;
        save_session(app_name, &server_name, session.clone())?;
    }

    Ok((session, server_name))
}

pub async fn handle_login(
    app_name: &str,
    base_url: &str,
    client_id: &str,
    port: u16,
    server_name: &str,
    insecure: bool,
) -> Result<()> {
    let provider_metadata = discover_provider(base_url, insecure)
        .await
        .context("Failed to discover OIDC provider metadata")?;

    let redirect_uri = format!("http://localhost:{}/callback", port);
    let redirect_url = RedirectUrl::new(redirect_uri.clone()).context("Invalid redirect URL")?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.to_string()),
        None,
    )
    .set_redirect_uri(redirect_url);

    let (code_verifier, _code_challenge) = generate_pkce_pair();
    let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(
        &PkceCodeVerifier::new(code_verifier.clone()),
    );

    let (auth_url, csrf_state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("groups".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let (tx, rx) = oneshot::channel::<(String, String)>();
    let tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

    let callback_app = axum::Router::new().route(
        "/callback",
        axum::routing::get(
            |axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>| async move {
                let tx_clone = tx.clone();
                if let (Some(code), Some(state)) = (params.get("code"), params.get("state")) {
                    if let Some(sender) = tx_clone.lock().await.take() {
                        let _ = sender.send((code.clone(), state.clone()));
                    }
                    return "✓ Login successful! You can close this window.";
                }
                "✗ Login failed: Missing authorization code or state."
            },
        ),
    );

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context(format!("Failed to bind to {}. Try different --port", addr))?;

    tokio::spawn(async move {
        axum::serve(listener, callback_app).await.ok();
    });

    println!("Opening browser for login...");
    println!("If browser doesn't open, visit: {}", auth_url);

    if let Err(e) = open_url(auth_url.as_str()) {
        eprintln!("Could not open browser: {}", e);
    }

    let (code, returned_state) =
        tokio::time::timeout(std::time::Duration::from_secs(120), rx)
            .await
            .context("Login timeout after 2 minutes")??;

    if returned_state != *csrf_state.secret() {
        bail!("State mismatch in OAuth2 callback");
    }

    exchange_code_for_tokens(
        app_name,
        &client,
        base_url,
        &code,
        &code_verifier,
        insecure,
        server_name,
        nonce,
    )
    .await
}

async fn discover_provider(base_url: &str, insecure: bool) -> Result<CoreProviderMetadata> {
    let issuer_url = IssuerUrl::new(base_url.to_string()).context("Invalid issuer URL")?;
    if insecure {
        eprintln!("Warning: --insecure is not supported for OIDC discovery; proceeding with default TLS validation.");
    }
    let metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client).await?;
    Ok(metadata)
}

fn generate_pkce_pair() -> (String, String) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    let code_verifier: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let hash = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(hash);

    (code_verifier, code_challenge)
}

async fn exchange_code_for_tokens(
    app_name: &str,
    client: &CoreClient,
    base_url: &str,
    code: &str,
    code_verifier: &str,
    insecure: bool,
    server_name: &str,
    nonce: Nonce,
) -> Result<()> {
    if insecure {
        eprintln!("Warning: --insecure is not supported for OIDC token exchange; proceeding with default TLS validation.");
    }

    let token_response = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(PkceCodeVerifier::new(code_verifier.to_string()))
        .request_async(async_http_client)
        .await
        .context("Failed to exchange authorization code for tokens")?;

    let id_token = token_response.id_token().context("No ID token in response")?;

    let claims = id_token
        .claims(&client.id_token_verifier(), move |nonce_opt: Option<&Nonce>| match nonce_opt {
            Some(value) if value.secret() == nonce.secret() => Ok(()),
            Some(_) => Err("Nonce mismatch".to_string()),
            None => Err("No nonce in token".to_string()),
        })
        .context("Failed to verify ID token")?;

    let email = claims
        .email()
        .map(|e| e.to_string())
        .filter(|e| !e.is_empty());

    let raw_claims = parse_raw_claims(id_token)?;
    let groups = extract_groups(&raw_claims);

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: i64,
    }

    let token_data = TokenResponse {
        access_token: token_response.access_token().secret().to_string(),
        refresh_token: token_response
            .refresh_token()
            .map(|token| token.secret().to_string()),
        expires_in: token_response
            .expires_in()
            .map(|exp| exp.as_secs() as i64)
            .unwrap_or(3600),
    };

    let session = Session {
        access_token: token_data.access_token,
        refresh_token: token_data.refresh_token.unwrap_or_default(),
        expires_at: Utc::now() + Duration::seconds(token_data.expires_in),
        base_url: base_url.to_string(),
        created_at: Utc::now(),
        user_email: email,
        user_groups: groups,
    };

    save_session(app_name, server_name, session)?;

    println!("✓ Login successful!");
    println!("Session saved to {}", sessions_file_path(app_name)?.display());
    println!("Server: {}", server_name);

    Ok(())
}

#[allow(dead_code)]
pub async fn refresh_session_async(session: Session) -> Result<Session> {
    if session.refresh_token.trim().is_empty() {
        bail!("No refresh token available. Please login again");
    }
    let client = reqwest::Client::new();

    let params = [
        ("grant_type", "refresh_token"),
        ("client_id", "cli-tools"),
        ("client_secret", ""),
        ("refresh_token", &session.refresh_token),
    ];

    let response = client
        .post(format!("{}/oauth2/token", session.base_url))
        .form(&params)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;

    if !status.is_success() {
        if let Ok(err) = serde_json::from_str::<ErrorResponse>(&body) {
            bail!(
                "Token refresh failed: {}: {}. Please login again",
                err.error,
                err.error_description
            );
        }
        bail!(
            "Token refresh failed ({}). Please login again. Response: {}",
            status,
            body.trim()
        );
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: i64,
    }

    let token_data: TokenResponse = match serde_json::from_str(&body) {
        Ok(data) => data,
        Err(err) => {
            if let Ok(err_body) = serde_json::from_str::<ErrorResponse>(&body) {
                bail!(
                    "Token refresh failed: {}: {}. Please login again",
                    err_body.error,
                    err_body.error_description
                );
            }
            bail!(
                "Token refresh response missing access_token. Please login again. Parse error: {}. Response: {}",
                err,
                body.trim()
            );
        }
    };

    Ok(Session {
        access_token: token_data.access_token,
        refresh_token: token_data.refresh_token.unwrap_or(session.refresh_token),
        expires_at: Utc::now() + Duration::seconds(token_data.expires_in),
        base_url: session.base_url,
        created_at: session.created_at,
        user_email: session.user_email,
        user_groups: session.user_groups,
    })
}

fn parse_raw_claims(id_token: &CoreIdToken) -> Result<HashMap<String, Value>> {
    let token_str = id_token.to_string();
    let parts: Vec<&str> = token_str.split('.').collect();
    if parts.len() != 3 {
        bail!("Invalid JWT format");
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .context("Failed to decode JWT payload")?;
    let claims: HashMap<String, Value> = serde_json::from_slice(&payload)
        .context("Failed to parse JWT claims")?;
    Ok(claims)
}

fn extract_groups(claims: &HashMap<String, Value>) -> Vec<String> {
    let Some(groups) = claims.get("groups") else {
        return Vec::new();
    };
    match groups {
        Value::Array(values) => values
            .iter()
            .filter_map(|value| value.as_str().map(|s| s.to_string()))
            .collect(),
        Value::String(single) => vec![single.to_string()],
        _ => Vec::new(),
    }
}

fn open_url(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(url).status()?;
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd").args(["/C", "start", url]).status()?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open").arg(url).status()?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(anyhow!("Unsupported OS for opening URLs"))
}
