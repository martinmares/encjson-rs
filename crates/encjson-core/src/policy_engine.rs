use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct EngineInput<'a> {
    pub principal_spiffe_id: &'a str,
    pub action: &'a str,
    pub resource: ResourceInput<'a>,
}

#[derive(Debug, Clone)]
pub enum ResourceInput<'a> {
    String(&'a str),
    Scoped(ResourceScopedInput<'a>),
}

#[derive(Debug, Clone, Default)]
pub struct ResourceScopedInput<'a> {
    pub tenant: Option<&'a str>,
    pub env: Option<&'a str>,
    pub app: Option<&'a str>,
    pub service: Option<&'a str>,
    pub public_key: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyFile {
    pub authz: AuthzConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthzConfig {
    #[serde(default)]
    pub default: DefaultAction,
    #[serde(default)]
    pub policies: Vec<PolicyEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    #[default]
    Deny,
    Allow,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyEntry {
    #[serde(default)]
    pub id: Option<String>,
    pub principal: PolicyPrincipal,
    #[serde(default)]
    pub allow: Vec<Permission>,
    #[serde(default)]
    pub deny: Vec<Permission>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyPrincipal {
    pub spiffe_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Permission {
    pub action: String,
    pub resource: PolicyResource,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PolicyResource {
    String(String),
    Scoped(PolicyResourceScoped),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyResourceScoped {
    #[serde(default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub env: Option<OneOrManyString>,
    #[serde(default)]
    pub app: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OneOrManyString {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct Policy {
    inner: PolicyFile,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyLoadError {
    #[error("failed to read policy file {path}: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid policy yaml in {path}: {source}")]
    ParseFile {
        path: String,
        source: serde_yaml_ng::Error,
    },
    #[error("invalid policy yaml: {0}")]
    Parse(serde_yaml_ng::Error),
}

impl Policy {
    pub fn from_yaml(raw: &str) -> Result<Self, PolicyLoadError> {
        let parsed = serde_yaml_ng::from_str::<PolicyFile>(raw).map_err(PolicyLoadError::Parse)?;
        Ok(Self { inner: parsed })
    }

    pub fn from_file(path: &Path) -> Result<Self, PolicyLoadError> {
        let p = path.display().to_string();
        let raw = std::fs::read_to_string(path).map_err(|source| PolicyLoadError::ReadFile {
            path: p.clone(),
            source,
        })?;
        let parsed = serde_yaml_ng::from_str::<PolicyFile>(&raw)
            .map_err(|source| PolicyLoadError::ParseFile { path: p, source })?;
        Ok(Self { inner: parsed })
    }

    pub fn as_file(&self) -> &PolicyFile {
        &self.inner
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    EncjsonKeys,
    SimpleInit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileViolation {
    pub policy_id: Option<String>,
    pub message: String,
}

pub fn evaluate(policy: &Policy, input: &EngineInput<'_>) -> Decision {
    let p = policy.as_file();

    for rule in &p.authz.policies {
        if !glob_match(&rule.principal.spiffe_id, input.principal_spiffe_id) {
            continue;
        }
        for perm in &rule.deny {
            if permission_matches(perm.action.as_str(), &perm.resource, input) {
                return Decision::Deny;
            }
        }
    }

    for rule in &p.authz.policies {
        if !glob_match(&rule.principal.spiffe_id, input.principal_spiffe_id) {
            continue;
        }
        for perm in &rule.allow {
            if permission_matches(perm.action.as_str(), &perm.resource, input) {
                return Decision::Allow;
            }
        }
    }

    match p.authz.default {
        DefaultAction::Allow => Decision::Allow,
        DefaultAction::Deny => Decision::Deny,
    }
}

pub fn validate_for_profile(policy: &Policy, profile: Profile) -> Vec<ProfileViolation> {
    let mut out = Vec::new();
    for entry in &policy.as_file().authz.policies {
        for perm in &entry.allow {
            validate_permission(profile, entry.id.clone(), perm, &mut out);
        }
        for perm in &entry.deny {
            validate_permission(profile, entry.id.clone(), perm, &mut out);
        }
    }
    out
}

fn permission_matches(
    action_rule: &str,
    rule_resource: &PolicyResource,
    input: &EngineInput<'_>,
) -> bool {
    if !glob_match(action_rule, input.action) {
        return false;
    }
    resource_matches(rule_resource, &input.resource)
}

fn resource_matches(rule: &PolicyResource, input: &ResourceInput<'_>) -> bool {
    match (rule, input) {
        (PolicyResource::String(rule_str), ResourceInput::String(v)) => glob_match(rule_str, v),
        (PolicyResource::String(rule_str), ResourceInput::Scoped(_)) => rule_str == "*",
        (PolicyResource::Scoped(rule_scoped), ResourceInput::Scoped(v)) => {
            scoped_matches(rule_scoped, v)
        }
        (PolicyResource::Scoped(_), ResourceInput::String(_)) => false,
    }
}

fn scoped_matches(rule: &PolicyResourceScoped, input: &ResourceScopedInput<'_>) -> bool {
    match_field(&rule.tenant, input.tenant)
        && match_one_or_many(&rule.env, input.env)
        && match_field(&rule.app, input.app)
        && match_field(&rule.service, input.service)
        && match_field(&rule.public_key, input.public_key)
}

fn match_field(rule: &Option<String>, value: Option<&str>) -> bool {
    match rule {
        None => true,
        Some(r) => match value {
            Some(v) => glob_match(r, v),
            None => r == "*",
        },
    }
}

fn match_one_or_many(rule: &Option<OneOrManyString>, value: Option<&str>) -> bool {
    match rule {
        None => true,
        Some(OneOrManyString::One(v)) => match value {
            Some(actual) => glob_match(v, actual),
            None => v == "*",
        },
        Some(OneOrManyString::Many(vs)) => match value {
            Some(actual) => vs.iter().any(|v| glob_match(v, actual)),
            None => vs.iter().any(|v| v == "*"),
        },
    }
}

fn validate_permission(
    profile: Profile,
    policy_id: Option<String>,
    perm: &Permission,
    out: &mut Vec<ProfileViolation>,
) {
    match profile {
        Profile::SimpleInit => {
            if matches!(perm.resource, PolicyResource::Scoped(_)) {
                out.push(ProfileViolation {
                    policy_id,
                    message: "simple-init profile does not support structured resource object"
                        .to_string(),
                });
            }
        }
        Profile::EncjsonKeys => match &perm.resource {
            PolicyResource::String(s) => {
                if s != "*" {
                    out.push(ProfileViolation {
                        policy_id,
                        message: "encjson-keys profile allows string resource only as '*'"
                            .to_string(),
                    });
                }
            }
            PolicyResource::Scoped(scoped) => {
                validate_encjson_scoped(policy_id, scoped, out);
            }
        },
    }
}

fn validate_encjson_scoped(
    policy_id: Option<String>,
    scoped: &PolicyResourceScoped,
    out: &mut Vec<ProfileViolation>,
) {
    if scoped.tenant.is_none() {
        out.push(ProfileViolation {
            policy_id,
            message: "encjson-keys scoped resource should define tenant".to_string(),
        });
    }
}

fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == value {
        return true;
    }
    glob_match_recursive(pattern, value)
}

fn glob_match_recursive(pattern: &str, value: &str) -> bool {
    let mut pat_chars = pattern.chars().peekable();
    let mut val_chars = value.chars().peekable();

    loop {
        match pat_chars.peek() {
            None => return val_chars.peek().is_none(),
            Some('*') => {
                pat_chars.next();
                if pat_chars.peek() == Some(&'*') {
                    pat_chars.next();
                    let remaining_pat: String = pat_chars.collect();
                    if remaining_pat.is_empty() {
                        return true;
                    }
                    let remaining_val: String = val_chars.collect();
                    for i in 0..=remaining_val.len() {
                        if glob_match_recursive(&remaining_pat, &remaining_val[i..]) {
                            return true;
                        }
                    }
                    return false;
                }

                let remaining_pat: String = pat_chars.collect();
                let remaining_val: String = val_chars.collect();
                for i in 0..=remaining_val.len() {
                    if remaining_val[..i].contains('/') {
                        break;
                    }
                    if glob_match_recursive(&remaining_pat, &remaining_val[i..]) {
                        return true;
                    }
                }
                return false;
            }
            Some(_) => {
                let pc = pat_chars.next().expect("peeked char");
                match val_chars.next() {
                    None => return false,
                    Some(vc) if vc == pc => continue,
                    Some(_) => return false,
                }
            }
        }
    }
}
