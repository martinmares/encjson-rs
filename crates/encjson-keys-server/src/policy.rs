use std::path::Path;

use serde::Deserialize;

use crate::state::Principal;

#[derive(Clone, Debug)]
pub(crate) struct LocalPolicy {
    bindings: Vec<PolicyBinding>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LocalPolicyGrant {
    pub(crate) is_admin: bool,
    pub(crate) is_scoped: bool,
    pub(crate) tenants: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    bindings: Vec<PolicyBinding>,
}

#[derive(Clone, Debug, Deserialize)]
struct PolicyBinding {
    #[allow(dead_code)]
    #[serde(default)]
    id: Option<String>,
    subjects: PolicySubjects,
    #[serde(default)]
    permissions: Vec<PolicyPermission>,
}

#[derive(Clone, Debug, Deserialize)]
struct PolicySubjects {
    issuer: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    service_account: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct PolicyPermission {
    resource: String,
    #[serde(default)]
    actions: Vec<String>,
    #[serde(default)]
    tenants: Vec<String>,
}

#[derive(Debug)]
pub(crate) enum LocalPolicyLoadError {
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    ParseFile {
        path: String,
        source: serde_yaml_ng::Error,
    },
}

impl std::fmt::Display for LocalPolicyLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadFile { path, source } => {
                write!(f, "failed to read policy file {path}: {source}")
            }
            Self::ParseFile { path, source } => {
                write!(f, "invalid policy yaml in {path}: {source}")
            }
        }
    }
}

impl std::error::Error for LocalPolicyLoadError {}

impl LocalPolicy {
    pub(crate) fn from_file(path: &Path) -> Result<Self, LocalPolicyLoadError> {
        let p = path.display().to_string();
        let raw =
            std::fs::read_to_string(path).map_err(|source| LocalPolicyLoadError::ReadFile {
                path: p.clone(),
                source,
            })?;
        let parsed = serde_yaml_ng::from_str::<PolicyFile>(&raw)
            .map_err(|source| LocalPolicyLoadError::ParseFile { path: p, source })?;
        Ok(Self {
            bindings: parsed.bindings,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_yaml(raw: &str) -> Result<Self, serde_yaml_ng::Error> {
        let parsed = serde_yaml_ng::from_str::<PolicyFile>(raw)?;
        Ok(Self {
            bindings: parsed.bindings,
        })
    }

    pub(crate) fn evaluate(&self, principal: &Principal) -> LocalPolicyGrant {
        let mut grant = LocalPolicyGrant::default();
        for binding in &self.bindings {
            if !binding.subjects.matches(principal) {
                continue;
            }
            grant.merge(binding.grant());
        }
        grant.tenants.sort();
        grant.tenants.dedup();
        grant
    }
}

impl LocalPolicyGrant {
    fn merge(&mut self, other: Self) {
        self.is_admin = self.is_admin || other.is_admin;
        self.is_scoped = self.is_scoped || other.is_scoped;
        self.tenants.extend(other.tenants);
    }
}

impl PolicyBinding {
    fn grant(&self) -> LocalPolicyGrant {
        let mut grant = LocalPolicyGrant::default();
        for permission in &self.permissions {
            match permission.resource.as_str() {
                "keys" => {
                    if permission.has_action("*") || permission.has_action("admin") {
                        grant.is_admin = true;
                        grant.is_scoped = true;
                    }
                    if permission.has_action("read") {
                        grant.is_scoped = true;
                    }
                }
                "requests" if permission.has_action("create") => grant.is_scoped = true,
                _ => {}
            }
            if !permission.tenants.is_empty() {
                grant.is_scoped = true;
                grant.tenants.extend(permission.tenants.iter().cloned());
            }
        }
        grant
    }
}

impl PolicyPermission {
    fn has_action(&self, action: &str) -> bool {
        self.actions.iter().any(|candidate| candidate == action)
    }
}

impl PolicySubjects {
    fn matches(&self, principal: &Principal) -> bool {
        if self.issuer != principal.issuer {
            return false;
        }
        if !option_matches(self.kind.as_deref(), Some(principal.kind_name())) {
            return false;
        }
        if !option_matches(self.subject.as_deref(), principal.subject.as_deref()) {
            return false;
        }
        if !option_matches(self.client_id.as_deref(), principal.client_id.as_deref()) {
            return false;
        }
        if !option_matches(self.namespace.as_deref(), principal.namespace.as_deref()) {
            return false;
        }
        if !option_matches(
            self.service_account.as_deref(),
            principal.service_account.as_deref(),
        ) {
            return false;
        }
        if !self
            .groups
            .iter()
            .all(|group| principal.groups.contains(group))
        {
            return false;
        }
        if !self
            .scopes
            .iter()
            .all(|scope| principal.scopes.contains(scope))
        {
            return false;
        }
        true
    }
}

fn option_matches(rule: Option<&str>, value: Option<&str>) -> bool {
    match rule {
        Some("*") => value.is_some(),
        Some(rule) => value == Some(rule),
        None => true,
    }
}

trait PrincipalKindName {
    fn kind_name(&self) -> &'static str;
}

impl PrincipalKindName for Principal {
    fn kind_name(&self) -> &'static str {
        match self.kind {
            crate::state::PrincipalKind::User => "user",
            crate::state::PrincipalKind::Service => "service",
            crate::state::PrincipalKind::Workload => "workload",
            crate::state::PrincipalKind::Unknown => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::state::{AuthMethod, PrincipalKind};

    use super::*;

    fn workload_principal() -> Principal {
        Principal {
            auth_method: AuthMethod::BearerToken,
            issuer: "kube-sa-jwt".to_string(),
            kind: PrincipalKind::Workload,
            subject: Some("system:serviceaccount:zis-test:order-api".to_string()),
            groups: Vec::new(),
            scopes: Vec::new(),
            audience: vec!["key-server".to_string()],
            client_id: None,
            email: None,
            username: None,
            namespace: Some("zis-test".to_string()),
            service_account: Some("order-api".to_string()),
        }
    }

    #[test]
    fn kube_workload_policy_grants_tenant_read() {
        let policy = LocalPolicy::from_yaml(
            r#"
bindings:
  - subjects:
      issuer: kube-sa-jwt
      kind: workload
      namespace: zis-test
      service_account: order-api
    permissions:
      - resource: keys
        actions: [read]
        tenants: [o2]
"#,
        )
        .unwrap();

        let grant = policy.evaluate(&workload_principal());
        assert!(!grant.is_admin);
        assert!(grant.is_scoped);
        assert_eq!(grant.tenants, vec!["o2"]);
    }

    #[test]
    fn kube_workload_policy_rejects_other_service_account() {
        let policy = LocalPolicy::from_yaml(
            r#"
bindings:
  - subjects:
      issuer: kube-sa-jwt
      kind: workload
      namespace: zis-test
      service_account: other-api
    permissions:
      - resource: keys
        actions: [read]
        tenants: [o2]
"#,
        )
        .unwrap();

        let grant = policy.evaluate(&workload_principal());
        assert_eq!(grant, LocalPolicyGrant::default());
    }

    #[test]
    fn old_authz_yaml_is_not_supported() {
        let raw = r#"
authz:
  rules:
    - principal:
        issuer: kube-sa-jwt
      allow:
        - keys:read
"#;
        assert!(LocalPolicy::from_yaml(raw).is_err());
    }
}
