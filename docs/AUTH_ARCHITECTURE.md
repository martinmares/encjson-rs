# Authentication and Authorization Architecture

This document is the binding architecture contract for authentication and
authorization across the `encjson-rs` ecosystem and related Simple services.

The goal is to keep the model simple, explicit, and reusable across services
without introducing a central online authorization dependency for every request.

## Scope

This contract applies to services such as:

- `encjson-keys-server`
- `simple-oci-registry`
- `simple-config-server`
- `simple-artifacts-server`
- `simple-deploy-server`
- deployment/sync tools and related CLIs

Not every service has to implement every mode immediately. The contract defines
the supported direction.

## Core Decision

There are two supported authentication mechanisms:

1. Bearer token authentication
2. Trusted proxy headers

These mechanisms are complementary.

```text
Bearer JWT token       = cryptographic trust in a signed token
X-Auth-* headers       = topological trust in a protected proxy boundary
```

`simple-idm-server` is the primary identity provider for humans, CLIs, GitLab,
and service-to-service clients.

Kubernetes/OpenShift is also a valid identity provider for workloads through
projected ServiceAccount tokens.

This means `simple-idm-server` is not the only possible issuer. It is one
trusted issuer among the configured issuers.

## Explicit Non-Goals

The current target architecture does not include:

- mTLS between all services
- SPIFFE/SPIRE
- service mesh identity
- OPA sidecars for every request
- token introspection on every request
- one new central authorization server for every service call

These can be reconsidered later only if there is a concrete operational or
regulatory need. For the current stack they add too much complexity.

## Authentication Modes

### 1. Browser to UI

Preferred model for UI/FE applications that should not implement full OIDC
logic themselves:

```text
Browser
  -> Nginx / ingress
  -> simple-idm-oauth2-proxy
  -> application
```

The proxy performs OIDC login and session handling through `simple-idm-server`.
The application receives identity through trusted headers:

```http
X-Auth-User: mares
X-Auth-Email: mares@example.com
X-Auth-Subject: 97173b5f-6277-4aa7-b15e-a6c0b03cf0fd
X-Auth-Groups: app:role:admin,app:tenant:o2
```

`simple-idm-oauth2-proxy` emits `X-Auth-Subject` from the stable OIDC `sub`
claim. Applications should use it for audit and durable identity, and treat
`X-Auth-User` as a display/login value.

This model is suitable for:

- internal web UIs
- admin consoles
- dashboard-like tools
- apps where auth should stay outside the application

### 2. API and CLI to Service

Preferred model for APIs and CLI tools:

```text
Client / CLI
  -> Authorization: Bearer <access-token>
  -> target service
```

The service validates the JWT locally:

- issuer
- signature through JWKS
- audience
- expiration / not-before
- scopes
- groups / roles

This model is suitable for:

- REST APIs
- CLIs
- backend endpoints
- automation
- GitLab / CI calls

### 3. Service to Service

Preferred model:

```text
caller service
  -> client_credentials token from simple-idm-server
  -> target service with Authorization: Bearer <access-token>
```

Example:

```text
client_id = gitlab-ci
audience  = encjson-keys-server
scope     = keys:read
```

The target service validates:

- issuer is `simple-idm-jwt`
- audience matches the target service
- scope allows the operation
- client identity is allowed by local policy

### 4. OpenShift Workload to Service

Preferred model for Pods running in Kubernetes/OpenShift:

```text
Pod
  -> projected ServiceAccount token
  -> Authorization: Bearer <jwt>
  -> target service
```

The target service validates the token locally using Kubernetes/OpenShift OIDC
discovery and JWKS.

This is not handled by `simple-idm-server`. Kubernetes/OpenShift is the issuer
for workload identity.

Expected claims:

```json
{
  "sub": "system:serviceaccount:zis-test:order-api",
  "kubernetes.io": {
    "namespace": "zis-test",
    "serviceaccount": {
      "name": "order-api"
    }
  }
}
```

The normalized workload identity is:

```text
namespace/serviceAccount
```

Example:

```text
zis-test/order-api
```

Pod name must not be used as the authorization identity because it changes on
rollout. Pod UID/name may be used only for audit logging.

## Trusted Proxy Header Rules

Applications may trust `X-Auth-*` headers only if they are reachable exclusively
through a trusted proxy.

Required rule:

```text
public traffic -> trusted proxy -> application
```

Forbidden rule:

```text
public traffic -> application
```

The public edge must strip any client-supplied auth headers and set trusted
headers only after successful authentication.

Headers such as `X-Auth-Token` must not be forwarded by default. Forward a raw
access token only when the downstream application explicitly needs delegated API
calls.

For `encjson-keys-server`, trusted proxy headers are accepted only when
explicitly enabled through `ENCJSON_KEYS_TRUSTED_PROXY_HEADERS=true` /
`--keys-trusted-proxy-headers`.

The normalized issuer is:

```text
proxy
```

The supported headers are:

```http
X-Auth-Subject: 97173b5f-6277-4aa7-b15e-a6c0b03cf0fd
X-Auth-User: mares
X-Auth-Email: mares@example.com
X-Auth-Groups: encjson:role:scoped,encjson:tenant:o2
```

`X-Auth-Groups` is comma-separated.

## Bearer Token Issuers

Services that accept bearer tokens should support multiple configured issuers.

Conceptual configuration:

```yaml
auth:
  issuers:
    - name: simple-idm-jwt
      type: oidc
      issuer: https://sso.cloud-app.cz
      jwks_url: https://sso.cloud-app.cz/.well-known/jwks.json
      audience: encjson-keys-server

    - name: kube-sa-jwt
      type: kubernetes_service_account
      issuer: https://kubernetes.default.svc
      discovery_url: https://kubernetes.default.svc/.well-known/openid-configuration
      audience: key-server
      ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      service_account_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
```

Issuer names are stable policy-facing identifiers.

Recommended names:

```text
simple-idm-jwt
kube-sa-jwt
```

`kube-sa-jwt` means Kubernetes/OpenShift projected ServiceAccount JWT.

## Normalized Principal

Every accepted authentication method must be normalized into one internal
principal shape.

Conceptual structure:

```text
Principal {
  auth_method: bearer_token | trusted_proxy_headers
  issuer: simple-idm-jwt | kube-sa-jwt | proxy
  kind: user | service | workload
  subject: string
  groups: [string]
  scopes: [string]
  audience: [string]
  client_id: optional string
  email: optional string
  username: optional string
  namespace: optional string
  service_account: optional string
}
```

Examples:

```text
Human via Simple IDM:
  issuer = simple-idm-jwt
  kind = user
  subject = 97173b5f-6277-4aa7-b15e-a6c0b03cf0fd
  groups = ["encjson:role:admin"]

GitLab via Simple IDM client credentials:
  issuer = simple-idm-jwt
  kind = service
  client_id = gitlab-ci
  scopes = ["keys:read"]

OpenShift workload:
  issuer = kube-sa-jwt
  kind = workload
  subject = system:serviceaccount:zis-test:order-api
  namespace = zis-test
  service_account = order-api
```

## Authorization Model

Identity providers prove identity. Target services decide local business
authorization.

In other words:

```text
Simple IDM / Kubernetes says who you are.
The target service decides what you may do.
```

Services should avoid pushing detailed business policy into Simple IDM.

Simple IDM should provide:

- subject
- client id
- groups
- scopes
- audience
- issuer
- expiration

The service should own:

- tenant access
- resource access
- operation-level permissions
- approval workflows
- audit decisions

## Example Policy

Example local policy for `encjson-keys-server`:

```yaml
bindings:
  - id: admin-group
    subjects:
      issuer: simple-idm-jwt
      groups:
        - encjson:role:admin
    permissions:
      - resource: keys
        actions: [admin]

  - id: tenant-o2-read
    subjects:
      issuer: simple-idm-jwt
      groups:
        - encjson:tenant:o2
    permissions:
      - resource: keys
        actions: [read]
        tenants: [o2]

  - id: gitlab-o2-read
    subjects:
      issuer: simple-idm-jwt
      client_id: gitlab-ci
      scopes:
        - keys:read
    permissions:
      - resource: keys
        actions: [read]
        tenants: [o2]

  - id: order-api-o2-read
    subjects:
      issuer: kube-sa-jwt
      kind: workload
      namespace: zis-test
      service_account: order-api
    permissions:
      - resource: keys
        actions: [read]
        tenants: [o2]
```

## OpenShift ServiceAccount JWT Requirements

For Kubernetes/OpenShift projected ServiceAccount tokens, the service must:

- load OIDC discovery document
- load JWKS
- validate `kid`
- validate signature
- accept only the configured algorithm, normally `RS256`
- validate issuer
- validate audience
- validate expiration and not-before
- refresh JWKS on unknown `kid`
- validate `sub` matches namespace and serviceAccount claims
- never use pod name as the authorization identity
- never log the full JWT token

TokenReview API is not required for this model.

## Service-Specific Direction

### encjson-keys-server

`encjson-keys-server` should accept bearer tokens from:

- `simple-idm-jwt`
- `kube-sa-jwt`

It should use the normalized principal and local policy to decide whether a key
may be read, registered, approved, or administered.

This is the first service where the multi-issuer model should be implemented.

### simple-oci-registry-like UI Services

Services with backend plus frontend UI should support both:

- trusted proxy headers for browser UI
- bearer token validation for API access

This makes the same service usable from browser, CLI, automation, and other
services without forcing every user-facing app to implement its own OIDC login.

Current `simple-oci-registry` implementation note:

- keeps the OCI `/v2/*` Docker/registry token challenge flow as a protocol-specific
  path
- supports trusted proxy `X-Auth-*` headers for UI and REST API when
  `auth.trusted_proxy.enabled=true`
- protects REST `/api/*` endpoints
- accepts registry Bearer tokens issued by `/v2/auth` for REST API repository
  operations
- maps REST read operations to repository `pull`
- maps REST write operations to repository `push`
- requires trusted-proxy `registry:admin` identity for global REST operations
  such as `/api/gc`

### simple-config-server / simple-artifacts-server / simple-deploy-server

These services should follow the same pattern:

- UI/browser entry can be protected by proxy headers
- API endpoints should accept bearer tokens
- service-specific authorization remains local

Current `simple-config-server` implementation note:

- supports opt-in trusted proxy headers through `auth.trusted_proxy.enabled`
- supports Bearer JWT issuers through `auth.bearer.issuers`
- supports `simple-idm-jwt` and `kube-sa-jwt`
- validates Kubernetes ServiceAccount `sub` against namespace/serviceAccount claims
- does not support legacy Basic Auth or `X-Client-Id` modes

Current `simple-artifacts-server` implementation note:

- supports trusted proxy `X-Auth-*` headers for UI and API identity
- uses service-specific groups:
  - `simple-artifacts:role:admin`
  - `simple-artifacts:repo:*:*:read`
  - `simple-artifacts:repo:*:*:write`
  - `simple-artifacts:repo:<repo_type>:*:read`
  - `simple-artifacts:repo:<repo_type>:*:write`
  - `simple-artifacts:repo:<repo_type>:<repo_name>:read`
  - `simple-artifacts:repo:<repo_type>:<repo_name>:write`
- keeps public repository read rules in local `policy.yaml`
- does not support legacy Basic Auth or `X-Client-Id` modes
- keeps Bearer JWT support as a later step

Current `kube-deploy-sync` implementation note:

- supports opt-in trusted proxy headers through `auth.trusted_proxy.enabled`
- protects UI and REST API when trusted proxy auth is enabled
- uses service-specific groups:
  - `kube-deploy-sync:role:admin`
  - `kube-deploy-sync:namespace:*:reader`
  - `kube-deploy-sync:namespace:*:operator`
  - `kube-deploy-sync:namespace:<namespace>:reader`
  - `kube-deploy-sync:namespace:<namespace>:operator`
- filters namespace and sync target listings by namespace read access
- requires namespace operator access for scale, restart, wave restart, exec and sync target mutations
- keeps Bearer JWT support as a later step

Current `kube-edit-app` implementation note:

- supports opt-in trusted proxy headers through `--trusted-proxy-auth` /
  `KUBE_EDIT_TRUSTED_PROXY_AUTH=true`
- protects UI and REST API when trusted proxy auth is enabled
- uses service-specific groups:
  - `kube-edit-app:role:admin`
  - `kube-edit-app:env:*:reader`
  - `kube-edit-app:env:*:writer`
  - `kube-edit-app:env:<env>:reader`
  - `kube-edit-app:env:<env>:writer`
- filters environment listings by environment read access
- requires environment writer access for structured environment mutations
- requires `kube-edit-app:role:admin` for global Git commit/restore operations
- still requires `--allow-write` for any mutating repository endpoint, even for
  authenticated writers
- keeps Bearer JWT support as a later step

## Implementation Order

1. Keep this document as the architecture contract.
2. [x] Refactor `encjson-keys-server` auth into issuer-based validation.
3. [x] Implement `simple-idm-jwt` as the first issuer backend.
4. [x] Implement `kube-sa-jwt` as the second issuer backend.
5. [x] Normalize accepted bearer JWT identities into `Principal`.
6. [x] Move bearer-token key access decisions to a local policy evaluator.
7. [x] Add opt-in trusted proxy header normalization to `encjson-keys-server`.
8. Reuse the same pattern in other services manually, without extracting a
   shared library too early.

Current `kube-sa-jwt` implementation note:

- loads JWKS URL from OIDC discovery by default
- accepts explicit `ENCJSON_KEYS_KUBE_SA_JWKS_URL` as an override
- validates issuer, audience, signature and ServiceAccount claim consistency
- supports local authorization grants through `ENCJSON_KEYS_POLICY_FILE`
- refreshes JWKS on unknown `kid`

## Important Constraint

Do not prematurely extract a shared authorization library or introduce a new
central authorization server.

Each binary should stay understandable and independently operable. Shared code
can be reconsidered only after the model is proven stable in more than one
service.
