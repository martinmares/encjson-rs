# Authentication and Authorization Architecture

This document is the binding architecture contract for authentication and
authorization across the `encjson-rs` ecosystem and related Simple services.

The goal is to keep the model simple, explicit, and reusable across services
without introducing a central online authorization dependency for every request.

## Scope

This contract applies to services such as:

- `encjson-keys-server`
- `simple-idm-server`
- `simple-idm-ad-proxy`
- `simple-idm-oauth2-proxy`
- `simple-oci-registry`
- `simple-config-server`
- `simple-vault-server`
- `postgres-explorer`
- `elastic-explorer`
- `simple-artifacts-server`
- `simple-deploy-server`
- deployment/sync tools and related CLIs

Not every service has to implement every mode immediately. The contract defines
the supported direction.

## Core Decision

There are three supported authentication mechanisms:

1. Signed Bearer JWT authentication
2. Trusted proxy headers
3. Local service tokens for explicitly configured same-host integrations

These mechanisms are complementary. A service implements only the mechanisms
required by its deployment and API surface.

```text
Bearer JWT token          = cryptographic trust in a signed token
X-Auth-* headers          = topological trust in a protected proxy boundary
X-Simple-Service-Token    = scoped opaque credential inside one host trust zone
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

### 5. Same-Host Service to Service

For a standalone host where both services run inside one controlled operating
system trust boundary, requiring OAuth2/OIDC for every local bootstrap request
can add more operational complexity than security value.

The optional local model is:

```text
local caller service
  -> direct loopback request to target service
  -> X-Simple-Service-Token: <opaque random value>
  -> target-local tenant and permission policy
```

The normalized issuer name is `local-service-token`.

This is not an IP allowlist. Source IP alone is never an identity. Every caller
has a random credential and an explicitly configured service name, tenant set
and permission set.

Required safeguards:

- the target application listener is bound to a loopback address;
- the caller connects directly to that listener, not through the public reverse
  proxy route;
- the token contains at least 256 bits of cryptographically random data;
- the token is loaded from an absolute, access-controlled file and is never
  stored in the application database;
- the target stores only a digest in memory and compares it in constant time;
- the reverse proxy always removes client-supplied
  `X-Simple-Service-Token`;
- the token maps to a named service principal and explicit local authorization
  policy;
- sensitive operations are audited without logging the token.

On the current standalone systemd deployment, cooperating services run as the
same dedicated Unix account and token files use mode `0600`. Services running
under different Unix identities should use signed JWTs unless a deliberately
scoped filesystem/ACL design is introduced.

Do not use this mode across hosts, containers or cluster nodes, through an
externally reachable reverse proxy, for browser sessions, or where workload
identity, expiry, revocation or delegation is required.

### Named Outbound Value Sources

When a service has a concrete need to refresh runtime values from another
same-host service, use named outbound providers instead of embedding endpoint
and credential details repeatedly in each environment block.

The cross-service vocabulary is:

```yaml
value_sources:
  local-vault:
    provider: "simple-vault-server"
    base_url: "http://127.0.0.1:8188/simple-vault-server"
    auth:
      kind: "local-service-token"
      token_file: "/absolute/path/to/service-token"
    refresh_interval_secs: 60
    timeout_secs: 10

tenants:
  default:
    environments:
      dev:
        env_source:
          provider: "local-vault"
          export_profile: "runtime-dotenv"
          required: true
```

The initial implementation exists only in `simple-config-server`. It treats
the structured resolved export as one atomic response and derives two snapshots
from it: a complete runtime map and a diagnostic map containing only values
classified as `anonymous` or `authenticated` and non-sensitive. Both snapshots are
replaced together.
The client retains the last known good pair after refresh failures, rereads the
token file for token rotation, and requires the provider URL to target loopback
when `local-service-token` is used.

`simple-vault-server` export profiles are stable output contracts identified by
a tenant-local slug. They define output names, mappings and format, but they do
not own a scope, environment or release. The consuming environment supplies the
runtime projection. Consequently, `simple-config-server` calls the contextual
slug route directly:

```text
GET /api/v1/tenants/{tenant_slug}/environments/{environment_slug}/export-profiles/{profile_slug}/resolved-values
```

This protected endpoint returns values and their classification in a single
JSON document. Dotenv comments are not authorization metadata. The consumer
must reject duplicate names, unknown classifications, and any value marked both
`anonymous` or `authenticated` and sensitive.

Each resolved value carries two independent fields:

| `exposure` | `sensitive` | Anonymous API | Diagnostics | Protected runtime |
| --- | ---: | ---: | ---: | ---: |
| `anonymous` | `false` | yes | yes | yes |
| `authenticated` | `false` | no | yes | yes |
| `private` | `false` | no | no | yes |
| `private` | `true` | no | no | yes |

`anonymous` or `authenticated` combined with `sensitive: true` is invalid and must
fail closed. `exposure` classifies distribution; `sensitive` controls handling,
redaction, and audit semantics. The `diagnostics:read` scope authorizes a
client, while mapping exposure determines which values that client may receive.

The tenant defaults to the enclosing Config Server tenant unless
`env_source.tenant` overrides it; the environment always comes from the
enclosing `tenants.<tenant>.environments.<environment>` branch. Export profile
UUIDs are internal storage identifiers and are not part of this contract.

The terms `value_sources`, `env_source`, `provider`, `auth.kind`,
`token_file`, `refresh_interval_secs`, `timeout_secs`, and `required` are the
preferred configuration vocabulary if another service later proves that it
needs the same capability. Consistent vocabulary does not imply a shared
runtime library: implement the small client independently in each binary only
after a concrete use case exists. Do not add this block speculatively to every
service and do not extract a shared crate prematurely.

For `simple-config-server`, one environment may configure either its existing
`env_file` or `env_source`, never both. The root-level `env_file` remains a
separate baseline source and may still be combined with either environment
choice.

### Diagnostic Configuration Channel

Operational diagnostics are a third channel, distinct from both browser UI and
the full runtime API:

```text
simple-vault-server resolved-values
        -> simple-config-server runtime + diagnostic snapshots
        -> /api/v1/diagnostics/* with diagnostics:read
```

Diagnostic endpoints:

```text
GET /api/v1/diagnostics/tenants/{tenant}/envs/{env}/{application}/{profile}
GET /api/v1/diagnostics/tenants/{tenant}/envs/{env}/{application}/{profile}/{label}
```

They always require a Bearer JWT with `diagnostics:read`; trusted proxy headers
and auth-disabled sandbox behavior must not authorize this channel. Only
non-sensitive `anonymous` and `authenticated` values are substituted. `private`
values retain their normal `{{ PLACEHOLDER }}` syntax, so templates do not need
separate public/private names. Responses use `Cache-Control: no-store` and
report which variable names were resolved, redacted, or missing without logging
their values.

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

The public edge must also strip `X-Simple-Service-Token`. That header belongs
only to direct same-host requests and must never be forwarded from public
traffic.

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

## Web UI SSO Deployment Modes

Backend services with browser UI should not each implement their own OIDC login
flow by default. The default integration is:

```text
browser -> simple-idm-oauth2-proxy -> backend
```

`simple-idm-oauth2-proxy` owns the OIDC login flow, session cookie, callback,
logout, stripping client-supplied `X-Auth-*` headers, and injecting trusted
identity headers for the backend.

For higher traffic, edge hardening, TLS termination, buffering, request limits,
or organization-standard ingress requirements, deploy a standard proxy/ingress
in front:

```text
browser -> nginx/Traefik/HAProxy/OpenShift Route -> simple-idm-oauth2-proxy -> backend
```

TLS termination is intentionally outside `simple-idm-oauth2-proxy`; it belongs
to the edge proxy/ingress layer.

`simple-idm-oauth2-proxy` supports two operational modes:

- `auth_request`: nginx/ingress performs reverse proxying and asks
  `simple-idm-oauth2-proxy` only for authentication decisions and headers.
- `reverse_proxy`: `simple-idm-oauth2-proxy` performs the OIDC login flow and
  forwards authenticated HTTP/1.1 and WebSocket traffic to one configured
  upstream.

The reverse proxy mode is not a general nginx/Traefik replacement. It is a
single-upstream OIDC adapter for services that need unified SSO without embedding
OIDC login code.

Backend services may implement a native OAuth2/OIDC login flow only when there
is a clear product or operational reason. This is an exception, not the default.

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

These issuer `kind` values are a cross-service contract. Keep the same names in
all services that accept bearer tokens:

- `simple-idm-jwt` for human, CLI, CI/CD, and M2M identities issued by
  `simple-idm-server`.
- `kube-sa-jwt` for Kubernetes/OpenShift workload identities based on projected
  ServiceAccount tokens.

Each service chooses its own `audience` and local policy model, but the issuer
kind names and the basic token validation semantics stay the same.

Services with direct Kubernetes ServiceAccount policy mappings use this shared
selector contract:

```yaml
kube_sa_policies:
  - issuer_name: "production-okd"
    namespace: "payments-production"
    service_accounts: ["order-api", "invoice-api"]
    # Service-specific grants follow, for example tenants/envs/scopes.
```

`issuer_name` binds the policy to one configured `kube-sa-jwt` issuer. The
ServiceAccounts in one list share the same grant. Implementations must reject
an unknown issuer, an empty namespace or list, duplicate names, empty names,
and wildcard ServiceAccount selectors. Broad access belongs in explicit local
resource grants, not in the identity selector.

`encjson-keys-server` currently expresses the same identity relationship in
its generic policy binding model. It does not need to copy the direct
`kube_sa_policies` configuration shape used by `simple-config-server` and
`simple-vault-server`.

Examples:

```text
simple-config-server:
  audience = simple-config-server
  policy = tenant/env/scope grants

encjson-keys-server:
  audience = encjson-keys-server
  policy = tenant/key read grants

simple-vault-server:
  audience = simple-vault-server
  policy = tenant/scope/environment/release/render grants
```

## Normalized Principal

Every accepted authentication method must be normalized into one internal
principal shape.

Conceptual structure:

```text
Principal {
  auth_method: bearer_token | trusted_proxy_headers | local_service_token
  issuer: simple-idm-jwt | kube-sa-jwt | proxy | local-service-token
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

Standalone same-host service:
  issuer = local-service-token
  kind = service
  subject = service:simple-config-server
  client_id = simple-config-server
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
- uses registry service/robot accounts for Docker/OCI machine access; do not add
  `local-service-token` as a competing push/pull credential model

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
- supports named outbound `value_sources` with the
  `simple-vault-server`/`local-service-token` combination for direct same-host
  runtime value refresh
- requires each environment to choose either `env_file` or `env_source`

This outbound use does not make `local-service-token` a public authentication
method of `simple-config-server`. OpenShift applications still authenticate to
Config Server with `kube-sa-jwt`.

### simple-vault-server

`simple-vault-server` supports:

- trusted proxy `X-Auth-*` identity for its browser UI;
- `simple-idm-jwt` and `kube-sa-jwt` for normal API access;
- optional `local-service-token` for direct same-host bootstrap/export calls,
  such as rendering a scoped dotenv file for `simple-config-server`.

The local token is configured and authorized by `simple-vault-server`; it is
not issued by `simple-idm-server`.

### Projects that do not need local service tokens

- `simple-idm-server` remains the JWT/OIDC issuer and does not consume local
  service tokens for its normal protocol endpoints.
- `simple-idm-ad-proxy` and `simple-idm-oauth2-proxy` authenticate humans and
  produce trusted `X-Auth-*` identity; they do not issue or translate local
  service tokens.
- `postgres-explorer` and `elastic-explorer` are interactive support tools and
  continue to use trusted proxy identity.
- `simple-oci-registry` keeps its protocol-specific registry Bearer token and
  service/robot account model for machine access.

`encjson-keys-server` may add `local-service-token` only for a concrete
same-host bootstrap use case. Its normal remote machine paths remain
`simple-idm-jwt` and `kube-sa-jwt`.

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
9. [x] Keep `simple-idm-jwt` and `kube-sa-jwt` as the shared issuer kind names
   in `encjson-keys-server`, `simple-config-server`, and `simple-vault-server`.
10. [x] Implement `kube-sa-jwt` policy support in `simple-vault-server`.

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

## Open Follow-ups

This is the current return plan after the first `simple-oci-registry` SSO rollout.

1. [ ] Verify and commit the final `simple-oci-registry` SSO identity model:
   - UI users authenticate only through `simple-idm-oauth2-proxy`.
   - `X-Auth-Subject` is mandatory and stored as `(provider, subject)`.
   - SSO-linked users cannot use local passwords for Docker/OCI login.
   - Docker/OCI access stays on registry user passwords and service-account
     tokens.
   - SSO UI/API access stays based on current `registry:*` groups from IDM.
2. [ ] Deploy and smoke-test `simple-oci-registry` with the new model:
   - login/logout through SSO proxy
   - account details showing trusted headers and provider/subject
   - Docker `login`, `pull`, and `push` through registry credentials
   - service-account token flow for CI/CD
3. [ ] Finish `simple-idm-oauth2-proxy` production polish:
   - reverse-proxy mode remains the default path for simple UI services
   - HTTP/1.1 and WebSocket behavior must stay tested
   - logout and standalone proxy pages use embedded Tabler assets
4. [ ] Keep the service auth contract aligned across projects:
   - UI services accept trusted `X-Auth-*` headers from the proxy
   - API/backend services accept bearer JWT issuers where direct machine access
     is needed
   - no Basic Auth or `X-Client-Id` compatibility paths are reintroduced
5. [ ] Continue validating the same pattern in the next services:
   - `simple-config-server`
   - `simple-artifacts-server`
   - `kube-deploy-sync`
   - `kube-edit-app`
