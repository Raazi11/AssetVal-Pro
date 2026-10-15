# AssetVal Pro Production Authentication & RBAC

## Authentication
The API uses OIDC/OAuth2 bearer access tokens. Every /v1/* endpoint requires a valid token when OIDC_REQUIRED=true.

Required environment variables:
- OIDC_ISSUER — token issuer
- OIDC_AUDIENCE — API audience
- OIDC_JWKS_URL — signing-key endpoint
- OIDC_REQUIRED=true

The API verifies JWT signature, issuer and audience, then maps the OIDC subject/email to the local users table and checks the user's memberships record for the requested organization.

## Roles
- owner — full organization control
- admin — administration and approvals
- asset_manager — asset/import operations
- approver — approval actions
- auditor — read/audit access
- viewer — read-only access

## Import RBAC
| Action | Allowed roles |
|---|---|
| Validate import | Authenticated organization member |
| Submit import for approval | Owner, Admin, Asset Manager |
| Approve import | Owner, Admin, Approver |
| Execute approved import | Owner, Admin, Asset Manager |
| View import history | All organization roles |
| Roll back completed import | Owner, Admin |

The API uses the authenticated user from the bearer token as the actor; clients cannot choose another actorId.

Approval also enforces separation of duties: the user who submitted an import batch cannot approve that same batch.

## Identity binding
users.oidc_subject stores the stable identity-provider subject. Existing users can be matched by email on first authenticated access and then bound to the OIDC subject.

## Web client
The authenticated web application must store the short-lived access token in its session and send:
Authorization: Bearer <access-token>

The current Smart Import page reads localStorage.assetvalAccessToken as a development/integration bridge. A production Next.js shell should replace this with an HttpOnly-session/OIDC callback flow.

## Production requirements
- Use HTTPS only.
- Keep OIDC client secrets outside Git.
- Use short-lived access tokens and refresh-token rotation.
- Restrict CORS to the production web origin.
- Use a managed secrets store.
- Enable database backups and point-in-time recovery.
- Enable PostgreSQL RLS as a second tenant-isolation layer when finalized.
- Monitor authentication failures and authorization denials.