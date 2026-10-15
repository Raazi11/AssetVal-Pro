# Production deployment checklist

- [ ] Managed PostgreSQL with encryption, backups and point-in-time recovery
- [ ] OIDC provider configured; disable password storage in the API
- [ ] Server-side organization/RBAC authorization on every endpoint
- [ ] Private object storage and short-lived signed URLs
- [ ] HTTPS and secure headers
- [ ] Immutable audit table permissions: application role cannot UPDATE/DELETE audit_events
- [ ] PDF worker/service configured
- [ ] Excel import queue + schema validation + duplicate detection
- [ ] Transactional email provider configured
- [ ] Secrets stored in a secret manager, never committed
- [ ] CI/CD with tests, migrations and vulnerability scanning
- [ ] Monitoring, error tracking and database alerts
- [ ] Web/PWA deployed over HTTPS
- [ ] Windows client packaged from the authenticated web/API build
- [ ] Android client packaged from the authenticated mobile build
