# AssetVal Pro — Production Cloud Edition

## Architecture
- **Web:** Next.js / TypeScript target architecture
- **API:** Node.js service with PostgreSQL
- **Auth:** OIDC/OAuth2 + short-lived sessions; organization membership and RBAC
- **Storage:** S3-compatible object storage with signed URLs
- **Audit:** append-only hash-chained audit events
- **PDF:** server-side PDF generation
- **Excel:** validated import pipeline with duplicate/field checks
- **Email:** transactional email provider integration
- **Clients:** responsive Web/PWA, Windows desktop wrapper, Android wrapper

## Security model
Tenant isolation is mandatory: every company-owned record carries an organization/company ID and is authorized server-side. Never trust client-side role checks.

Recommended roles:
- Organization Owner
- Administrator
- Asset Manager
- Auditor
- Approver
- Viewer

## Data model
Core tables: organizations, users, memberships, assets, locations, custodians, vendors, asset_transfers, approvals, attachments, service_records, depreciation_snapshots, audit_events, notifications, report_jobs.

## Immutable audit log
Each audit event stores event ID, organization ID, actor, action, entity, entity ID, timestamp, metadata hash, previous hash and current hash. Events are append-only; updates/deletes are prohibited by database policy.

## Production deployment
Use managed PostgreSQL, private object storage, HTTPS, secret management, automated migrations, backups, monitoring and CI/CD. Windows and Android clients consume the same authenticated HTTPS API.

This repository currently contains the browser-first v0.x implementation. This document is the production architecture contract; the cloud backend must be deployed before production credentials or customer data are used.
