# Operations runbook

## First startup

1. Copy `.env.example` to `.env`.
2. Generate a unique `SECRET_KEY`, `POSTGRES_PASSWORD` and `ZAP_API_KEY`.
3. Set the true public origin when behind TLS proxy (`APP_ORIGIN=https://security.example.com`).
4. Choose `ALLOW_PRIVATE_TARGETS=false` for ordinary deployments. Enabling it permits local/private destinations and is only suitable for operator-controlled self-hosted installs with tight network isolation.
5. Start with `docker compose up --build -d` and check `docker compose ps` then `docker compose logs -f api worker zap web`.
6. Open the configured web port and register the initial workspace owner. Disable `ALLOW_PUBLIC_SIGNUP` after establishing the intended account lifecycle if appropriate.

## Production reverse proxy

Terminate TLS at a maintained reverse proxy or load balancer. Do not expose API, Redis, PostgreSQL or the ZAP API directly to the internet. Set `APP_ORIGIN` to the exact HTTPS origin and configure trusted proxy forwarding deliberately; do not blindly trust forwarded headers from public clients. The web service is bound to 127.0.0.1 by default for this reason.

## Migrations and backups

- Schema migrations run before the API starts; inspect the migration and backup before upgrading production.
- Take encrypted PostgreSQL backups and regularly execute a restore drill in an isolated environment.
- Back up `.env`/secrets through your secret manager, not into the repository.
- No object-store service is required for this release; large reports/evidence are represented as structured database records. If external artifact storage is added, enforce private buckets and expiring authorized links.

## Troubleshooting

- Scan remains queued: check Redis health and worker logs.
- `completed_with_warnings`: inspect scan `error_summary` and `scanner_versions.zap`; the deterministic safe checks may have succeeded while ZAP was unavailable.
- `Target failed network policy validation`: check DNS, URL scheme, private-address policy and network reachability; do not turn off private-address checks just to bypass a hosted restriction.
- No findings: this profile covers only documented checks. Review the report's limitation list.
- AI rationale missing: expected when `AI_BASE_URL` is unset or the optional provider is unavailable. Deterministic recommendations still work.

## Incidents

Pause worker service to stop new scan execution, preserve relevant logs/scan IDs, rotate credentials if exposed, review audit records, and only resume after the source of unintended traffic or access is understood. Do not delete all evidence before incident analysis.
