# API overview

Base path: `/api/v1`. Authenticated requests use `Authorization: Bearer <token>`; the Next.js app proxies requests using an HttpOnly cookie.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/auth/register` | Create user + owner organization (if signup enabled) |
| `POST` | `/auth/login` | Authenticate and issue an expiring bearer token |
| `GET` | `/auth/me` | Current account |
| `GET/POST` | `/projects` | List/create projects |
| `GET` | `/projects/{id}` | Read a project within the current organization |
| `GET/POST` | `/targets` | List/register authorized target records |
| `POST` | `/targets/{id}/verification-challenge` | Retrieve hosted DNS TXT challenge |
| `POST` | `/targets/{id}/verify` | Verify DNS proof |
| `PATCH` | `/targets/{id}/disable` | Disable a target |
| `GET/POST` | `/scans` | List/queue bounded safe-baseline scans |
| `GET` | `/scans/{id}` | Scan progress/status |
| `POST` | `/scans/{id}/cancel` | Persist cancellation request |
| `GET` | `/findings` | Filter findings by project/severity/status/verification |
| `GET` | `/findings/{id}` | Finding evidence/history context |
| `PATCH` | `/findings/{id}/status` | Change non-fixed workflow state |
| `POST` | `/findings/{id}/remediations` | Create manual remediation proposal |
| `GET` | `/remediations` | List proposals |
| `PATCH` | `/remediations/{id}/review` | Approve/reject a proposal (records review only) |
| `POST` | `/findings/{id}/retest` | Queue a finding-specific safe-baseline retest |
| `GET` | `/retests` | Retest outcomes |
| `GET` | `/reports/{scan_id}` | Structured JSON report |
| `GET` | `/audit-events` | Organization audit events, privileged roles only |
| `GET` | `/team/members` | List organization members |
| `PATCH/DELETE` | `/team/members/{id}/role` / `/team/members/{id}` | Owner-controlled role/remove operations |
| `GET` | `/system/info` | Deployment mode and enabled optional layers |
| `GET` | `/dashboard/summary` | Dashboard counts and recent jobs |

## API rules

- All organization data endpoints derive organization context from the signed token and current membership.
- `fixed` cannot be set using the finding-status endpoint; supported rule-specific retest logic must record the outcome.
- Remediation approval does not apply a patch or deploy code.
- The safe baseline does not submit exploit payloads or follow redirects. Optional ZAP calls the spider/passive APIs only.
- Report limitations are always included; no finding result implies comprehensive coverage.
