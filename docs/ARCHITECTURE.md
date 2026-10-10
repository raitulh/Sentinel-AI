# SentinelAI architecture

## Service boundaries

- **Next.js web**: public marketing pages, authenticated product UI and a same-origin backend proxy. Access tokens are stored in an HttpOnly cookie rather than localStorage.
- **FastAPI control plane**: authentication, organization scoping, project/target management, durable scan state, findings, evidence, remediation proposals, reports and audit actions.
- **PostgreSQL**: canonical durable state. Redis is a broker/result backend, not the source of truth for scan state.
- **Celery scan worker**: a separately deployed process that executes bounded scan workflows and persists normalized results.
- **OWASP ZAP**: internal, API-key protected service. The adapter uses scoped spidering/passive alerts; it intentionally does not call the active scanner.
- **Optional AI provider**: OpenAI-compatible endpoint, including local inference gateways. AI output is advisory and never decides target authorization, executes commands, applies a patch or marks a finding fixed.

## Scan lifecycle

1. User submits a scan against an active project target.
2. API checks organization membership, role, target acknowledgement and network policy.
3. Scan row is committed before the Celery task is enqueued.
4. Worker re-validates DNS/address policy immediately before requesting the target.
5. The safe baseline uses a single GET to the registered URL, no redirect following, bounded timeout and response-header/cookie-flag inspection. Optional ZAP adds a context-bounded spider plus passive scanning.
6. Findings normalize to stable fingerprints and evidence records store sanitized metadata, never cookie values or response bodies.
7. Report endpoint provides explicit profile limitations.

## Deployment profile limits

`self_hosted` puts target authorization and network boundary responsibility on the operator. `hosted` requires DNS TXT ownership verification in this starter and additionally requires infrastructure-enforced egress restrictions, customer/tenant controls, quotas and independent security review before public exposure.

The repository is a production-oriented foundation, not a certification or a claim that every feature is fully audited. The shipped web scanner does not cover all OWASP risks, authenticated application flows, business logic, arbitrary source code, or prove an application secure.
