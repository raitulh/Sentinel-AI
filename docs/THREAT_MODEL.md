# Threat model (initial)

## Protected assets

Account sessions, organization/project data, scan authorization, target credentials (none are needed by the base profile), sanitized evidence, remediation records, provider secrets, and scan worker infrastructure.

## Trust boundaries

1. Browser to same-origin Next.js proxy.
2. Next.js proxy to private FastAPI service.
3. FastAPI to PostgreSQL/Redis.
4. Worker to target network and ZAP API.
5. Repository/HTTP content to optional AI provider.
6. User-supplied hostnames and DNS resolution to scan execution.

## Main risks and baseline mitigations

- Cross-tenant object access: organization filters and role checks on API routes; tests should cover every object endpoint.
- SSRF and DNS rebinding: target scheme checks, public-address validation in hosted mode, no redirect following in the built-in checker; network egress policy is still mandatory.
- Scanner blast radius: bounded GET requests, timeouts, worker memory limits, no privileged runtime or host Docker socket, passive-only ZAP profile.
- Credential/evidence leakage: cookie values are not persisted; evidence summaries are length limited; AI input contains summaries and rule context only.
- Prompt injection: supplied web/code text is untrusted; LLM has no tools; schema and policy engine remain authoritative.
- False claims: unverified status remains explicit; missing findings do not equal fixed; report states scope and limitations.
- Queue failures: database row persisted before queue send; worker task ID matches scan ID; periodic operational recovery still needs monitoring in production.

## Release blockers for public multi-tenant hosted use

- Add robust Redis-backed rate limiting and abuse prevention.
- Add resolver/IP pinning or egress proxy that enforces host-to-IP bindings and revalidates each connection.
- Configure Kubernetes/runner network policies and per-job CPU/memory/PID/filesystem quotas.
- Add domain verification tests, expiry and scope-change invalidation.
- Implement complete membership invitation lifecycle, email verification, password reset, MFA/SSO and session revocation policy.
- Add external append-only audit sink, tested retention/deletion workflows, threat-model review and independent penetration test.
- Pin every production container image by digest and monitor advisories.
