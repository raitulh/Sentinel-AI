# Build and validation record

This is an honest record of checks performed in the code-generation environment. It is not a production certification.

## Checks completed

- Standard backend run without Celery installed: **12 passed, 1 skipped**. The skipped module contains API integration smoke tests and is guarded by `pytest.importorskip("celery")`.
- Additional API integration run with a temporary, test-only no-op Celery shim: **14 passed**, including registration, project creation, authentication, first-owner signup gating and organization isolation. This does not validate a real Redis/Celery broker or execute scan jobs.
- Python `compileall`: passed.
- Backend wheel packaging (`pip wheel --no-deps --no-build-isolation`): passed.
- TypeScript/TSX syntax transpilation: 31 files checked, zero syntax diagnostics (syntax only; not a full typecheck). This is a syntax check, not a full TypeScript typecheck.
- Docker Compose, policy YAML and CI YAML parsed successfully.
- In-memory SQLAlchemy schema creation passed. Explicit initial Alembic migration was upgraded, checked for model drift (`alembic check`), downgraded, and re-upgraded on a fresh SQLite database. Risk-scoring tests cover score bounds, relative severity ordering, confidence weighting, and invalid inputs. The API smoke test also surfaced and helped resolve the ambiguous `Finding.scan` ORM relationship.

## Not run here

- `npm install`, full `tsc --noEmit`, ESLint and `next build`: package registry access was unavailable, so frontend dependencies could not be installed.
- Docker image build or compose startup: Docker CLI/daemon was not available.
- PostgreSQL/Celery/ZAP end-to-end scan with real services, restore drills, concurrency/failure-injection, broad scanner evaluation, or an independent penetration test.

## Release gates

Before any internet-facing hosted deployment, use the [Operations](OPERATIONS.md) and [Threat Model](THREAT_MODEL.md) docs as required gates. In particular, enforce network egress restrictions at the scan runner, pin container images and dependency lockfiles, configure secrets and backups, add identity hardening/rate limiting, run the full CI pipeline, and commission an independent security review.
