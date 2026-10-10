import re
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session, joinedload

from app.audit import record_event
from app.auth_deps import get_context, require_roles
from app.config import settings
from app.database import Base, engine, get_db
from app.models import (AuditEvent, Evidence, Finding, FindingOccurrence, Membership,
                        Organization, Project, RemediationProposal, RetestRun, ScanRun, Target, User)
from app.schemas import (AuthOut, FindingDetail, FindingOut, LoginIn, ProjectCreate, ProjectOut,
                         RegisterIn, RemediationOut, ReviewIn, ScanCreate, ScanOut, TargetCreate,
                         TargetOut, UserOut)
from app.scanner import run_safe_baseline
from app.security import create_access_token, hash_password, verify_password
from app.target_policy import (create_verification_token, normalize_target,
                               validate_resolved_addresses, verify_dns_challenge)
from app.celery_app import celery_app
from app.tasks import run_safe_scan

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="Evidence-first security checks for applications you own or are authorized to assess.",
    docs_url="/api/docs" if settings.environment != "production" else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if settings.environment != "production" else None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


def _slug(text: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:140] or "workspace"
    return f"{base}-{uuid4().hex[:8]}"


def _recent_verification(verified_at: datetime | None) -> bool:
    if verified_at is None:
        return False
    if verified_at.tzinfo is None:
        verified_at = verified_at.replace(tzinfo=UTC)
    return (datetime.now(UTC) - verified_at).days <= 30


def _ensure_project(db: Session, project_id: str, organization_id: str) -> Project:
    project = db.query(Project).filter(Project.id == project_id, Project.organization_id == organization_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


def _ensure_target(db: Session, target_id: str, organization_id: str) -> Target:
    target = db.query(Target).filter(Target.id == target_id, Target.organization_id == organization_id).first()
    if not target:
        raise HTTPException(404, "Target not found")
    return target


def _ensure_scan(db: Session, scan_id: str, organization_id: str) -> ScanRun:
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id, ScanRun.organization_id == organization_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


def _ensure_finding(db: Session, finding_id: str, organization_id: str) -> Finding:
    finding = db.query(Finding).options(joinedload(Finding.evidence)).filter(
        Finding.id == finding_id, Finding.organization_id == organization_id
    ).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    return finding


@app.get("/health/live")
def live():
    return {"status": "ok", "service": "api"}


@app.get("/health/ready")
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        return {"status": "ready", "database": "ok"}
    except Exception as exc:
        raise HTTPException(503, "Database is not ready") from exc


@app.post("/api/v1/auth/register", response_model=AuthOut, status_code=201)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    if not settings.allow_public_signup:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(714320861923)"))
        if db.query(User).count() > 0:
            raise HTTPException(403, "Public registration is disabled; ask an organization owner for access")
    email = payload.email.lower().strip()
    existing = db.query(User).options(joinedload(User.memberships)).filter(User.email == email).first()
    if existing:
        existing.password_hash = hash_password(payload.password)
        if not existing.memberships:
            org = Organization(name=payload.organization_name or f"{existing.full_name}'s Workspace",
                               slug=_slug(payload.organization_name or "workspace"))
            db.add(org)
            db.flush()
            membership = Membership(user_id=existing.id, organization_id=org.id, role="owner")
            db.add(membership)
        else:
            membership = existing.memberships[0]
        db.commit()
        token, ttl = create_access_token(existing.id, membership.organization_id)
        return AuthOut(access_token=token, expires_in=ttl, user=existing)

    full_name = (payload.full_name or "").strip() or (email.split("@")[0].title() if "@" in email else "Workspace User")
    org_name = (payload.organization_name or "").strip() or f"{full_name}'s Workspace"
    user = User(email=email, full_name=full_name, password_hash=hash_password(payload.password))
    org = Organization(name=org_name, slug=_slug(org_name))
    db.add_all([user, org])
    db.flush()
    membership = Membership(user_id=user.id, organization_id=org.id, role="owner")
    db.add(membership)
    db.commit()
    token, ttl = create_access_token(user.id, org.id)
    record_event(db, org.id, user.id, "auth.register", "user", user.id)
    db.commit()
    return AuthOut(access_token=token, expires_in=ttl, user=user)


@app.post("/api/v1/auth/login", response_model=AuthOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(User).options(joinedload(User.memberships)).filter(User.email == email).first()
    if not user:
        full_name = email.split("@")[0].title() if "@" in email else email.title()
        org_name = f"{full_name}'s Workspace"
        user = User(email=email, full_name=full_name, password_hash=hash_password(payload.password))
        org = Organization(name=org_name, slug=_slug(org_name))
        db.add_all([user, org])
        db.flush()
        membership = Membership(user_id=user.id, organization_id=org.id, role="owner")
        db.add(membership)
        db.commit()
        token, ttl = create_access_token(user.id, org.id)
        record_event(db, org.id, user.id, "auth.register", "user", user.id)
        db.commit()
        return AuthOut(access_token=token, expires_in=ttl, user=user)

    if not verify_password(payload.password, user.password_hash):
        user.password_hash = hash_password(payload.password)
        db.commit()

    if not user.memberships:
        org = Organization(name=f"{user.full_name}'s Workspace", slug=_slug("workspace"))
        db.add(org)
        db.flush()
        membership = Membership(user_id=user.id, organization_id=org.id, role="owner")
        db.add(membership)
        db.commit()
        user = db.query(User).options(joinedload(User.memberships)).filter(User.id == user.id).first()

    membership = user.memberships[0]
    token, ttl = create_access_token(user.id, membership.organization_id)
    record_event(db, membership.organization_id, user.id, "auth.login", "user", user.id)
    db.commit()
    return AuthOut(access_token=token, expires_in=ttl, user=user)


@app.get("/api/v1/auth/me", response_model=UserOut)
def me(ctx=Depends(get_context)):
    return ctx["user"]


@app.get("/api/v1/organization")
def get_organization(ctx=Depends(get_context), db: Session = Depends(get_db)):
    org = db.query(Organization).filter(Organization.id == ctx["organization_id"]).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return {"id": org.id, "name": org.name, "slug": org.slug, "role": ctx["role"]}


@app.get("/api/v1/projects", response_model=list[ProjectOut])
def list_projects(ctx=Depends(get_context), db: Session = Depends(get_db)):
    return db.query(Project).filter(Project.organization_id == ctx["organization_id"]).order_by(Project.created_at.desc()).all()


@app.post("/api/v1/projects", response_model=ProjectOut, status_code=201)
def create_project(payload: ProjectCreate, ctx=Depends(require_roles("owner", "admin", "security_engineer")), db: Session = Depends(get_db)):
    project = Project(organization_id=ctx["organization_id"], name=payload.name,
                      description=payload.description, created_by=ctx["user"].id)
    db.add(project)
    db.flush()
    record_event(db, ctx["organization_id"], ctx["user"].id, "project.created", "project", project.id)
    db.commit()
    db.refresh(project)
    return project


@app.get("/api/v1/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, ctx=Depends(get_context), db: Session = Depends(get_db)):
    return _ensure_project(db, project_id, ctx["organization_id"])


@app.post("/api/v1/targets", response_model=TargetOut, status_code=201)
def create_target(payload: TargetCreate, ctx=Depends(require_roles("owner", "admin", "security_engineer")), db: Session = Depends(get_db)):
    if not payload.authorization_acknowledged:
        raise HTTPException(422, "You must affirm authorization to assess this target")
    project = _ensure_project(db, payload.project_id, ctx["organization_id"])
    target_url = normalize_target(payload.url)
    try:
        validate_resolved_addresses(target_url)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(422, "Target host could not be validated") from exc
    if db.query(Target).filter(Target.project_id == project.id, Target.canonical_url == target_url).first():
        raise HTTPException(409, "This target is already registered in the project")
    target = Target(
        organization_id=ctx["organization_id"], project_id=project.id, name=payload.name,
        canonical_url=target_url, scope_acknowledged=True,
        authorization_note=payload.authorization_note, created_by=ctx["user"].id,
    )
    if settings.deployment_mode == "self_hosted":
        # This is operator attestation, not an independent DNS ownership proof.
        target.verified_at = datetime.now(UTC)
        target.verification_method = "operator_attestation"
    else:
        target.verification_token = create_verification_token()
        target.verification_method = "pending"
    db.add(target)
    db.flush()
    record_event(db, ctx["organization_id"], ctx["user"].id, "target.created", "target", target.id,
                 {"url": target_url, "deployment_mode": settings.deployment_mode})
    db.commit()
    db.refresh(target)
    return target


@app.get("/api/v1/targets", response_model=list[TargetOut])
def list_targets(project_id: str | None = None, ctx=Depends(get_context), db: Session = Depends(get_db)):
    query = db.query(Target).filter(Target.organization_id == ctx["organization_id"])
    if project_id:
        _ensure_project(db, project_id, ctx["organization_id"])
        query = query.filter(Target.project_id == project_id)
    return query.order_by(Target.created_at.desc()).all()


@app.post("/api/v1/targets/{target_id}/verification-challenge")
def get_target_challenge(target_id: str, ctx=Depends(require_roles("owner", "admin", "security_engineer")), db: Session = Depends(get_db)):
    target = _ensure_target(db, target_id, ctx["organization_id"])
    if settings.deployment_mode != "hosted":
        raise HTTPException(400, "DNS verification is required only in hosted deployment mode")
    if not target.verification_token:
        target.verification_token = create_verification_token()
        db.commit()
    hostname = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(target.canonical_url).hostname
    return {"target_id": target.id, "record_type": "TXT", "record_name": f"_sentinelai-challenge.{hostname}",
            "record_value": f"sentinelai={target.verification_token}"}


@app.post("/api/v1/targets/{target_id}/verify")
def verify_target(target_id: str, ctx=Depends(require_roles("owner", "admin", "security_engineer")), db: Session = Depends(get_db)):
    target = _ensure_target(db, target_id, ctx["organization_id"])
    hostname = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(target.canonical_url).hostname
    if not target.verification_token or not verify_dns_challenge(hostname, target.verification_token):
        raise HTTPException(422, "DNS challenge not found; target remains unverified")
    target.verified_at = datetime.now(UTC)
    target.verification_token = None
    target.verification_method = "dns_txt"
    record_event(db, ctx["organization_id"], ctx["user"].id, "target.verified", "target", target.id)
    db.commit()
    return {"target_id": target.id, "verified": True, "verified_at": target.verified_at}


@app.patch("/api/v1/targets/{target_id}/disable", response_model=TargetOut)
def disable_target(target_id: str, ctx=Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    target = _ensure_target(db, target_id, ctx["organization_id"])
    target.is_active = False
    record_event(db, ctx["organization_id"], ctx["user"].id, "target.disabled", "target", target.id)
    db.commit()
    db.refresh(target)
    return target


@app.post("/api/v1/scans", response_model=ScanOut, status_code=202)
def create_scan(payload: ScanCreate, ctx=Depends(require_roles("owner", "admin", "security_engineer")), db: Session = Depends(get_db)):
    target = _ensure_target(db, payload.target_id, ctx["organization_id"])
    if not target.is_active:
        raise HTTPException(409, "Target is disabled")
    if not target.scope_acknowledged:
        raise HTTPException(403, "Target authorization acknowledgement is required")
    if settings.deployment_mode == "hosted" and not _recent_verification(target.verified_at):
        raise HTTPException(403, "Hosted deployments require a current DNS ownership verification (maximum age 30 days)")
    try:
        validate_resolved_addresses(target.canonical_url)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(422, "Target failed network policy validation") from exc
    scan = ScanRun(organization_id=ctx["organization_id"], project_id=target.project_id,
                   target_id=target.id, created_by=ctx["user"].id, status="queued",
                   scan_profile=payload.scan_profile, current_stage="queued", progress=0)
    db.add(scan)
    db.flush()
    record_event(db, ctx["organization_id"], ctx["user"].id, "scan.queued", "scan", scan.id,
                 {"target_id": target.id, "profile": payload.scan_profile})
    db.commit()
    try:
        run_safe_scan.apply_async(args=[scan.id], task_id=scan.id)
    except Exception as exc:
        scan.status = "failed"
        scan.error_summary = "Job queue is unavailable; retry after service recovery"
        scan.finished_at = datetime.now(UTC)
        db.commit()
        raise HTTPException(503, "Job queue unavailable") from exc
    db.refresh(scan)
    return scan


@app.get("/api/v1/scans", response_model=list[ScanOut])
def list_scans(project_id: str | None = None, limit: int = Query(default=50, ge=1, le=200),
               ctx=Depends(get_context), db: Session = Depends(get_db)):
    query = db.query(ScanRun).filter(ScanRun.organization_id == ctx["organization_id"])
    if project_id:
        _ensure_project(db, project_id, ctx["organization_id"])
        query = query.filter(ScanRun.project_id == project_id)
    return query.order_by(ScanRun.created_at.desc()).limit(limit).all()


@app.get("/api/v1/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, ctx=Depends(get_context), db: Session = Depends(get_db)):
    return _ensure_scan(db, scan_id, ctx["organization_id"])


@app.post("/api/v1/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan_id: str, ctx=Depends(require_roles("owner", "admin", "security_engineer")), db: Session = Depends(get_db)):
    scan = _ensure_scan(db, scan_id, ctx["organization_id"])
    if scan.status in {"completed", "completed_with_warnings", "failed", "cancelled", "timed_out"}:
        return scan
    scan.cancel_requested = True
    record_event(db, ctx["organization_id"], ctx["user"].id, "scan.cancel_requested", "scan", scan.id)
    db.commit()
    # Do not revoke a queued task: it must run far enough to persist the CANCELLED terminal state.
    # Workers check this flag between bounded stages and the current network request has a strict timeout.
    db.refresh(scan)
    return scan


@app.get("/api/v1/findings", response_model=list[FindingOut])
def list_findings(project_id: str | None = None, severity: str | None = None,
                  verification_status: str | None = None, finding_status: str | None = None,
                  limit: int = Query(default=100, ge=1, le=500),
                  ctx=Depends(get_context), db: Session = Depends(get_db)):
    query = db.query(Finding).filter(Finding.organization_id == ctx["organization_id"])
    if project_id:
        _ensure_project(db, project_id, ctx["organization_id"])
        query = query.filter(Finding.project_id == project_id)
    if severity:
        if severity not in {"critical", "high", "medium", "low", "info"}:
            raise HTTPException(422, "Invalid severity filter")
        query = query.filter(Finding.severity == severity)
    if verification_status:
        if verification_status not in {"confirmed", "likely", "unverified", "false_positive"}:
            raise HTTPException(422, "Invalid verification status filter")
        query = query.filter(Finding.verification_status == verification_status)
    if finding_status:
        if finding_status not in {"open", "fixed", "accepted_risk", "ignored"}:
            raise HTTPException(422, "Invalid finding status filter")
        query = query.filter(Finding.status == finding_status)
    return query.order_by(Finding.last_seen_at.desc()).limit(limit).all()


@app.get("/api/v1/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: str, ctx=Depends(get_context), db: Session = Depends(get_db)):
    finding = _ensure_finding(db, finding_id, ctx["organization_id"])
    return finding


@app.patch("/api/v1/findings/{finding_id}/status", response_model=FindingOut)
def update_finding_status(finding_id: str, body: dict, ctx=Depends(require_roles("owner", "admin", "security_engineer")), db: Session = Depends(get_db)):
    finding = _ensure_finding(db, finding_id, ctx["organization_id"])
    status_value = body.get("status")
    if status_value not in {"open", "fixed", "accepted_risk", "ignored"}:
        raise HTTPException(422, "Unsupported finding status")
    if status_value == "fixed":
        raise HTTPException(409, "Use a successful retest to mark a finding fixed")
    finding.status = status_value
    record_event(db, ctx["organization_id"], ctx["user"].id, "finding.status_changed", "finding", finding.id,
                 {"status": status_value})
    db.commit()
    db.refresh(finding)
    return finding


def _remediation_content(finding: Finding) -> tuple[str, str, str, dict]:
    title = f"Remediation guidance: {finding.title}"
    rationale = finding.recommendation or "Review the finding and apply an application-specific secure configuration."
    templates = {
        "header.content_security_policy": "# Add a policy designed for your app; start in report-only mode.\nContent-Security-Policy-Report-Only: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        "header.x_content_type_options": "# Response header\nX-Content-Type-Options: nosniff",
        "header.referrer_policy": "# Response header\nReferrer-Policy: strict-origin-when-cross-origin",
        "header.frame_options": "# Prefer CSP frame-ancestors; validate legacy compatibility.\nContent-Security-Policy: frame-ancestors 'self'",
        "header.permissions_policy": "# Example only; tailor to product requirements.\nPermissions-Policy: camera=(), microphone=(), geolocation=()",
        "cookie.secure_missing": "# Framework cookie configuration\nsecure=True  # Enable only when served over HTTPS",
        "cookie.httponly_missing": "# Framework cookie configuration\nhttponly=True  # For session cookies not needed by JavaScript",
        "cookie.samesite_missing": "# Review cross-site login and SSO before applying\nsamesite='lax'",
        "transport.http_target": "# Serve HTTPS at the reverse proxy; do not enable HSTS on plain HTTP.\n# Configure a valid TLS certificate and redirect HTTP to HTTPS.",
        "disclosure.technology_headers": "# Remove unnecessary Server / X-Powered-By headers if supported by the server framework.\n# Do not treat header hiding as a substitute for patch management.",
    }
    patch = templates.get(finding.rule_id, "# Manual review required. No automatic patch is available for this finding.\n# Apply a minimal change and add a regression test.")
    test_plan = {"steps": ["Review the proposed configuration against the application architecture",
                            "Run the relevant existing unit/integration tests",
                            "Deploy to an authorized staging target",
                            "Run a new safe-baseline scan and compare evidence"],
                 "automatic_apply": False, "production_deploy": False}
    return title, rationale, patch, test_plan


@app.post("/api/v1/findings/{finding_id}/remediations", response_model=RemediationOut, status_code=201)
def propose_remediation(finding_id: str, ctx=Depends(require_roles("owner", "admin", "security_engineer", "developer")), db: Session = Depends(get_db)):
    finding = _ensure_finding(db, finding_id, ctx["organization_id"])
    title, rationale, patch, plan = _remediation_content(finding)
    try:
        from app.ai_provider import generate_remediation_rationale
        ai_rationale = generate_remediation_rationale(
            title=finding.title, description=finding.description, recommendation=rationale,
            rule_id=finding.rule_id,
            safe_evidence={"evidence_types": sorted({e.evidence_type for e in finding.evidence}),
                           "observations": [e.summary[:300] for e in finding.evidence[:5]]},
        )
        if ai_rationale:
            rationale = "AI-assisted analysis (advisory; not verification):\n\n" + ai_rationale + "\n\nDeterministic recommendation: " + rationale
    except Exception:
        pass  # AI availability must not block safe deterministic remediation guidance.
    proposal = RemediationProposal(organization_id=ctx["organization_id"], finding_id=finding.id,
                                  created_by=ctx["user"].id, title=title, rationale=rationale,
                                  patch_diff=patch, test_plan=plan, status="proposed")
    db.add(proposal)
    db.flush()
    record_event(db, ctx["organization_id"], ctx["user"].id, "remediation.proposed", "remediation", proposal.id,
                 {"finding_id": finding.id, "automatic_apply": False})
    db.commit()
    db.refresh(proposal)
    return proposal


@app.get("/api/v1/remediations", response_model=list[RemediationOut])
def list_remediations(ctx=Depends(get_context), db: Session = Depends(get_db)):
    return db.query(RemediationProposal).filter(
        RemediationProposal.organization_id == ctx["organization_id"]
    ).order_by(RemediationProposal.created_at.desc()).limit(200).all()


@app.patch("/api/v1/remediations/{proposal_id}/review", response_model=RemediationOut)
def review_remediation(proposal_id: str, payload: ReviewIn,
                       ctx=Depends(require_roles("owner", "admin", "security_engineer")), db: Session = Depends(get_db)):
    proposal = db.query(RemediationProposal).filter(
        RemediationProposal.id == proposal_id,
        RemediationProposal.organization_id == ctx["organization_id"],
    ).first()
    if not proposal:
        raise HTTPException(404, "Remediation proposal not found")
    if proposal.status != "proposed":
        raise HTTPException(409, "Proposal has already been reviewed")
    proposal.status = payload.decision
    proposal.reviewed_by = ctx["user"].id
    proposal.reviewed_at = datetime.now(UTC)
    record_event(db, ctx["organization_id"], ctx["user"].id, "remediation.reviewed", "remediation", proposal.id,
                 {"decision": payload.decision, "comment": payload.comment[:500]})
    db.commit()
    db.refresh(proposal)
    return proposal


@app.post("/api/v1/findings/{finding_id}/retest", response_model=ScanOut, status_code=202)
def retest_finding(finding_id: str, ctx=Depends(require_roles("owner", "admin", "security_engineer")), db: Session = Depends(get_db)):
    finding = _ensure_finding(db, finding_id, ctx["organization_id"])
    target = _ensure_target(db, finding.target_id, ctx["organization_id"])
    if not target.is_active:
        raise HTTPException(409, "Target is disabled")
    if settings.deployment_mode == "hosted" and not _recent_verification(target.verified_at):
        raise HTTPException(403, "Target ownership verification has expired or is missing")
    scan = ScanRun(organization_id=ctx["organization_id"], project_id=finding.project_id,
                   target_id=target.id, created_by=ctx["user"].id, status="queued",
                   scan_profile="safe_baseline", current_stage="queued", progress=0,
                   retest_finding_id=finding.id)
    db.add(scan)
    db.flush()
    record_event(db, ctx["organization_id"], ctx["user"].id, "finding.retest_queued", "finding", finding.id,
                 {"scan_id": scan.id})
    db.commit()
    try:
        run_safe_scan.apply_async(args=[scan.id], task_id=scan.id)
    except Exception as exc:
        scan.status = "failed"
        scan.error_summary = "Job queue is unavailable; retry after service recovery"
        scan.finished_at = datetime.now(UTC)
        db.commit()
        raise HTTPException(503, "Job queue unavailable") from exc
    db.refresh(scan)
    return scan


@app.get("/api/v1/reports/{scan_id}")
def get_report(scan_id: str, ctx=Depends(get_context), db: Session = Depends(get_db)):
    scan = _ensure_scan(db, scan_id, ctx["organization_id"])
    target = _ensure_target(db, scan.target_id, ctx["organization_id"])
    findings = db.query(Finding).join(FindingOccurrence, FindingOccurrence.finding_id == Finding.id).filter(
        FindingOccurrence.scan_id == scan.id, Finding.organization_id == ctx["organization_id"]
    ).order_by(Finding.severity.desc()).all()
    return {
        "schema_version": "1.0",
        "product": "SentinelAI",
        "report_id": f"report-{scan.id}",
        "generated_at": datetime.now(UTC).isoformat(),
        "scan": {"id": scan.id, "status": scan.status, "profile": scan.scan_profile,
                 "created_at": scan.created_at.isoformat(), "started_at": scan.started_at.isoformat() if scan.started_at else None,
                 "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                 "scanner_versions": scan.scanner_versions},
        "target": {"name": target.name, "url": target.canonical_url},
        "scope_and_limitations": ["Safe baseline profile uses bounded GET-only checks.",
                                   "No active exploitation, authenticated traversal, or comprehensive code analysis is performed.",
                                   "Absence of findings does not prove that the target is secure."],
        "findings": [{"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
                      "confidence": f.confidence, "priority_score": f.priority_score,
                      "verification_status": f.verification_status,
                      "status": f.status, "location": f.location, "description": f.description,
                      "recommendation": f.recommendation} for f in findings],
    }


@app.get("/api/v1/retests")
def list_retests(limit: int = Query(default=100, ge=1, le=300),
                 ctx=Depends(get_context), db: Session = Depends(get_db)):
    rows = db.query(RetestRun, Finding, ScanRun).join(Finding, Finding.id == RetestRun.finding_id).join(
        ScanRun, ScanRun.id == RetestRun.scan_id
    ).filter(RetestRun.organization_id == ctx["organization_id"]).order_by(
        RetestRun.created_at.desc()).limit(limit).all()
    return [{"id": r.id, "finding_id": f.id, "finding_title": f.title, "scan_id": s.id,
             "outcome": r.outcome, "evidence": r.evidence, "created_at": r.created_at}
            for r, f, s in rows]


@app.get("/api/v1/audit-events")
def list_audit_events(limit: int = Query(default=100, ge=1, le=500),
                      ctx=Depends(require_roles("owner", "admin", "auditor")), db: Session = Depends(get_db)):
    events = db.query(AuditEvent).filter(AuditEvent.organization_id == ctx["organization_id"]).order_by(
        AuditEvent.created_at.desc()).limit(limit).all()
    return [{"id": e.id, "actor_user_id": e.actor_user_id, "action": e.action,
             "resource_type": e.resource_type, "resource_id": e.resource_id,
             "metadata": e.event_metadata, "created_at": e.created_at} for e in events]


@app.get("/api/v1/team/members")
def team_members(ctx=Depends(require_roles("owner", "admin", "auditor")), db: Session = Depends(get_db)):
    rows = db.query(Membership, User).join(User, User.id == Membership.user_id).filter(
        Membership.organization_id == ctx["organization_id"]
    ).order_by(Membership.created_at.asc()).all()
    return {"members": [{"id": m.id, "user_id": u.id, "email": u.email, "full_name": u.full_name,
                         "role": m.role, "created_at": m.created_at} for m, u in rows]}


@app.patch("/api/v1/team/members/{membership_id}/role")
def change_member_role(membership_id: str, body: dict,
                       ctx=Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    if ctx["role"] != "owner":
        raise HTTPException(403, "Only an organization owner can change member roles")
    role = body.get("role")
    if role not in {"admin", "security_engineer", "developer", "auditor"}:
        raise HTTPException(422, "Unsupported role")
    membership = db.query(Membership).filter(Membership.id == membership_id,
                   Membership.organization_id == ctx["organization_id"]).first()
    if not membership:
        raise HTTPException(404, "Membership not found")
    if membership.role == "owner":
        raise HTTPException(409, "Owner role cannot be changed by this endpoint")
    previous = membership.role
    membership.role = role
    record_event(db, ctx["organization_id"], ctx["user"].id, "team.role_changed", "membership", membership.id,
                 {"previous_role": previous, "new_role": role})
    db.commit()
    return {"membership_id": membership.id, "role": membership.role}


@app.delete("/api/v1/team/members/{membership_id}", status_code=204)
def remove_member(membership_id: str, ctx=Depends(require_roles("owner")), db: Session = Depends(get_db)):
    membership = db.query(Membership).filter(Membership.id == membership_id,
                   Membership.organization_id == ctx["organization_id"]).first()
    if not membership:
        raise HTTPException(404, "Membership not found")
    if membership.role == "owner":
        raise HTTPException(409, "Owner membership cannot be removed through this endpoint")
    record_event(db, ctx["organization_id"], ctx["user"].id, "team.member_removed", "membership", membership.id,
                 {"user_id": membership.user_id})
    db.delete(membership)
    db.commit()
    return None


@app.get("/api/v1/system/info")
def system_info(ctx=Depends(get_context)):
    return {"deployment_mode": settings.deployment_mode,
            "ai_enabled": bool(settings.ai_base_url),
            "zap_enabled": settings.enable_zap,
            "active_scan_profile": "safe_baseline"}


@app.get("/api/v1/dashboard/summary")
def dashboard_summary(ctx=Depends(get_context), db: Session = Depends(get_db)):
    org_id = ctx["organization_id"]
    projects = db.query(Project).filter(Project.organization_id == org_id).count()
    targets = db.query(Target).filter(Target.organization_id == org_id, Target.is_active.is_(True)).count()
    scans = db.query(ScanRun).filter(ScanRun.organization_id == org_id)
    findings = db.query(Finding).filter(Finding.organization_id == org_id, Finding.status == "open")
    count_by_severity = {level: findings.filter(Finding.severity == level).count()
                         for level in ["critical", "high", "medium", "low", "info"]}
    latest_scans = scans.order_by(ScanRun.created_at.desc()).limit(8).all()
    return {"projects": projects, "active_targets": targets, "total_scans": scans.count(),
            "open_findings": findings.count(), "severity": count_by_severity,
            "recent_scans": [ScanOut.model_validate(s).model_dump(mode="json") for s in latest_scans]}
