import hashlib
import logging
from datetime import UTC, datetime

from sqlalchemy.exc import IntegrityError

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Evidence, Finding, FindingOccurrence, RetestRun, ScanRun, Target
from app.risk import calculate_priority_score
from app.scanner import run_safe_baseline
from app.target_policy import validate_resolved_addresses
from app.zap_adapter import run_zap_passive, ZapUnavailable
from app.config import settings

logger = logging.getLogger("sentinelai.worker")


def _digest(data: dict) -> str:
    import json
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _set_progress(db, scan, status: str, stage: str, progress: int):
    scan.status = status
    scan.current_stage = stage
    scan.progress = progress
    db.commit()


@celery_app.task(bind=True, name="sentinelai.run_safe_scan", acks_late=True)
def run_safe_scan(self, scan_id: str):
    db = SessionLocal()
    try:
        scan = db.query(ScanRun).filter(ScanRun.id == scan_id).with_for_update().first()
        if not scan or scan.status in {"cancelled", "completed", "failed", "timed_out"}:
            return {"scan_id": scan_id, "status": "ignored"}
        target = db.query(Target).filter(Target.id == scan.target_id, Target.organization_id == scan.organization_id).first()
        if not target or not target.is_active:
            scan.status = "failed"
            scan.error_summary = "Target is unavailable or disabled"
            scan.finished_at = datetime.now(UTC)
            db.commit()
            return {"scan_id": scan_id, "status": "failed"}
        scan.status = "running"
        scan.current_stage = "policy_validation"
        scan.progress = 5
        scan.started_at = datetime.now(UTC)
        db.commit()

        # Target policy is checked at job execution, not only at registration time.
        try:
            validate_resolved_addresses(target.canonical_url)
        except Exception as exc:
            scan.status = "failed"
            scan.error_summary = f"Target policy validation failed ({type(exc).__name__}); details suppressed"
            scan.finished_at = datetime.now(UTC)
            db.commit()
            return {"scan_id": scan_id, "status": "failed"}

        if scan.cancel_requested:
            scan.status, scan.current_stage = "cancelled", "cancelled"
            scan.finished_at = datetime.now(UTC)
            db.commit()
            return {"scan_id": scan_id, "status": "cancelled"}

        _set_progress(db, scan, "running", "safe_baseline_checks", 20)
        try:
            results, summary = run_safe_baseline(target.canonical_url)
        except Exception as exc:
            scan.status = "failed"
            scan.current_stage = "failed"
            scan.error_summary = str(exc)[:500]
            scan.finished_at = datetime.now(UTC)
            db.commit()
            logger.warning("scan_failed scan_id=%s error_type=%s", scan_id, type(exc).__name__)
            return {"scan_id": scan_id, "status": "failed"}

        warnings = []
        zap_summary = {"enabled": settings.enable_zap, "status": "not_run"}
        if settings.enable_zap and scan.cancel_requested:
            scan.status, scan.current_stage = "cancelled", "cancelled"
            scan.finished_at = datetime.now(UTC)
            db.commit()
            return {"scan_id": scan_id, "status": "cancelled"}
        if settings.enable_zap:
            _set_progress(db, scan, "running", "zap_passive_scan", 45)
            try:
                zap_findings, zap_summary = run_zap_passive(target.canonical_url, settings.scan_max_pages,
                                                           min(settings.scan_timeout_seconds, 180))
                results.extend(zap_findings)
                if zap_summary.get("status") != "completed":
                    warnings.append("ZAP passive scan did not finish cleanly")
            except ZapUnavailable as exc:
                warnings.append(str(exc))
                zap_summary = {"enabled": True, "status": "unavailable", "warning": str(exc)}
            except Exception as exc:
                warnings.append(f"ZAP passive scan failed ({type(exc).__name__})")
                zap_summary = {"enabled": True, "status": "failed"}

        db.refresh(scan)
        if scan.cancel_requested:
            scan.status, scan.current_stage = "cancelled", "cancelled"
            scan.finished_at = datetime.now(UTC)
            db.commit()
            return {"scan_id": scan_id, "status": "cancelled"}
        _set_progress(db, scan, "running", "persisting_evidence", 80)
        scan.scanner_versions = {"safe_baseline": "1.0.0", "zap": zap_summary, "profile": scan.scan_profile}
        seen = set()
        for item in results:
            fingerprint = item.fingerprint
            seen.add(fingerprint)
            existing = db.query(Finding).filter(
                Finding.organization_id == scan.organization_id,
                Finding.project_id == scan.project_id,
                Finding.fingerprint == fingerprint,
            ).first()
            if existing:
                existing.scan_id = scan.id
                existing.target_id = target.id
                existing.severity = item.severity
                existing.confidence = item.confidence
                existing.priority_score = calculate_priority_score(item.severity, item.confidence)
                existing.verification_status = item.verification_status
                existing.last_seen_at = datetime.now(UTC)
                if existing.status in {"fixed", "accepted_risk"}:
                    existing.status = "open"
                finding = existing
            else:
                finding = Finding(
                    organization_id=scan.organization_id,
                    project_id=scan.project_id,
                    target_id=target.id,
                    scan_id=scan.id,
                    rule_id=item.rule_id,
                    fingerprint=fingerprint,
                    title=item.title,
                    description=item.description,
                    severity=item.severity,
                    confidence=item.confidence,
                    priority_score=calculate_priority_score(item.severity, item.confidence),
                    verification_status=item.verification_status,
                    status="open",
                    location=item.location,
                    recommendation=item.recommendation,
                    remediation_template={},
                )
                db.add(finding)
                db.flush()
            exists = db.query(FindingOccurrence).filter_by(finding_id=finding.id, scan_id=scan.id).first()
            if not exists:
                db.add(FindingOccurrence(finding_id=finding.id, scan_id=scan.id,
                                         observed_status=item.verification_status,
                                         evidence_summary=item.evidence_summary[:1000]))
            evidence_data = item.sanitized_data
            hash_value = _digest(evidence_data)
            db.add(Evidence(finding_id=finding.id, scan_id=scan.id, evidence_type=item.evidence_type,
                            summary=item.evidence_summary[:1000], sanitized_data=evidence_data,
                            content_hash=hash_value))

        # A retest updates one specific prior finding. Only deterministic checks with a successful
        # base response can produce a fixed outcome; passive-scanner absences remain inconclusive.
        if scan.retest_finding_id:
            prior = db.query(Finding).filter(
                Finding.id == scan.retest_finding_id,
                Finding.organization_id == scan.organization_id,
                Finding.target_id == target.id,
            ).first()
            if prior:
                same_rule_found = any(item.rule_id == prior.rule_id for item in results)
                deterministic_rules = {
                    "header.content_security_policy", "header.x_content_type_options",
                    "header.referrer_policy", "header.frame_options", "header.permissions_policy",
                    "cookie.secure_missing", "cookie.httponly_missing", "cookie.samesite_missing",
                    "disclosure.technology_headers", "transport.http_target",
                }
                if prior.rule_id in deterministic_rules and summary.get("response", {}).get("status_code", 599) < 500:
                    outcome = "still_vulnerable" if same_rule_found else "fixed"
                    if outcome == "fixed":
                        prior.status = "fixed"
                    else:
                        prior.status = "open"
                elif same_rule_found:
                    outcome = "still_vulnerable"
                    prior.status = "open"
                else:
                    outcome = "inconclusive"
                retest_evidence = {
                    "rule_id": prior.rule_id,
                    "outcome": outcome,
                    "same_rule_observed": same_rule_found,
                    "base_response_status": summary.get("response", {}).get("status_code"),
                    "deterministic_rule": prior.rule_id in deterministic_rules,
                    "zap_status": zap_summary.get("status"),
                    "note": "A single retest covers only this rule and request path; it does not prove the entire application is secure.",
                }
                db.add(RetestRun(organization_id=scan.organization_id, finding_id=prior.id,
                                 scan_id=scan.id, outcome=outcome, evidence=retest_evidence))
                digest = _digest(retest_evidence)
                db.add(Evidence(finding_id=prior.id, scan_id=scan.id, evidence_type="retest_result",
                                summary=f"Retest outcome: {outcome}. Same rule observed: {same_rule_found}.",
                                sanitized_data=retest_evidence, content_hash=digest))
        # A finding that did not recur in an ordinary scan is not automatically marked fixed.
        db.flush()
        scan.progress = 95
        scan.current_stage = "finalizing"
        db.commit()
        scan.status = "completed_with_warnings" if warnings else "completed"
        scan.current_stage = "completed_with_warnings" if warnings else "completed"
        if warnings:
            scan.error_summary = "; ".join(warnings)[:500]
        else:
            scan.error_summary = None
        scan.progress = 100
        scan.finished_at = datetime.now(UTC)
        db.commit()
        return {"scan_id": scan_id, "status": scan.status, "finding_count": len(results), "summary": summary, "zap": zap_summary}
    except Exception as exc:
        db.rollback()
        logger.exception("unhandled_scan_error scan_id=%s error_type=%s", scan_id, type(exc).__name__)
        scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.current_stage = "failed"
            scan.error_summary = "Unexpected worker failure; inspect server-side logs using the scan ID"
            scan.finished_at = datetime.now(UTC)
            db.commit()
        raise
    finally:
        db.close()
