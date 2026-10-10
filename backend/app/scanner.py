"""Bounded, non-destructive web checks. This engine sends only GET requests and never runs exploit payloads."""
import hashlib
import ipaddress
import socket
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.target_policy import validate_resolved_addresses


@dataclass
class ScanFinding:
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    verification_status: str
    location: str
    recommendation: str
    evidence_type: str
    evidence_summary: str
    sanitized_data: dict

    @property
    def fingerprint(self) -> str:
        raw = f"{self.rule_id}|{self.location.split('?')[0]}"
        return hashlib.sha256(raw.encode()).hexdigest()


def _finding(rule_id: str, title: str, description: str, severity: str, location: str,
             recommendation: str, evidence_summary: str, sanitized_data: dict,
             confidence: str = "high", status: str = "confirmed", evidence_type: str = "http_metadata") -> ScanFinding:
    return ScanFinding(rule_id, title, description, severity, confidence, status, location,
                       recommendation, evidence_type, evidence_summary, sanitized_data)


def _safe_get(url: str, timeout: float = 12.0) -> httpx.Response:
    # Re-resolve just before connecting. Production hosted deployments must also enforce
    # destination restrictions with network egress policy to close DNS-rebinding races.
    validate_resolved_addresses(url)
    with httpx.Client(timeout=timeout, follow_redirects=False, verify=True,
                      headers={"User-Agent": "SentinelAI-SafeScanner/1.0 (+authorized security assessment)"}) as client:
        return client.get(url)


def run_safe_baseline(target_url: str) -> tuple[list[ScanFinding], dict]:
    """Run conservative GET-only checks for response headers and cookie flags."""
    findings: list[ScanFinding] = []
    metadata: dict = {"checks": [], "warnings": []}
    parsed = urlparse(target_url)
    if not settings.allow_private_targets:
        try:
            if not all(ipaddress.ip_address(ip).is_global for ip in validate_resolved_addresses(target_url)):
                raise ValueError("Non-public address")
        except ValueError as exc:
            raise RuntimeError("Target policy rejected a non-public IP address") from exc

    try:
        response = _safe_get(target_url)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Target request failed ({type(exc).__name__}); details suppressed") from exc
    except Exception as exc:
        raise RuntimeError(f"Target validation or request failed ({type(exc).__name__}); details suppressed") from exc

    headers = {k.lower(): v for k, v in response.headers.items()}
    metadata["checks"].append({"name": "base_response", "status": response.status_code})
    metadata["response"] = {
        "status_code": response.status_code,
        "http_version": response.http_version,
        "content_type": headers.get("content-type", "")[:120],
        "url": target_url,
    }

    header_checks = [
        ("header.content_security_policy", "Content-Security-Policy missing", "medium",
         "Content-Security-Policy helps limit the impact of script injection. Define a policy appropriate to the application and test it in report-only mode before enforcement."),
        ("header.x_content_type_options", "X-Content-Type-Options missing", "low",
         "Set X-Content-Type-Options: nosniff on applicable responses."),
        ("header.referrer_policy", "Referrer-Policy missing", "low",
         "Set an explicit Referrer-Policy such as strict-origin-when-cross-origin after reviewing product needs."),
        ("header.frame_options", "Clickjacking protection header missing", "medium",
         "Use a suitable Content-Security-Policy frame-ancestors directive. X-Frame-Options may be retained for legacy clients."),
        ("header.permissions_policy", "Permissions-Policy missing", "info",
         "Consider an explicit Permissions-Policy that disables browser features the application does not need."),
    ]
    for rule_id, title, severity, recommendation in header_checks:
        header_name = {
            "header.content_security_policy": "content-security-policy",
            "header.x_content_type_options": "x-content-type-options",
            "header.referrer_policy": "referrer-policy",
            "header.frame_options": "x-frame-options",
            "header.permissions_policy": "permissions-policy",
        }[rule_id]
        present = bool(headers.get(header_name)) or (rule_id == "header.frame_options" and "frame-ancestors" in headers.get("content-security-policy", "").lower())
        metadata["checks"].append({"name": rule_id, "passed": present})
        if not present:
            findings.append(_finding(
                rule_id, title, f"The response from the authorized target did not include {header_name}.",
                severity, target_url, recommendation,
                f"HTTP {response.status_code}; header absent: {header_name}",
                {"status_code": response.status_code, "header_name": header_name, "present": False},
            ))

    server_header = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if server_header or powered_by:
        disclosed = {k: v[:120] for k, v in {"server": server_header, "x-powered-by": powered_by}.items() if v}
        findings.append(_finding(
            "disclosure.technology_headers", "Technology details disclosed in response headers",
            "Response headers reveal server or framework information that may help fingerprint the application. This is generally informational and does not by itself prove a vulnerability.",
            "info", target_url, "Remove unnecessary technology-identifying headers where practical; keep software patched regardless of whether headers are hidden.",
            "Technology-identifying headers present; values sanitized and length-limited.",
            {"disclosed_header_names": list(disclosed.keys()), "values_redacted_in_summary": True},
            confidence="high", status="confirmed",
        ))

    cookie_header_values = response.headers.get_list("set-cookie")
    cookie_flags = []
    for value in cookie_header_values[:30]:
        # Cookie values are never persisted. Only flag presence is captured.
        prefix = value.split("=", 1)[0][:80].strip()
        lower = value.lower()
        secure = "; secure" in lower
        httponly = "; httponly" in lower
        samesite = "samesite=" in lower
        cookie_flags.append({"cookie_name": prefix, "secure": secure, "httponly": httponly, "samesite": samesite})
        if parsed.scheme == "https" and not secure:
            findings.append(_finding(
                "cookie.secure_missing", "Cookie missing Secure attribute",
                "A Set-Cookie response over HTTPS did not include the Secure attribute. The cookie value was not stored.",
                "medium", target_url, "Set Secure on cookies that should only be sent over HTTPS.",
                f"Cookie {prefix or '[unnamed]'} lacks Secure; cookie value redacted.",
                {"cookie_name": prefix, "secure": False, "httponly": httponly, "samesite": samesite},
            ))
        if not httponly:
            findings.append(_finding(
                "cookie.httponly_missing", "Cookie missing HttpOnly attribute",
                "A Set-Cookie response did not include HttpOnly. Whether this is a vulnerability depends on the cookie's intended JavaScript access.",
                "low", target_url, "Set HttpOnly for session and other sensitive cookies that do not need JavaScript access.",
                f"Cookie {prefix or '[unnamed]'} lacks HttpOnly; cookie value redacted.",
                {"cookie_name": prefix, "secure": secure, "httponly": False, "samesite": samesite},
                confidence="medium", status="likely",
            ))
        if not samesite:
            findings.append(_finding(
                "cookie.samesite_missing", "Cookie missing SameSite attribute",
                "A Set-Cookie response did not declare SameSite. Application behaviour and cross-site flows should be considered before remediation.",
                "low", target_url, "Set an appropriate SameSite value (often Lax) after validating OAuth, SSO and cross-site workflows.",
                f"Cookie {prefix or '[unnamed]'} lacks SameSite; cookie value redacted.",
                {"cookie_name": prefix, "secure": secure, "httponly": httponly, "samesite": False},
                confidence="medium", status="likely",
            ))
    metadata["cookie_metadata"] = cookie_flags

    if parsed.scheme == "http":
        findings.append(_finding(
            "transport.http_target", "Target uses unencrypted HTTP",
            "The registered target URL uses HTTP. Credentials and sensitive content can be exposed in transit unless the environment is intentionally isolated.",
            "high", target_url, "Serve the application over HTTPS, redirect HTTP safely to HTTPS, and configure HSTS on HTTPS responses.",
            "Registered URL scheme is HTTP; no credentials or payloads were sent.",
            {"scheme": "http", "https_upgrade_tested": False}, confidence="high", status="confirmed",
        ))

    # Deliberately do not crawl arbitrary paths or follow redirects in this first safe profile.
    metadata["policy"] = {
        "method": "GET only", "active_scanning": False, "redirects_followed": False,
        "cookie_values_stored": False, "max_cookie_headers_examined": 30,
    }
    return findings, metadata
