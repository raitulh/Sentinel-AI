"""Optional ZAP spider + passive scan adapter. Active scanner and forced browsing are never called."""
import re
import time
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.scanner import ScanFinding


class ZapUnavailable(RuntimeError):
    pass


def _alert_to_finding(alert: dict) -> ScanFinding | None:
    risk_map = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    risk = str(alert.get("risk", "Info"))
    risk_id = str(alert.get("riskcode", "0"))
    title = str(alert.get("name", "Security observation"))[:280]
    uri = str(alert.get("url", ""))[:2048]
    if not uri:
        return None
    # ZAP alert fields can echo target content; persist only short, sanitized metadata.
    rule_id = "zap." + re.sub(r"[^a-zA-Z0-9_.-]", "_", str(alert.get("pluginId", "unknown")))[:100]
    description = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(alert.get("description", "")))[:1500]
    solution = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(alert.get("solution", "")))[:1500]
    summary = f"ZAP passive alert; risk={risk}; method={str(alert.get('method',''))[:10]}; parameter={str(alert.get('param',''))[:80]}"
    evidence = {"scanner": "OWASP ZAP passive", "plugin_id": str(alert.get("pluginId", ""))[:100],
                "risk": risk, "method": str(alert.get("method", ""))[:10],
                "parameter": str(alert.get("param", ""))[:80],
                "confidence": str(alert.get("confidence", "Medium"))[:30],
                "request_response_bodies_stored": False}
    return ScanFinding(rule_id, title, description or title, risk_map.get(risk_id, "info"),
                       "medium", "likely", uri, solution or "Review the passive scanner observation and verify manually.",
                       "scanner_alert", summary, evidence)


def run_zap_passive(target_url: str, max_pages: int = 40, timeout: int = 120) -> tuple[list[ScanFinding], dict]:
    if not settings.enable_zap:
        return [], {"enabled": False, "status": "skipped"}
    api_url = settings.zap_api_url.rstrip("/")
    key = settings.zap_api_key
    if not key or key == "replace-zap-api-key":
        raise ZapUnavailable("ZAP API key is not configured")

    parsed = urlparse(target_url)
    # Context inclusion is limited to the registered origin and path prefix.
    prefix = parsed.path.rstrip("/")
    path_pattern = re.escape(prefix)
    if not prefix:
        path_pattern = ""
    host_pattern = re.escape(parsed.hostname or "")
    port_pattern = f":{parsed.port}" if parsed.port else ""
    scheme_pattern = re.escape(parsed.scheme)
    scoped_regex = f"^{scheme_pattern}://{host_pattern}{re.escape(port_pattern)}{path_pattern}(?:/.*)?(?:\\?.*)?$"
    context_name = "sentinel_" + str(abs(hash(target_url)))
    timeout = max(30, min(timeout, 180))

    def api_get(client: httpx.Client, endpoint: str, params: dict | None = None) -> dict:
        query = {"apikey": key, **(params or {})}
        response = client.get(f"{api_url}/JSON/{endpoint}", params=query)
        response.raise_for_status()
        try:
            data = response.json()
        except ValueError as exc:
            raise ZapUnavailable("ZAP returned an invalid response") from exc
        if not isinstance(data, dict):
            raise ZapUnavailable("ZAP returned an unexpected response")
        return data

    with httpx.Client(timeout=httpx.Timeout(8, read=12), follow_redirects=False) as client:
        try:
            context = api_get(client, "context/action/newContext/", {"contextName": context_name})
            context_id = str(context.get("contextId", ""))
            if not context_id:
                raise ZapUnavailable("Could not create a scanner context")
            api_get(client, "context/action/includeInContext/", {"contextName": context_name, "regex": scoped_regex})
            spider_result = api_get(client, "spider/action/scan/", {"url": target_url, "contextName": context_name,
                                                                      "recurse": "true", "maxChildren": max_pages, "subtreeOnly": "true"})
            spider_id = str(spider_result.get("scan", "0"))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                status_data = api_get(client, "spider/view/status/", {"scanId": spider_id})
                try:
                    progress = int(status_data.get("status", 0))
                except (TypeError, ValueError):
                    progress = 0
                if progress >= 100:
                    break
                time.sleep(0.5)
            else:
                raise ZapUnavailable("ZAP spider timed out")

            # Wait for passive processing to drain. The active scanner endpoint is never used.
            p_deadline = time.monotonic() + min(30, timeout // 2)
            while time.monotonic() < p_deadline:
                records = api_get(client, "pscan/view/recordsToScan/")
                try:
                    count = int(records.get(".recordsToScan", records.get("recordsToScan", 0)))
                except (TypeError, ValueError):
                    count = 0
                if count <= 0:
                    break
                time.sleep(0.5)

            alerts_data = api_get(client, "core/view/alerts/", {"baseurl": target_url, "start": 0, "count": 200})
            alerts = alerts_data.get("alerts", [])
            findings = []
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for alert in alerts if isinstance(alerts, list) else []:
                if not isinstance(alert, dict):
                    continue
                alert_url = str(alert.get("url", ""))
                if not alert_url.startswith(origin):
                    continue
                if prefix and not (urlparse(alert_url).path == prefix or urlparse(alert_url).path.startswith(prefix + "/")):
                    continue
                normalized = _alert_to_finding(alert)
                if normalized:
                    findings.append(normalized)
            return findings, {"enabled": True, "status": "completed", "passive_only": True,
                              "alerts_returned": len(findings), "active_scanner_invoked": False}
        except (httpx.HTTPError, KeyError) as exc:
            raise ZapUnavailable(f"ZAP service unavailable ({type(exc).__name__})") from exc
        finally:
            try:
                api_get(client, "context/action/removeContext/", {"contextName": context_name})
            except Exception:
                pass
