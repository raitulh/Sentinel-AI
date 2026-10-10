import httpx
from app import scanner


def test_safe_baseline_reports_missing_headers(monkeypatch):
    monkeypatch.setattr(scanner, "validate_resolved_addresses", lambda url: ["93.184.216.34"])
    def fake_get(url, timeout=12.0):
        request = httpx.Request("GET", url)
        return httpx.Response(200, request=request, headers={"content-type": "text/html", "server": "example"}, text="ok")
    monkeypatch.setattr(scanner, "_safe_get", fake_get)
    findings, metadata = scanner.run_safe_baseline("https://example.com")
    ids = {f.rule_id for f in findings}
    assert "header.content_security_policy" in ids
    assert "header.x_content_type_options" in ids
    assert metadata["policy"]["active_scanning"] is False


def test_cookie_values_are_not_stored(monkeypatch):
    monkeypatch.setattr(scanner, "validate_resolved_addresses", lambda url: ["93.184.216.34"])
    def fake_get(url, timeout=12.0):
        request = httpx.Request("GET", url)
        return httpx.Response(200, request=request, headers=[("set-cookie", "session=supersecret; Path=/")])
    monkeypatch.setattr(scanner, "_safe_get", fake_get)
    findings, _ = scanner.run_safe_baseline("https://example.com")
    serialized = str([f.sanitized_data for f in findings])
    assert "supersecret" not in serialized
