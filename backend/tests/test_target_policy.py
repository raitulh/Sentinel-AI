import pytest
from fastapi import HTTPException
from app.target_policy import normalize_target


def test_target_requires_http_or_https():
    with pytest.raises(HTTPException):
        normalize_target("file:///etc/passwd")


def test_target_rejects_embedded_credentials():
    with pytest.raises(HTTPException):
        normalize_target("https://user:pass@example.com")


def test_normalizes_host_and_trailing_slash(monkeypatch):
    from app import target_policy
    monkeypatch.setattr(target_policy.settings, "allow_private_targets", True)
    assert normalize_target("https://EXAMPLE.com/path/") == "https://example.com/path"
