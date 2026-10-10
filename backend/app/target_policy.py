import ipaddress
import secrets
import socket
from urllib.parse import urlparse, urlunparse

import dns.resolver
from fastapi import HTTPException

from app.config import settings


def normalize_target(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=422, detail="Target must use HTTP or HTTPS")
    if not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(status_code=422, detail="Target URL is invalid or contains credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Target port is invalid") from exc
    if port and not 1 <= port <= 65535:
        raise HTTPException(status_code=422, detail="Target port is invalid")
    if settings.deployment_mode == "hosted" and port and port not in {80, 443}:
        raise HTTPException(status_code=422, detail="Hosted targets may use only ports 80 and 443")
    if parsed.scheme == "http" and not settings.allow_http_targets:
        raise HTTPException(status_code=422, detail="HTTP targets are disabled by policy")
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} and not settings.allow_private_targets:
        raise HTTPException(status_code=422, detail="Private targets are disabled in this deployment")
    if not settings.allow_private_targets:
        try:
            ip = ipaddress.ip_address(host)
            if not ip.is_global:
                raise HTTPException(status_code=422, detail="Non-public IP targets are disabled")
        except ValueError:
            pass
    try:
        ip_literal = ipaddress.ip_address(host)
        netloc = f"[{host}]" if ip_literal.version == 6 else host
    except ValueError:
        netloc = host
    if port:
        netloc = f"{netloc}:{port}"
    path = parsed.path.rstrip("/")
    return urlunparse((parsed.scheme, netloc, path, "", "", ""))


def validate_resolved_addresses(url: str) -> list[str]:
    host = urlparse(url).hostname
    if not host:
        raise HTTPException(status_code=422, detail="Target hostname missing")
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(status_code=422, detail="Target hostname did not resolve") from exc
    addresses = sorted({item[4][0] for item in infos})
    if not addresses:
        raise HTTPException(status_code=422, detail="Target hostname did not resolve")
    if not settings.allow_private_targets:
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail="Invalid target address") from exc
            if not ip.is_global:
                raise HTTPException(status_code=422, detail="Target resolves to a non-public address")
    return addresses


def create_verification_token() -> str:
    return secrets.token_urlsafe(24)


def verify_dns_challenge(hostname: str, token: str) -> bool:
    try:
        answers = dns.resolver.resolve(f"_sentinelai-challenge.{hostname}", "TXT", lifetime=4)
        expected = f"sentinelai={token}"
        for record in answers:
            chunks = getattr(record, "strings", ())
            value = "".join(chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else str(chunk) for chunk in chunks)
            if value == expected:
                return True
        return False
    except Exception:
        # Verification failures are deliberately fail-closed.
        return False
