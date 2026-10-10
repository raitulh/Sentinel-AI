from datetime import UTC, datetime, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
import jwt

from app.config import settings

_password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _password_hasher.verify(hashed, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def create_access_token(user_id: str, organization_id: str) -> tuple[str, int]:
    ttl = settings.access_token_minutes * 60
    now = datetime.now(UTC)
    payload = {
        "sub": user_id,
        "org": organization_id,
        "iat": now,
        "exp": now + timedelta(seconds=ttl),
        "iss": "sentinelai",
        "aud": "sentinelai-api",
        "jti": __import__("uuid").uuid4().hex,
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256"), ttl


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        settings.secret_key,
        algorithms=["HS256"],
        issuer="sentinelai",
        audience="sentinelai-api",
        options={"require": ["sub", "org", "exp", "iat", "jti"]},
    )
