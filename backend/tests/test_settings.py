import pytest
from pydantic import ValidationError

from app.config import Settings


def test_production_rejects_placeholder_secrets():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            environment="production",
            deployment_mode="self_hosted",
            secret_key="replace-with-a-unique-random-secret-at-least-48-characters",
            zap_api_key="replace-with-a-separate-strong-random-zap-key",
            allow_public_signup=False,
        )


def test_production_accepts_distinct_long_random_looking_secrets():
    settings = Settings(
        _env_file=None,
        environment="production",
        deployment_mode="self_hosted",
        secret_key="qF8jM2vR9sW4xL7pN1aC6dH0kB5tY3uE8zG4mP7r",
        zap_api_key="V6nQ2sT9wK4cX8pL1rD5hM7zB0fA3uE6",
        database_url="postgresql+psycopg://sentinelai:q7M4tD9xL2vB8nQ5cR1kZ6pH3aW0sE7y@db:5432/sentinelai",
        postgres_password="q7M4tD9xL2vB8nQ5cR1kZ6pH3aW0sE7y",
        allow_public_signup=False,
    )
    assert settings.allow_public_signup is False


def test_production_rejects_placeholder_database_password():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            environment="production",
            deployment_mode="self_hosted",
            secret_key="qF8jM2vR9sW4xL7pN1aC6dH0kB5tY3uE8zG4mP7r",
            zap_api_key="V6nQ2sT9wK4cX8pL1rD5hM7zB0fA3uE6",
            database_url="postgresql+psycopg://sentinelai:replace-password@db:5432/sentinelai",
            postgres_password="replace-with-a-strong-unique-postgres-password",
            allow_public_signup=False,
        )
