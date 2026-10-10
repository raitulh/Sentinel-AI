from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "SentinelAI API"
    environment: str = "development"
    deployment_mode: str = "self_hosted"  # self_hosted or hosted
    secret_key: str = Field(default="development-only-change-this-secret-before-deploying-123456")
    access_token_minutes: int = 30
    allow_public_signup: bool = True
    database_url: str = "sqlite:///./sentinelai.db"
    postgres_password: str = ""
    redis_url: str = "redis://localhost:6379/0"
    frontend_origin: str = "http://localhost:3000"
    zap_api_url: str = "http://zap:8080"
    zap_api_key: str = "replace-zap-api-key"
    enable_zap: bool = True
    scan_max_pages: int = 40
    scan_timeout_seconds: int = 600
    scan_max_concurrency: int = 2
    allow_private_targets: bool = False
    allow_http_targets: bool = True
    ai_base_url: str | None = "http://localhost:11434/v1"  # OpenAI-compatible; e.g. local Ollama endpoint
    ai_api_key: str | None = None
    ai_model: str = "Qwen3:1.7B"

    @field_validator("deployment_mode")
    @classmethod
    def validate_deployment_mode(cls, value: str) -> str:
        if value not in {"self_hosted", "hosted"}:
            raise ValueError("deployment_mode must be self_hosted or hosted")
        return value

    @model_validator(mode="after")
    def reject_weak_production_secret(self):
        # Check after all fields are loaded; field order must not weaken this guard.
        if self.deployment_mode == "hosted" and len(self.secret_key) < 40:
            raise ValueError("SECRET_KEY must contain at least 40 characters in hosted mode")
        if self.environment == "production":
            secret_lower = self.secret_key.lower()
            if len(self.secret_key) < 40 or any(marker in secret_lower for marker in ("development-only", "replace-with", "changeme", "example-secret")):
                raise ValueError("Set a unique random SECRET_KEY of at least 40 characters before production deployment")
            zap_key_lower = self.zap_api_key.lower()
            if len(self.zap_api_key) < 32 or any(marker in zap_key_lower for marker in ("replace", "changeme", "example")):
                raise ValueError("Set a unique random ZAP_API_KEY of at least 32 characters before production deployment")
            if self.database_url.startswith("postgresql"):
                db_pass_lower = self.postgres_password.lower()
                if len(self.postgres_password) < 24 or any(marker in db_pass_lower for marker in ("replace", "changeme", "password", "example")):
                    raise ValueError("Set a unique POSTGRES_PASSWORD of at least 24 characters before production deployment")
        if self.environment == "production" and self.allow_private_targets and self.allow_public_signup:
            raise ValueError("Do not combine private-target scanning and public signup in production; bootstrap the owner, disable signup, then enable private targets only for trusted self-hosted use")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
