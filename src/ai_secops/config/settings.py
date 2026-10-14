"""Runtime settings and configuration management."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment or defaults."""

    app_name: str = "AI Security Operations Assistant"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = False

    # Server Configuration
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # Persistence Configuration
    database_path: str = "data/secops.db"

    # AI Model & Guardrail Parameters
    model_name: str = "secops-guardian-v1"
    guardrails_enabled: bool = True
    max_query_length: int = 2048
    blast_radius_threshold: float = 0.80
    high_criticality_confirmation_required: bool = True

    # Security Configuration
    secret_key: str = "insecure-dev-secret-key-change-in-production"  # noqa: S105
    allowed_hosts: list[str] = ["*"]
    cors_origins: list[str] = ["*"]

    model_config = SettingsConfigDict(
        env_prefix="SECOPS_",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    def resolve_db_path(self) -> Path:
        """Resolve and ensure parent directory for the database path."""
        path = Path(self.database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached instance of Settings."""
    return Settings()
