"""Tests for configuration settings."""

from pathlib import Path

from ai_secops.config.settings import Settings, get_settings


def test_settings_defaults() -> None:
    """Test default values of Settings."""
    settings = Settings()
    assert settings.app_name == "AI Security Operations Assistant"
    assert settings.api_port == 8000
    assert settings.guardrails_enabled is True
    assert settings.blast_radius_threshold == 0.80


def test_get_settings_cached() -> None:
    """Test singleton cached getter returns same instance."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_resolve_db_path(temp_dir: Path) -> None:
    """Test database directory creation on resolve."""
    custom_db = temp_dir / "subdir" / "secops_custom.db"
    settings = Settings(database_path=str(custom_db))
    resolved = settings.resolve_db_path()
    assert resolved == custom_db
    assert resolved.parent.exists()
