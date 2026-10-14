"""Pytest shared fixtures and configurations."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from ai_secops.config.settings import Settings


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def test_settings(temp_dir: Path) -> Settings:
    """Provide isolated test settings with temporary SQLite DB."""
    db_file = temp_dir / "test_secops.db"
    return Settings(
        environment="testing",
        debug=True,
        database_path=str(db_file),
        guardrails_enabled=True,
    )
