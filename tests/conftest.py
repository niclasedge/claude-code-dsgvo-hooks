"""
DSGVO Hook Test-Konfiguration (conftest.py)
=============================================
Pytest-Fixtures fuer alle Hook-Tests.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import HOOKS_DIR, TESTFILES_DIR


@pytest.fixture
def hooks_dir() -> Path:
    """Pfad zum Hooks-Verzeichnis."""
    return HOOKS_DIR


@pytest.fixture
def testfiles_dir() -> Path:
    """Pfad zum Testdateien-Verzeichnis."""
    return TESTFILES_DIR
