"""
Tests fuer dsgvo-session-guard.py (SessionStart)
=================================================
Prueft CLAUDE.md-Dateien auf PII beim Session-Start.
Gibt Warnung aus, wenn Personendaten gefunden werden.
"""
from __future__ import annotations

from tests.helpers import run_hook


def _make_session_input(project_dir: str = "/tmp") -> dict:
    """Erstellt SessionStart-Input."""
    return {
        "session_id": "test-session-123",
        "project_dir": project_dir,
    }


# ─── PII in CLAUDE.md erkennen ───────────────────────────

class TestSessionGuardDetects:
    """PII in CLAUDE.md muss erkannt und gewarnt werden."""

    def test_warns_on_email_in_claude_md(self, tmp_path):
        """CLAUDE.md mit Email muss Warnung ausloesen."""
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("Kontakt: max.mustermann@example.de\n")
        result = run_hook("dsgvo-session-guard.py",
            _make_session_input(str(tmp_path)))
        stdout_text = result.get("message", "")
        assert "WARNUNG" in stdout_text or "Email" in stdout_text

    def test_warns_on_phone_in_claude_md(self, tmp_path):
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("Support: +49 170 1234567\n")
        result = run_hook("dsgvo-session-guard.py",
            _make_session_input(str(tmp_path)))
        stdout_text = result.get("message", "")
        assert "WARNUNG" in stdout_text or "Telefon" in stdout_text

    def test_warns_on_iban_in_claude_md(self, tmp_path):
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("Konto: DE89 3704 0044 0532 0130 00\n")
        result = run_hook("dsgvo-session-guard.py",
            _make_session_input(str(tmp_path)))
        stdout_text = result.get("message", "")
        assert "WARNUNG" in stdout_text or "IBAN" in stdout_text

    def test_warns_on_credentials_in_claude_md(self, tmp_path):
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("DB_PASSWORD=geheim123\n")
        result = run_hook("dsgvo-session-guard.py",
            _make_session_input(str(tmp_path)))
        stdout_text = result.get("message", "")
        assert "WARNUNG" in stdout_text or "Credentials" in stdout_text

    def test_checks_nested_claude_md(self, tmp_path):
        """Auch .claude/CLAUDE.md muss geprueft werden."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        claude_md = claude_dir / "CLAUDE.md"
        claude_md.write_text("Owner: max@example.de\n")
        result = run_hook("dsgvo-session-guard.py",
            _make_session_input(str(tmp_path)))
        stdout_text = result.get("message", "")
        assert "WARNUNG" in stdout_text or "Email" in stdout_text


# ─── Saubere CLAUDE.md erlauben ──────────────────────────

class TestSessionGuardClean:
    """Saubere CLAUDE.md ohne PII soll keine Warnung ausloesen."""

    def test_clean_claude_md_no_warning(self, tmp_path):
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("# Projekt\nCode-Qualitaet beachten.\n")
        result = run_hook("dsgvo-session-guard.py",
            _make_session_input(str(tmp_path)))
        stdout_text = result.get("message", "")
        assert "WARNUNG" not in stdout_text

    def test_no_claude_md_no_warning(self, tmp_path):
        """Kein CLAUDE.md -> keine Warnung."""
        result = run_hook("dsgvo-session-guard.py",
            _make_session_input(str(tmp_path)))
        stdout_text = result.get("message", "")
        assert "WARNUNG" not in stdout_text

    def test_example_emails_no_warning(self, tmp_path):
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("Contact: test@example.com\n")
        result = run_hook("dsgvo-session-guard.py",
            _make_session_input(str(tmp_path)))
        stdout_text = result.get("message", "")
        assert "WARNUNG" not in stdout_text
