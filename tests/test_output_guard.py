"""
Tests fuer dsgvo-output-guard.py (PostToolUse: Bash)
=====================================================
Scannt Tool-Output auf PII und blockiert mit Exit-Code 2.
"""
from __future__ import annotations

from tests.helpers import run_hook


def _make_post_bash(stdout: str, stderr: str = "") -> dict:
    """Erstellt PostToolUse-Input fuer Bash-Tool."""
    return {
        "tool_name": "Bash",
        "tool_response": {"stdout": stdout, "stderr": stderr},
    }


# ─── PII im Output blockieren ────────────────────────────

class TestOutputGuardBlocks:
    """PII im Bash-Output muss blockiert werden (exit 2)."""

    def test_blocks_email_in_stdout(self):
        result = run_hook("dsgvo-output-guard.py",
            _make_post_bash("Author: max.mustermann@example.de"))
        assert result.get("error"), "Email im Output muss blockieren"

    def test_blocks_iban_in_stdout(self):
        result = run_hook("dsgvo-output-guard.py",
            _make_post_bash("IBAN: DE89 3704 0044 0532 0130 00"))
        assert result.get("error"), "IBAN im Output muss blockieren"

    def test_blocks_phone_in_stdout(self):
        result = run_hook("dsgvo-output-guard.py",
            _make_post_bash("Tel: +49 170 1234567"))
        assert result.get("error"), "Telefonnummer im Output muss blockieren"

    def test_blocks_credentials_in_stderr(self):
        result = run_hook("dsgvo-output-guard.py",
            _make_post_bash("", stderr="password=secret123"))
        assert result.get("error"), "Credentials in stderr muss blockieren"

    def test_blocks_connection_string(self):
        result = run_hook("dsgvo-output-guard.py",
            _make_post_bash("postgres://user:pass@host:5432/db"))
        assert result.get("error"), "Connection-String muss blockieren"

    def test_blocks_api_key(self):
        result = run_hook("dsgvo-output-guard.py",
            _make_post_bash("key=sk-abcdefghijklmnopqrstuvwxyz"))
        assert result.get("error"), "API-Key muss blockieren"

    def test_blocks_git_log_with_email(self):
        """Realistisch: git log zeigt Entwickler-Emails."""
        git_output = (
            "commit abc123\n"
            "Author: Max Mustermann <max@example.de>\n"
            "Date: Mon Mar 15 10:00:00 2026\n"
        )
        result = run_hook("dsgvo-output-guard.py",
            _make_post_bash(git_output))
        assert result.get("error"), "git log mit Email muss blockieren"


# ─── Sauberer Output erlauben ────────────────────────────

class TestOutputGuardAllows:
    """Sauberer Output ohne PII muss durchgelassen werden."""

    def test_allows_clean_stdout(self):
        result = run_hook("dsgvo-output-guard.py",
            _make_post_bash("Build successful. 0 errors."))
        assert not result.get("error"), "Sauberer Output muss erlaubt sein"

    def test_allows_empty_output(self):
        result = run_hook("dsgvo-output-guard.py",
            _make_post_bash(""))
        assert not result.get("error"), "Leerer Output muss erlaubt sein"

    def test_allows_code_output(self):
        result = run_hook("dsgvo-output-guard.py",
            _make_post_bash("def hello():\n    print('hello')\n"))
        assert not result.get("error"), "Code-Output muss erlaubt sein"

    def test_allows_example_email(self):
        """test@example.com ist kein echtes PII."""
        result = run_hook("dsgvo-output-guard.py",
            _make_post_bash("Contact: test@example.com"))
        assert not result.get("error"), "Example-Emails sind kein PII"

    def test_allows_private_ip(self):
        result = run_hook("dsgvo-output-guard.py",
            _make_post_bash("Server: 192.168.1.1"))
        assert not result.get("error"), "Private IPs sind kein PII"


# ─── Fail-Closed ────────────────────────────────────────

class TestOutputGuardFailClosed:
    """Bei Fehlern muss blockiert werden."""

    def test_malformed_input_blocks(self):
        result = run_hook("dsgvo-output-guard.py", {"broken": True})
        assert result.get("error"), "Kaputtes Input muss blockieren"
