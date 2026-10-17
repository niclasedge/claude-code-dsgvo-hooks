"""
Tests fuer dsgvo-content-guard.py (PostToolUse: Read)
=====================================================
Scannt gelesenen Dateiinhalt auf PII und blockiert mit Exit-Code 2.
"""
from __future__ import annotations

from tests.helpers import run_hook


def _make_post_read(file_path: str, content: str) -> dict:
    """Erstellt PostToolUse-Input fuer Read-Tool."""
    return {
        "tool_name": "Read",
        "tool_input": {"file_path": file_path},
        "tool_response": {"type": "text", "file": {"filePath": file_path, "content": content}},
    }


# ─── PII im gelesenen Inhalt blockieren ──────────────────

class TestContentGuardBlocks:
    """PII im gelesenen Dateiinhalt muss blockiert werden."""

    def test_blocks_csv_with_emails(self):
        content = "Name,Email\nMax Mustermann,max@example.de\n"
        result = run_hook("dsgvo-content-guard.py",
            _make_post_read("/data/customers.csv", content))
        assert result.get("error"), "CSV mit Emails muss blockieren"

    def test_blocks_file_with_iban(self):
        content = "Konto: DE89 3704 0044 0532 0130 00\n"
        result = run_hook("dsgvo-content-guard.py",
            _make_post_read("/data/payments.txt", content))
        assert result.get("error"), "Datei mit IBAN muss blockieren"

    def test_blocks_file_with_phone(self):
        content = "Kontakt: +49 170 1234567\n"
        result = run_hook("dsgvo-content-guard.py",
            _make_post_read("/data/contacts.txt", content))
        assert result.get("error"), "Datei mit Telefon muss blockieren"

    def test_blocks_file_with_credentials(self):
        content = "DB_PASSWORD=geheim123\nDB_HOST=localhost\n"
        result = run_hook("dsgvo-content-guard.py",
            _make_post_read("/config/secrets.ini", content))
        assert result.get("error"), "Datei mit Credentials muss blockieren"

    def test_blocks_file_with_connection_string(self):
        content = "DATABASE_URL=postgres://user:pass@host:5432/db\n"
        result = run_hook("dsgvo-content-guard.py",
            _make_post_read("/config/database.yml", content))
        assert result.get("error"), "Datei mit Connection-String muss blockieren"

    def test_blocks_json_with_personal_data(self):
        content = '{"name": "Max", "email": "max@example.de", "phone": "+49 170 1234567"}'
        result = run_hook("dsgvo-content-guard.py",
            _make_post_read("/data/user.json", content))
        assert result.get("error"), "JSON mit PII muss blockieren"


# ─── Saubere Dateien erlauben ────────────────────────────

class TestContentGuardAllows:
    """Saubere Dateien ohne PII muessen durchgelassen werden."""

    def test_allows_python_code(self):
        """Source-Code-Dateien werden uebersprungen (kein Scan)."""
        content = "def hello():\n    print('world')\n"
        result = run_hook("dsgvo-content-guard.py",
            _make_post_read("/src/app.py", content))
        assert not result.get("error"), "Python-Code muss erlaubt sein"

    def test_allows_python_with_mock_pii(self):
        """Python mit PII-Patterns (Mock-Daten) darf nicht blockieren."""
        content = 'MOCK_DATES = ["01.01.2000"]\nMOCK_SVNS = ["00A000000A000"]'
        result = run_hook("dsgvo-content-guard.py",
            _make_post_read("/tools/generate_mock_data.py", content))
        assert not result.get("error"), "Python mit Mock-PII muss erlaubt sein"

    def test_allows_config_without_secrets(self):
        content = "[server]\nport = 8080\nhost = localhost\n"
        result = run_hook("dsgvo-content-guard.py",
            _make_post_read("/config/server.ini", content))
        assert not result.get("error"), "Config ohne Secrets muss erlaubt sein"

    def test_allows_empty_file(self):
        result = run_hook("dsgvo-content-guard.py",
            _make_post_read("/data/empty.txt", ""))
        assert not result.get("error"), "Leere Datei muss erlaubt sein"

    def test_allows_example_email(self):
        content = "Contact: test@example.com\n"
        result = run_hook("dsgvo-content-guard.py",
            _make_post_read("/docs/readme.md", content))
        assert not result.get("error"), "Example-Emails sind kein PII"

    def test_allows_private_ip(self):
        content = "Server: 192.168.1.1\n"
        result = run_hook("dsgvo-content-guard.py",
            _make_post_read("/docs/network.md", content))
        assert not result.get("error"), "Private IPs sind kein PII"


# ─── Fail-Closed ────────────────────────────────────────

class TestContentGuardFailClosed:
    """Bei Fehlern muss blockiert werden."""

    def test_malformed_input_blocks(self):
        result = run_hook("dsgvo-content-guard.py", {"broken": True})
        assert result.get("error"), "Kaputtes Input muss blockieren"
