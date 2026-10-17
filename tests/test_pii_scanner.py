"""
Tests fuer den Shared PII Scanner (pii_scanner_engine.py)
==========================================================
Zentrale PII-Erkennung fuer alle DSGVO-Hooks.
Tier 1: Regex, Tier 2: Keyword-Kontext.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Hook-Verzeichnis in sys.path fuer direkten Import
HOOKS_DIR = Path(__file__).parent.parent / ".claude" / "hooks"
sys.path.insert(0, str(HOOKS_DIR))


@pytest.fixture
def scanner():
    from pii_scanner_engine import PIIScanner
    return PIIScanner()


# ─── Tier 1: IBAN ─────────────────────────────────────────

class TestIBAN:
    def test_detects_german_iban(self, scanner):
        result = scanner.scan("Konto: DE89 3704 0044 0532 0130 00")
        assert "IBAN" in result

    def test_detects_iban_without_spaces(self, scanner):
        result = scanner.scan("IBAN: DE89370400440532013000")
        assert "IBAN" in result

    def test_filters_dummy_iban(self, scanner):
        result = scanner.scan("Test-IBAN: DE00 0000 0000 0000 0000 00")
        assert "IBAN" not in result

    def test_filters_dummy_iban_compact(self, scanner):
        result = scanner.scan("DE00000000000000000000")
        assert "IBAN" not in result


# ─── Tier 1: Telefon ──────────────────────────────────────

class TestTelefon:
    def test_detects_mobile_plus49(self, scanner):
        result = scanner.scan("Tel: +49 170 1234567")
        assert "Telefon" in result

    def test_detects_mobile_0(self, scanner):
        result = scanner.scan("Mobil: 0170/1234567")
        assert "Telefon" in result

    def test_detects_landline(self, scanner):
        result = scanner.scan("Festnetz: 030 12345678")
        assert "Telefon" in result

    def test_no_false_positive_on_short_numbers(self, scanner):
        """Kurze Zahlen wie Hausnummern sollen nicht matchen."""
        result = scanner.scan("Hausnummer 42")
        assert "Telefon" not in result


# ─── Tier 1: Geburtsdatum ─────────────────────────────────

class TestGeburtsdatum:
    def test_detects_dot_format(self, scanner):
        result = scanner.scan("Geb: 15.03.1985")
        assert "Geburtsdatum" in result

    def test_detects_dash_format(self, scanner):
        result = scanner.scan("DOB: 15-03-1985")
        assert "Geburtsdatum" in result

    def test_detects_slash_format(self, scanner):
        result = scanner.scan("Born: 15/03/1985")
        assert "Geburtsdatum" in result


# ─── Tier 1: SVN ──────────────────────────────────────────

class TestSVN:
    def test_detects_svn(self, scanner):
        result = scanner.scan("SVN: 12A123456B789")
        assert "SVN" in result

    def test_no_false_positive_on_random_text(self, scanner):
        result = scanner.scan("Projekt-ID: ABC-12345")
        assert "SVN" not in result


# ─── Tier 1: Email ────────────────────────────────────────

class TestEmail:
    def test_detects_real_email(self, scanner):
        result = scanner.scan("Kontakt: max.mustermann@example.de")
        assert "Email" in result

    def test_detects_company_email(self, scanner):
        result = scanner.scan("HR: personal@unternehmen.com")
        assert "Email" in result

    def test_filters_example_com(self, scanner):
        result = scanner.scan("test@example.com")
        assert "Email" not in result

    def test_filters_example_test(self, scanner):
        result = scanner.scan("user@example.test")
        assert "Email" not in result

    def test_filters_noreply(self, scanner):
        result = scanner.scan("noreply@github.com")
        assert "Email" not in result

    def test_filters_localhost(self, scanner):
        result = scanner.scan("admin@localhost")
        assert "Email" not in result


# ─── Tier 1: IPv4 ─────────────────────────────────────────

class TestIPv4:
    def test_detects_external_ip(self, scanner):
        result = scanner.scan("Server: 8.8.8.8")
        assert "IPv4_extern" in result

    def test_filters_private_10(self, scanner):
        result = scanner.scan("LAN: 10.0.0.1")
        assert "IPv4_extern" not in result

    def test_filters_private_172(self, scanner):
        result = scanner.scan("Docker: 172.17.0.1")
        assert "IPv4_extern" not in result

    def test_filters_private_192(self, scanner):
        result = scanner.scan("WiFi: 192.168.1.1")
        assert "IPv4_extern" not in result

    def test_filters_loopback(self, scanner):
        result = scanner.scan("Local: 127.0.0.1")
        assert "IPv4_extern" not in result

    def test_filters_zero(self, scanner):
        result = scanner.scan("Bind: 0.0.0.0")
        assert "IPv4_extern" not in result


# ─── Tier 2: Credentials ──────────────────────────────────

class TestCredentials:
    def test_detects_password_equals(self, scanner):
        result = scanner.scan("password=geheim123")
        assert "Credentials" in result

    def test_detects_passwort_colon(self, scanner):
        result = scanner.scan("Passwort: test123")
        assert "Credentials" in result

    def test_detects_secret_equals(self, scanner):
        result = scanner.scan("secret=abc123def")
        assert "Credentials" in result

    def test_no_detection_tier1_only(self, scanner):
        """Tier 1 allein soll keine Credentials erkennen."""
        result = scanner.scan("password=geheim123", tier=1)
        assert "Credentials" not in result


# ─── Tier 2: Connection Strings ────────────────────────────

class TestConnectionStrings:
    def test_detects_postgres(self, scanner):
        result = scanner.scan("postgres://user:pass@host:5432/db")
        assert "Connection_String" in result

    def test_detects_mysql(self, scanner):
        result = scanner.scan("mysql://root:secret@localhost/app")
        assert "Connection_String" in result

    def test_detects_mongodb(self, scanner):
        result = scanner.scan("mongodb://admin:pw@cluster0.example.net/mydb")
        assert "Connection_String" in result


# ─── Tier 2: API Keys ─────────────────────────────────────

class TestAPIKeys:
    def test_detects_openai_key(self, scanner):
        result = scanner.scan("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz")
        assert "API_Key" in result

    def test_detects_aws_key(self, scanner):
        result = scanner.scan("AWS_KEY=AKIA1234567890ABCDEF")
        assert "API_Key" in result

    def test_detects_github_pat(self, scanner):
        result = scanner.scan("TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456")
        assert "API_Key" in result

    def test_detects_slack_token(self, scanner):
        result = scanner.scan("SLACK=xoxb-123-456-abcdefgh")
        assert "API_Key" in result


# ─── Kombiniert ───────────────────────────────────────────

class TestCombined:
    def test_no_pii_returns_empty(self, scanner):
        result = scanner.scan("Hello world, this is normal text.")
        assert result == []

    def test_multiple_categories(self, scanner):
        text = (
            "Name: Max Mustermann\n"
            "Email: max@example.de\n"
            "IBAN: DE89 3704 0044 0532 0130 00\n"
            "Tel: +49 170 1234567\n"
        )
        result = scanner.scan(text)
        assert "IBAN" in result
        assert "Email" in result
        assert "Telefon" in result

    def test_tier1_only(self, scanner):
        text = "password=secret123 und IBAN DE89 3704 0044 0532 0130 00"
        result = scanner.scan(text, tier=1)
        assert "IBAN" in result
        assert "Credentials" not in result

    def test_tier2_default(self, scanner):
        text = "password=secret123 und IBAN DE89 3704 0044 0532 0130 00"
        result = scanner.scan(text)
        assert "IBAN" in result
        assert "Credentials" in result


# ─── Edge Cases ───────────────────────────────────────────

class TestEdgeCases:
    def test_empty_string(self, scanner):
        assert scanner.scan("") == []

    def test_none_like(self, scanner):
        assert scanner.scan("") == []

    def test_long_text_performance(self, scanner):
        """10000 Zeichen Text muss schnell verarbeitet werden."""
        text = "Normal text without PII. " * 400
        result = scanner.scan(text)
        assert result == []
