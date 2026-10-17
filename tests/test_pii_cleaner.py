# /// script
# requires-python = ">=3.10"
# dependencies = ["pytest"]
# ///
"""
Tests fuer den PII-Cleaner
============================
Testet Scan, Clean und Format-spezifische Logik (Text, JSON, JSONL).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# PIICleaner importieren (vor pytest, da sys.path angepasst werden muss)
TOOLS_DIR = Path(__file__).parent.parent / ".claude" / "tools"
sys.path.insert(0, str(TOOLS_DIR))

from pii_cleaner import PIICleaner, PIIFinding, ScanReport, CleanResult, _reset_mock_counters  # noqa: E402

import pytest  # noqa: E402


# ─── Fixtures ─────────────────────────────────────────


@pytest.fixture
def cleaner():
    """PIICleaner mit Tier 2 (schnell, kein NLP noetig)."""
    _reset_mock_counters()
    return PIICleaner(tier=2)


@pytest.fixture
def cleaner_t1():
    """PIICleaner mit Tier 1 (nur Regex)."""
    _reset_mock_counters()
    return PIICleaner(tier=1)


# ─── Text-Level: scan_text ────────────────────────────


class TestScanText:
    """scan_text erkennt PII in Strings."""

    def test_erkennt_email(self, cleaner):
        findings = cleaner.scan_text("Kontakt: max@example.de")
        kategorien = [f.kategorie for f in findings]
        assert "Email" in kategorien

    def test_erkennt_iban(self, cleaner):
        findings = cleaner.scan_text("IBAN: DE89 3704 0044 0532 0130 00")
        kategorien = [f.kategorie for f in findings]
        assert "IBAN" in kategorien

    def test_erkennt_telefon(self, cleaner):
        findings = cleaner.scan_text("Tel: +49 170 1234567")
        kategorien = [f.kategorie for f in findings]
        assert "Telefon" in kategorien

    def test_erkennt_credentials(self, cleaner):
        findings = cleaner.scan_text("password=geheim123")
        kategorien = [f.kategorie for f in findings]
        assert "Credentials" in kategorien

    def test_erkennt_api_key(self, cleaner):
        findings = cleaner.scan_text("Token: sk-abcdefghijklmnopqrstuvwxyz1234567890")
        kategorien = [f.kategorie for f in findings]
        assert "API_Key" in kategorien

    def test_erkennt_connection_string(self, cleaner):
        findings = cleaner.scan_text("DB: postgres://admin:secret@db.host:5432/prod")
        kategorien = [f.kategorie for f in findings]
        assert "Connection_String" in kategorien

    def test_leerer_text_keine_findings(self, cleaner):
        assert cleaner.scan_text("") == []
        assert cleaner.scan_text("   ") == []

    def test_sauberer_text_keine_findings(self, cleaner):
        findings = cleaner.scan_text("Dies ist ein normaler Satz ohne PII.")
        assert findings == []

    def test_ignoriert_safe_email(self, cleaner):
        findings = cleaner.scan_text("mail: test@example.com")
        kategorien = [f.kategorie for f in findings]
        assert "Email" not in kategorien

    def test_ignoriert_private_ip(self, cleaner):
        findings = cleaner.scan_text("Server: 192.168.1.1")
        kategorien = [f.kategorie for f in findings]
        assert "IPv4_extern" not in kategorien

    def test_ignoriert_dummy_iban(self, cleaner):
        findings = cleaner.scan_text("Test-IBAN: DE00 0000 0000 0000 0000 00")
        kategorien = [f.kategorie for f in findings]
        assert "IBAN" not in kategorien

    def test_mehrere_pii_typen(self, cleaner):
        text = "Max, IBAN: DE89 3704 0044 0532 0130 00, Tel: +49 170 1234567"
        findings = cleaner.scan_text(text)
        kategorien = {f.kategorie for f in findings}
        assert "IBAN" in kategorien
        assert "Telefon" in kategorien

    def test_finding_hat_mock_wert(self, cleaner):
        findings = cleaner.scan_text("max@example.de")
        assert findings[0].ersetzt_durch
        assert findings[0].ersetzt_durch != "max@example.de"


# ─── Text-Level: clean_text ──────────────────────────


class TestCleanText:
    """clean_text ersetzt PII durch Mock-Daten."""

    def test_ersetzt_email(self, cleaner):
        result = cleaner.clean_text("Kontakt: max@example.de")
        assert "max@example.de" not in result.bereinigt
        assert "@example.test" in result.bereinigt
        assert result.geaendert

    def test_ersetzt_iban(self, cleaner):
        result = cleaner.clean_text("IBAN: DE89 3704 0044 0532 0130 00")
        assert "DE89" not in result.bereinigt
        assert "DE00" in result.bereinigt
        assert result.geaendert

    def test_sauberer_text_unveraendert(self, cleaner):
        text = "Ein normaler Satz."
        result = cleaner.clean_text(text)
        assert result.bereinigt == text
        assert not result.geaendert

    def test_leerer_text(self, cleaner):
        result = cleaner.clean_text("")
        assert result.bereinigt == ""
        assert not result.geaendert

    def test_result_hat_findings(self, cleaner):
        result = cleaner.clean_text("password=geheim123")
        assert len(result.findings) > 0
        assert result.findings[0].kategorie == "Credentials"

    def test_original_erhalten(self, cleaner):
        text = "max@example.de"
        result = cleaner.clean_text(text)
        assert result.original == text


# ─── Datei-Level: scan_file ──────────────────────────


class TestScanFile:
    """scan_file scannt verschiedene Dateiformate."""

    def test_scan_textdatei(self, cleaner, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("Zeile 1\nKontakt: max@example.de\nZeile 3\n")
        report = cleaner.scan_file(f)
        assert report.hat_pii
        assert "Email" in report.kategorien

    def test_scan_json(self, cleaner, tmp_path):
        f = tmp_path / "data.json"
        f.write_text(json.dumps({"name": "test", "email": "max@example.de"}))
        report = cleaner.scan_file(f)
        assert report.hat_pii
        assert any(f.pfad for f in report.findings)

    def test_scan_jsonl(self, cleaner, tmp_path):
        f = tmp_path / "data.jsonl"
        lines = [
            json.dumps({"msg": "Hallo"}),
            json.dumps({"email": "max@example.de", "iban": "DE89 3704 0044 0532 0130 00"}),
        ]
        f.write_text("\n".join(lines) + "\n")
        report = cleaner.scan_file(f)
        assert report.hat_pii
        # Zeile 2 sollte Findings haben
        assert any(finding.zeile == 2 for finding in report.findings)

    def test_scan_saubere_datei(self, cleaner, tmp_path):
        f = tmp_path / "clean.txt"
        f.write_text("Keine personenbezogenen Daten hier.\n")
        report = cleaner.scan_file(f)
        assert not report.hat_pii

    def test_scan_fehlende_datei(self, cleaner):
        report = cleaner.scan_file("/nicht/vorhanden.txt")
        assert report.fehler
        assert not report.hat_pii

    def test_scan_jsonl_mit_pfaden(self, cleaner, tmp_path):
        f = tmp_path / "audit.jsonl"
        line = json.dumps({"user": {"email": "max@example.de"}, "action": "login"})
        f.write_text(line + "\n")
        report = cleaner.scan_file(f)
        assert report.hat_pii
        # Pfad sollte verschachtelten Key zeigen
        email_findings = [fi for fi in report.findings if fi.kategorie == "Email"]
        assert any("user" in fi.pfad or "email" in fi.pfad for fi in email_findings)


# ─── Datei-Level: clean_file ─────────────────────────


class TestCleanFile:
    """clean_file bereinigt Dateien in-place oder dry-run."""

    def test_clean_text_datei_dry(self, cleaner, tmp_path):
        f = tmp_path / "test.txt"
        original = "Kontakt: max@example.de\n"
        f.write_text(original)
        result = cleaner.clean_file(f, dry_run=True)
        assert result.geaendert
        # Datei unveraendert (dry-run)
        assert f.read_text() == original

    def test_clean_text_datei_inplace(self, cleaner, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("Kontakt: max@example.de\n")
        result = cleaner.clean_file(f)
        assert result.geaendert
        # Datei geaendert
        inhalt = f.read_text()
        assert "max@example.de" not in inhalt
        assert "@example.test" in inhalt

    def test_clean_mit_backup(self, cleaner, tmp_path):
        f = tmp_path / "test.txt"
        original = "IBAN: DE89 3704 0044 0532 0130 00\n"
        f.write_text(original)
        cleaner.clean_file(f, backup=True)
        bak = tmp_path / "test.txt.bak"
        assert bak.exists()
        assert bak.read_text() == original

    def test_clean_jsonl(self, cleaner, tmp_path):
        f = tmp_path / "data.jsonl"
        lines = [
            json.dumps({"msg": "ok"}),
            json.dumps({"email": "max@example.de"}),
        ]
        f.write_text("\n".join(lines) + "\n")
        result = cleaner.clean_file(f)
        assert result.geaendert

        # Zeile 1 unveraendert, Zeile 2 bereinigt
        neue_zeilen = f.read_text().strip().split("\n")
        zeile2 = json.loads(neue_zeilen[1])
        assert "max@example.de" not in zeile2["email"]
        assert "@example.test" in zeile2["email"]

    def test_clean_json(self, cleaner, tmp_path):
        f = tmp_path / "data.json"
        data = {"nutzer": [{"email": "max@example.de"}, {"email": "lisa@example.de"}]}
        f.write_text(json.dumps(data))
        result = cleaner.clean_file(f)
        assert result.geaendert

        neuer_inhalt = json.loads(f.read_text())
        for nutzer in neuer_inhalt["nutzer"]:
            assert "@example.de" not in nutzer["email"]

    def test_clean_saubere_datei(self, cleaner, tmp_path):
        f = tmp_path / "clean.txt"
        f.write_text("Alles gut hier.\n")
        result = cleaner.clean_file(f)
        assert not result.geaendert


# ─── Verzeichnis-Level ────────────────────────────────


class TestScanDirectory:
    """scan_directory scannt Verzeichnisse."""

    def test_scan_verzeichnis(self, cleaner, tmp_path):
        (tmp_path / "a.txt").write_text("max@example.de")
        (tmp_path / "b.txt").write_text("Kein PII")
        (tmp_path / "c.json").write_text(json.dumps({"x": "ok"}))

        reports = cleaner.scan_directory(tmp_path)
        assert len(reports) >= 2
        pii_reports = [r for r in reports if r.hat_pii]
        assert len(pii_reports) >= 1

    def test_ueberspringt_clean_dateien(self, cleaner, tmp_path):
        (tmp_path / "data.csv.clean").write_text("mock data")
        (tmp_path / "data.bak").write_text("backup")
        reports = cleaner.scan_directory(tmp_path)
        dateien = [r.datei for r in reports]
        assert not any(".clean" in d for d in dateien)
        assert not any(".bak" in d for d in dateien)

    def test_scan_mit_muster(self, cleaner, tmp_path):
        (tmp_path / "a.jsonl").write_text('{"x": "max@example.de"}\n')
        (tmp_path / "b.txt").write_text("max@example.de")
        reports = cleaner.scan_directory(tmp_path, muster=["*.jsonl"])
        assert len(reports) == 1
        assert reports[0].datei.endswith(".jsonl")

    def test_scan_leeres_verzeichnis(self, cleaner, tmp_path):
        reports = cleaner.scan_directory(tmp_path)
        assert reports == []


# ─── Datenklassen ─────────────────────────────────────


class TestDatenklassen:
    """ScanReport und CleanResult Hilfsmethoden."""

    def test_scan_report_zusammenfassung(self):
        report = ScanReport(datei="test.txt", findings=[
            PIIFinding(kategorie="Email", wert="x@y.de", ersetzt_durch="mock"),
        ])
        assert "1 PII-Funde" in report.zusammenfassung()
        assert "Email" in report.zusammenfassung()

    def test_scan_report_ohne_findings(self):
        report = ScanReport(datei="test.txt")
        assert "Keine PII" in report.zusammenfassung()
        assert not report.hat_pii

    def test_clean_result_felder(self):
        result = CleanResult(
            datei="test.txt",
            original="max@example.de",
            bereinigt="mock@example.test",
            geaendert=True,
        )
        assert result.geaendert
        assert result.original != result.bereinigt


# ─── Edge Cases ───────────────────────────────────────


class TestEdgeCases:
    """Grenzfaelle und Robustheit."""

    def test_kaputtes_jsonl(self, cleaner, tmp_path):
        f = tmp_path / "broken.jsonl"
        f.write_text('{"ok": true}\nnot json max@example.de\n{"ok": true}\n')
        report = cleaner.scan_file(f)
        # Kaputte Zeile wird als Text gescannt
        assert report.hat_pii

    def test_leere_datei(self, cleaner, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        report = cleaner.scan_file(f)
        assert not report.hat_pii

    def test_verschachtelte_json_tiefe(self, cleaner, tmp_path):
        f = tmp_path / "deep.json"
        data = {"a": {"b": {"c": {"email": "max@example.de"}}}}
        f.write_text(json.dumps(data))
        report = cleaner.scan_file(f)
        assert report.hat_pii
        assert any("a" in fi.pfad and "b" in fi.pfad for fi in report.findings)

    def test_clean_jsonl_erhalt_struktur(self, cleaner, tmp_path):
        f = tmp_path / "struct.jsonl"
        original_lines = [
            json.dumps({"id": 1, "data": "max@example.de"}),
            json.dumps({"id": 2, "data": "ok"}),
        ]
        f.write_text("\n".join(original_lines) + "\n")
        cleaner.clean_file(f)

        neue_zeilen = f.read_text().strip().split("\n")
        assert len(neue_zeilen) == 2
        for line in neue_zeilen:
            obj = json.loads(line)
            assert "id" in obj
            assert "data" in obj

    def test_tier1_nur_regex(self, cleaner_t1):
        """Tier 1 erkennt nur Regex-PII, keine Keywords."""
        findings = cleaner_t1.scan_text("password=geheim123")
        kategorien = [f.kategorie for f in findings]
        assert "Credentials" not in kategorien

    def test_tier2_erkennt_keywords(self, cleaner):
        """Tier 2 erkennt auch Keyword-basierte PII."""
        findings = cleaner.scan_text("password=geheim123")
        kategorien = [f.kategorie for f in findings]
        assert "Credentials" in kategorien
