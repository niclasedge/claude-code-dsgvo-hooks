"""
Tests fuer .claude/tools/generate_mock_data.py — PIIScanner-Integration
================================================================
Testet dass der Generator den zentralen PIIScanner nutzt (Tier 1-3).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tests.helpers import require_mock_data_stack

require_mock_data_stack()

try:
    from gliner import GLiNER  # noqa: F401
    HAS_GLINER = True
except ImportError:
    HAS_GLINER = False

ROOT = Path(__file__).parent.parent
TOOL = ROOT / ".claude" / "tools" / "generate_mock_data.py"


def run_tool(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Fuehrt generate_mock_data.py aus."""
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True, text=True, timeout=30,
        cwd=str(cwd or ROOT),
    )


# ─── --dry ohne input = Verzeichnis-Scan ────────────────

class TestDryRepoScan:
    """--dry ohne input scannt das Verzeichnis."""

    def test_dry_without_input_scans_directory(self, tmp_path):
        """--dry ohne input muss Verzeichnis scannen."""
        # CSV mit PII erstellen
        csv_file = tmp_path / "kunden.csv"
        csv_file.write_text("Name,Email\nMax,max@example.de\n")
        result = run_tool("--dry", "--dir", str(tmp_path))
        assert result.returncode == 0
        assert "kunden.csv" in result.stdout

    def test_dry_scans_text_files(self, tmp_path):
        """Textdateien (.txt) muessen gescannt werden."""
        txt = tmp_path / "notes.txt"
        txt.write_text("Kontakt: max@example.de\nIBAN: DE89 3704 0044 0532 0130 00\n")
        result = run_tool("--dry", "--dir", str(tmp_path))
        assert result.returncode == 0
        assert "notes.txt" in result.stdout

    def test_dry_scans_ini_files(self, tmp_path):
        """Config-Dateien (.ini) muessen gescannt werden."""
        ini = tmp_path / "config.ini"
        ini.write_text("DB_PASSWORD=geheim123\n")
        result = run_tool("--dry", "--dir", str(tmp_path))
        assert result.returncode == 0
        assert "config.ini" in result.stdout

    def test_dry_scans_yaml_files(self, tmp_path):
        """YAML-Dateien muessen gescannt werden."""
        yml = tmp_path / "secrets.yml"
        yml.write_text("password: geheim123\napi_key: sk-abc123\n")
        result = run_tool("--dry", "--dir", str(tmp_path))
        assert result.returncode == 0
        assert "secrets.yml" in result.stdout

    def test_dry_skips_source_code(self, tmp_path):
        """Source-Code-Dateien sollen nicht als PII-Dateien gelistet werden."""
        py = tmp_path / "app.py"
        py.write_text('MOCK_DATES = ["01.01.2000"]\n')
        result = run_tool("--dry", "--dir", str(tmp_path))
        assert result.returncode == 0
        assert "app.py" not in result.stdout

    def test_dry_skips_clean_files(self, tmp_path):
        """Dateien mit .clean-Suffix sollen uebersprungen werden."""
        csv = tmp_path / "data.csv.clean"
        csv.write_text("Name,Email\nDummy,test@example.com\n")
        result = run_tool("--dry", "--dir", str(tmp_path))
        assert result.returncode == 0
        assert ".clean" not in result.stdout


# ─── PIIScanner-Integration fuer Tier 2 ─────────────────

class TestPIIScannerIntegration:
    """Der zentrale PIIScanner muss fuer Detection genutzt werden."""

    def test_detects_credentials_tier2(self, tmp_path):
        """Tier 2: Credentials muessen erkannt werden."""
        ini = tmp_path / "config.ini"
        ini.write_text("DB_PASSWORD=geheim123\nDB_HOST=localhost\n")
        result = run_tool("--dry", str(ini))
        assert result.returncode == 0
        assert "Credentials" in result.stdout or "password" in result.stdout.lower()

    def test_detects_connection_string_tier2(self, tmp_path):
        """Tier 2: Connection Strings muessen erkannt werden."""
        cfg = tmp_path / "db.cfg"
        cfg.write_text("url=postgres://user:pass@host:5432/db\n")
        result = run_tool("--dry", str(cfg))
        assert result.returncode == 0
        assert "Connection" in result.stdout or "postgres" in result.stdout

    def test_detects_api_key_tier2(self, tmp_path):
        """Tier 2: API Keys muessen erkannt werden."""
        cfg = tmp_path / "api.cfg"
        cfg.write_text("OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyz\n")
        result = run_tool("--dry", str(cfg))
        assert result.returncode == 0
        assert "API" in result.stdout or "key" in result.stdout.lower()

    def test_detects_email_tier1(self, tmp_path):
        """Tier 1: Emails muessen erkannt werden."""
        txt = tmp_path / "kontakte.txt"
        txt.write_text("Max Mustermann: max@example.de\n")
        result = run_tool("--dry", str(txt))
        assert result.returncode == 0
        assert "Email" in result.stdout or "email" in result.stdout

    def test_detects_iban_tier1(self, tmp_path):
        """Tier 1: IBANs muessen erkannt werden."""
        txt = tmp_path / "konten.txt"
        txt.write_text("Konto: DE89 3704 0044 0532 0130 00\n")
        result = run_tool("--dry", str(txt))
        assert result.returncode == 0
        assert "IBAN" in result.stdout


# ─── Bestehende Anonymisierung intakt ────────────────────

class TestAnonymizationIntact:
    """Anonymisierungsfunktion darf nicht brechen."""

    def test_csv_anonymization_works(self, tmp_path):
        csv_in = tmp_path / "input.csv"
        csv_in.write_text("Name,Email\nMax Mustermann,max@example.de\n")
        csv_out = tmp_path / "output.csv"
        result = run_tool(str(csv_in), "-o", str(csv_out))
        assert result.returncode == 0
        content = csv_out.read_text()
        assert "max@example.de" not in content
        assert "@example.test" in content

    def test_json_anonymization_works(self, tmp_path):
        json_in = tmp_path / "input.json"
        json_in.write_text('{"email": "max@example.de", "name": "Max Mustermann"}')
        json_out = tmp_path / "output.json"
        result = run_tool(str(json_in), "-o", str(json_out))
        assert result.returncode == 0
        data = json.loads(json_out.read_text())
        assert "example.de" not in data["email"]

    def test_cli_args_unchanged(self):
        """--help muss funktionieren."""
        result = run_tool("--help")
        assert result.returncode == 0
        assert "--dry" in result.stdout
        assert "--dir" in result.stdout
        assert "--output" in result.stdout


# ─── GLiNER NLP Tier 3 im Generator ─────────────────────

if HAS_GLINER:
    class TestGLiNERIntegration:
        """GLiNER Tier 3 muss im Generator aktiv sein."""

        def test_detects_person_name_in_txt(self, tmp_path):
            """Personennamen ohne Regex-Pattern muessen via NLP erkannt werden."""
            txt = tmp_path / "notiz.txt"
            txt.write_text("Max Mustermann hat angerufen.\n")
            result = run_tool("--dry", str(txt), cwd=ROOT)
            assert result.returncode == 0
            assert "Person" in result.stdout or "NLP" in result.stdout

        def test_detects_address_in_txt(self, tmp_path):
            """Adressen muessen via NLP erkannt werden."""
            txt = tmp_path / "lieferung.txt"
            txt.write_text("Lieferadresse: Berliner Str. 42, 10115 Berlin\n")
            result = run_tool("--dry", str(txt), cwd=ROOT)
            assert result.returncode == 0
            assert "Adresse" in result.stdout or "NLP" in result.stdout

        def test_detects_organization_in_txt(self, tmp_path):
            """Organisationsnamen muessen via NLP erkannt werden."""
            txt = tmp_path / "auftrag.txt"
            txt.write_text("Auftraggeber: Siemens AG, Muenchen\n")
            result = run_tool("--dry", str(txt), cwd=ROOT)
            assert result.returncode == 0
            assert "Organisation" in result.stdout or "NLP" in result.stdout

        def test_nlp_findings_show_score(self, tmp_path):
            """NLP-Findings muessen den Score anzeigen."""
            txt = tmp_path / "test.txt"
            txt.write_text("Dr. Friedrich Weber hat den Bericht unterschrieben.\n")
            result = run_tool("--dry", str(txt), cwd=ROOT)
            assert result.returncode == 0
            assert "NLP" in result.stdout

        def test_mixed_regex_and_nlp(self, tmp_path):
            """Regex + NLP muessen zusammen funktionieren."""
            txt = tmp_path / "mixed.txt"
            txt.write_text("Max Mustermann: max@example.de, IBAN DE89 3704 0044 0532 0130 00\n")
            result = run_tool("--dry", str(txt), cwd=ROOT)
            assert result.returncode == 0
            assert "Email" in result.stdout
            assert "IBAN" in result.stdout
            # NLP sollte auch den Namen finden
            assert "Person" in result.stdout or "NLP" in result.stdout

        def test_clean_text_no_nlp_findings(self, tmp_path):
            """Sauberer Text darf keine NLP-Findings erzeugen."""
            txt = tmp_path / "clean.txt"
            txt.write_text("Die Berechnung ergibt 42.\nDer Prozess ist abgeschlossen.\n")
            result = run_tool("--dry", str(txt), cwd=ROOT)
            assert result.returncode == 0
            assert "NLP" not in result.stdout

        def test_directory_scan_finds_nlp_pii(self, tmp_path):
            """Verzeichnis-Scan muss NLP-PII in Textdateien erkennen."""
            txt = tmp_path / "intern.txt"
            txt.write_text("Bitte kontaktieren Sie Frau Erika Schmidt.\n")
            result = run_tool("--dry", "--dir", str(tmp_path), cwd=ROOT)
            assert result.returncode == 0
            assert "intern.txt" in result.stdout

        def test_english_names_detected(self, tmp_path):
            """Auch englische Namen muessen erkannt werden."""
            txt = tmp_path / "meeting.txt"
            txt.write_text("Meeting with John Smith and Sarah Miller tomorrow.\n")
            result = run_tool("--dry", str(txt), cwd=ROOT)
            assert result.returncode == 0
            assert "Person" in result.stdout or "NLP" in result.stdout
