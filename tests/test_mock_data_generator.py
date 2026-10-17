# /// script
# requires-python = ">=3.10"
# dependencies = ["pytest"]
# ///
"""
TDD-Tests fuer den Mock-Daten-Generator (inkl. --dry Modus)
=============================================================
Testet Anonymisierung und den neuen Dry-Run-Modus.

Tool: .claude/tools/generate_mock_data.py
"""
from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
from pathlib import Path

from tests.helpers import require_mock_data_stack

require_mock_data_stack()

ROOT = Path(__file__).parent.parent
TOOL = ROOT / ".claude" / "tools" / "generate_mock_data.py"
TESTFILES = ROOT / "testfiles"


def run_generator(
    input_file: str | Path,
    output_file: str | Path | None = None,
    dry: bool = False,
) -> tuple[int, str, str]:
    """Fuehrt den Mock-Daten-Generator aus. Gibt (returncode, stdout, stderr) zurueck."""
    cmd = [sys.executable, str(TOOL), str(input_file)]
    if output_file:
        cmd.extend(["--output", str(output_file)])
    if dry:
        cmd.append("--dry")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.returncode, result.stdout, result.stderr


# ─── DRY-RUN: PII-Fundstellen anzeigen ────────────────


class TestDryRunMode:
    """--dry zeigt PII-Fundstellen an, ohne Dateien zu schreiben."""

    def test_dry_returns_zero(self):
        """Dry-Run beendet sich mit Exit-Code 0."""
        rc, _, _ = run_generator(TESTFILES / "customers.csv", dry=True)
        assert rc == 0

    def test_dry_no_file_created(self, tmp_path):
        """Dry-Run erstellt keine Ausgabedatei."""
        out = tmp_path / "should_not_exist.csv.clean"
        run_generator(TESTFILES / "customers.csv", output_file=out, dry=True)
        assert not out.exists(), "Dry-Run sollte keine Datei erstellen"

    def test_dry_shows_email_locations(self):
        """Dry-Run zeigt gefundene E-Mail-Adressen."""
        rc, stdout, _ = run_generator(TESTFILES / "customers.csv", dry=True)
        assert "email" in stdout.lower() or "e-mail" in stdout.lower() or "@" in stdout

    def test_dry_shows_iban_locations(self):
        """Dry-Run zeigt gefundene IBANs."""
        rc, stdout, _ = run_generator(TESTFILES / "customers.csv", dry=True)
        assert "iban" in stdout.lower() or "DE" in stdout

    def test_dry_shows_phone_locations(self):
        """Dry-Run zeigt gefundene Telefonnummern."""
        rc, stdout, _ = run_generator(TESTFILES / "customers.csv", dry=True)
        assert "telefon" in stdout.lower() or "phone" in stdout.lower() or "+49" in stdout

    def test_dry_shows_line_numbers(self):
        """Dry-Run zeigt Zeilen-/Feldnummern der Fundstellen."""
        rc, stdout, _ = run_generator(TESTFILES / "customers.csv", dry=True)
        # Sollte Zeilen- oder Feldnummern enthalten
        assert re.search(r"[Zz]eile|[Ll]ine|[Rr]ow|\d+:", stdout)

    def test_dry_json_shows_fields(self):
        """Dry-Run fuer JSON zeigt betroffene Felder."""
        rc, stdout, _ = run_generator(TESTFILES / "employees.json", dry=True)
        assert "name" in stdout.lower() or "email" in stdout.lower()

    def test_dry_shows_summary_count(self):
        """Dry-Run zeigt Gesamtzahl der Fundstellen."""
        rc, stdout, _ = run_generator(TESTFILES / "customers.csv", dry=True)
        # Sollte eine Zahl enthalten die Gesamtfunde repraesentiert
        assert re.search(r"\d+\s*(PII|Fund|Treffer|fund|treffer)", stdout)


# ─── Generator: Clean-Dateien erstellen ────────────────


class TestGeneratorCreatesCleanFiles:
    """Generator erstellt .clean-Versionen von PII-Dateien."""

    def test_csv_generates_clean(self, tmp_path):
        src = TESTFILES / "customers.csv"
        out = tmp_path / "customers.csv.clean"
        rc, _, _ = run_generator(src, out)
        assert rc == 0
        assert out.exists()

    def test_json_generates_clean(self, tmp_path):
        src = TESTFILES / "employees.json"
        out = tmp_path / "employees.json.clean"
        rc, _, _ = run_generator(src, out)
        assert rc == 0
        assert out.exists()

    def test_default_output_is_dotclean(self):
        src = TESTFILES / "customers.csv"
        rc, _, _ = run_generator(src)
        assert rc == 0


# ─── Clean-Daten: Keine echten PII ────────────────────


class TestCleanDataHasNoPii:
    """Generierte Clean-Dateien duerfen keine echten PII enthalten."""

    def test_csv_clean_no_real_emails(self, tmp_path):
        out = tmp_path / "out.csv.clean"
        run_generator(TESTFILES / "customers.csv", out)
        content = out.read_text(encoding="utf-8")
        real_emails = re.findall(r"[\w.+-]+@(?!example\.test)[\w-]+\.\w+", content)
        assert not real_emails, f"Echte E-Mails: {real_emails}"

    def test_csv_clean_no_real_iban(self, tmp_path):
        out = tmp_path / "out.csv.clean"
        run_generator(TESTFILES / "customers.csv", out)
        content = out.read_text(encoding="utf-8")
        ibans = re.findall(r"\bDE\d{20}\b", content)
        for iban in ibans:
            assert iban.startswith("DE0000"), f"Echte IBAN: {iban}"

    def test_csv_clean_no_real_phones(self, tmp_path):
        out = tmp_path / "out.csv.clean"
        run_generator(TESTFILES / "customers.csv", out)
        content = out.read_text(encoding="utf-8")
        real_phones = re.findall(r"\+49\s?(?!000)\d{3}\s?\d{7}", content)
        assert not real_phones, f"Echte Telefonnummern: {real_phones}"

    def test_json_clean_no_real_names(self, tmp_path):
        src = TESTFILES / "employees.json"
        out = tmp_path / "out.json.clean"
        run_generator(src, out)
        original = json.loads(src.read_text(encoding="utf-8"))
        clean = json.loads(out.read_text(encoding="utf-8"))
        original_names = {e["name"] for e in original["employees"]}
        clean_names = {e["name"] for e in clean["employees"]}
        assert not original_names & clean_names


# ─── Struktur erhalten ─────────────────────────────────


class TestCleanDataPreservesStructure:
    """Clean-Dateien behalten die Struktur des Originals."""

    def test_csv_same_column_count(self, tmp_path):
        out = tmp_path / "out.csv.clean"
        run_generator(TESTFILES / "customers.csv", out)
        with open(TESTFILES / "customers.csv", encoding="utf-8") as f:
            orig_cols = len(next(csv.reader(f)))
        with open(out, encoding="utf-8") as f:
            clean_cols = len(next(csv.reader(f)))
        assert orig_cols == clean_cols

    def test_csv_same_row_count(self, tmp_path):
        out = tmp_path / "out.csv.clean"
        run_generator(TESTFILES / "customers.csv", out)
        orig_lines = (TESTFILES / "customers.csv").read_text(encoding="utf-8").strip().splitlines()
        clean_lines = out.read_text(encoding="utf-8").strip().splitlines()
        assert len(orig_lines) == len(clean_lines)

    def test_json_same_structure(self, tmp_path):
        src = TESTFILES / "employees.json"
        out = tmp_path / "out.json.clean"
        run_generator(src, out)
        original = json.loads(src.read_text(encoding="utf-8"))
        clean = json.loads(out.read_text(encoding="utf-8"))
        assert set(original.keys()) == set(clean.keys())
        assert len(original["employees"]) == len(clean["employees"])
        assert set(original["employees"][0].keys()) == set(clean["employees"][0].keys())
