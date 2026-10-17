#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
DSGVO PII-Cleaner — Dateien auf personenbezogene Daten pruefen und bereinigen
===============================================================================

Modulares Tool zum Scannen und Bereinigen von PII in beliebigen Dateien.
Nutzt den zentralen PIIScanner (Tier 1-3) fuer die Erkennung und
ersetzt gefundene PII durch Mock-Daten.

Einsatzbereiche:
  - .claude/ Konfigurationsdateien (JSONL, JSON, MD)
  - Source-Code mit hartcodierten PII
  - Log-Dateien, Audit-Trails
  - Beliebige Textdateien

Verwendung als CLI:
  uv run .claude/tools/pii_cleaner.py                        # Interaktiv: Verzeichnis waehlen
  uv run .claude/tools/pii_cleaner.py scan <pfad>            # Scan mit Bericht
  uv run .claude/tools/pii_cleaner.py clean <pfad>           # PII ersetzen (in-place)
  uv run .claude/tools/pii_cleaner.py clean <pfad> --dry     # Vorschau ohne Aenderung
  uv run .claude/tools/pii_cleaner.py clean <pfad> --backup  # Sicherung vor Aenderung

Verwendung als Library:
  from pii_cleaner import PIICleaner
  cleaner = PIICleaner(tier=3)
  report = cleaner.scan_file("data.jsonl")
  result = cleaner.clean_file("data.jsonl", dry_run=True)
  result = cleaner.clean_text("Max Mustermann, IBAN: DE89...")
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path


# ─── PIIScanner importieren ────────────────────────────
# Relativ zum Tool-Verzeichnis: ../hooks/pii_scanner_engine.py
_HOOKS_DIR = str(Path(__file__).resolve().parent.parent / "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

from pii_scanner_engine import PIIScanner  # noqa: E402


# ─── Mock-Daten fuer Ersetzungen ──────────────────────

MOCK_POOLS: dict[str, list[str]] = {
    # Tier 1: Regex
    "IBAN": [f"DE00 0000 0000 0000 00{i:02d}" for i in range(20)],
    "Telefon": [f"+49 000 {i:07d}" for i in range(1, 20)],
    "Geburtsdatum": ["01.01.2000", "02.02.2001", "03.03.2002", "04.04.2003"],
    "SVN": ["00A000000A000", "00B000000B000", "00C000000C000"],
    "Email": [f"testuser.{i:03d}@example.test" for i in range(1, 20)],
    "IPv4_extern": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
    # Tier 2: Keywords
    "Credentials": ["***REDACTED***"],
    "Connection_String": ["postgres://user:***@localhost:5432/testdb"],
    "API_Key": ["sk-MOCK0000000000000000"],
    # Tier 3: NLP
    "Person": [
        "Anna Beispiel", "Peter Musterfall", "Erika Musterfrau",
        "Test Testperson", "Demo Benutzer", "Probe Mitarbeiter",
    ],
    "Organisation": ["Muster GmbH", "Beispiel AG", "Test Corp."],
    "Adresse": [
        "Musterstrasse 1, 10000 Musterstadt",
        "Beispielweg 42, 20000 Beispielstadt",
    ],
}

_mock_counters: dict[str, int] = {}


def _next_mock(category: str) -> str:
    """Naechsten Mock-Wert aus dem Pool holen (Round-Robin)."""
    pool = MOCK_POOLS.get(category, ["***REDACTED***"])
    idx = _mock_counters.get(category, 0)
    _mock_counters[category] = idx + 1
    return pool[idx % len(pool)]


def _reset_mock_counters() -> None:
    _mock_counters.clear()


# ─── Datenklassen ─────────────────────────────────────


@dataclass
class PIIFinding:
    """Ein einzelner PII-Fund."""
    kategorie: str          # z.B. "Email", "Person", "IBAN"
    wert: str               # Originaltext
    ersetzt_durch: str       # Mock-Wert
    zeile: int = 0          # Zeilennummer (1-basiert)
    spalte: int = 0         # Spaltenoffset
    score: float = 1.0      # Konfidenz (0-1, Tier 3)
    pfad: str = ""          # JSON-Pfad bei strukturierten Daten
    datei: str = ""         # Dateiname


@dataclass
class ScanReport:
    """Ergebnis eines Scans."""
    datei: str
    findings: list[PIIFinding] = field(default_factory=list)
    fehler: str = ""

    @property
    def hat_pii(self) -> bool:
        return len(self.findings) > 0

    @property
    def kategorien(self) -> list[str]:
        return sorted(set(f.kategorie for f in self.findings))

    def zusammenfassung(self) -> str:
        if not self.findings:
            return f"  {self.datei}: Keine PII gefunden"
        cats = ", ".join(self.kategorien)
        return f"  {self.datei}: {len(self.findings)} PII-Funde ({cats})"


@dataclass
class CleanResult:
    """Ergebnis einer Bereinigung."""
    datei: str
    original: str           # Originalinhalt
    bereinigt: str          # Bereinigter Inhalt
    findings: list[PIIFinding] = field(default_factory=list)
    geaendert: bool = False
    fehler: str = ""


# ─── PIICleaner Kernklasse ────────────────────────────


class PIICleaner:
    """
    Modularer PII-Scanner und -Bereiniger.

    Verwendung:
        cleaner = PIICleaner(tier=3)

        # Einzelne Datei scannen
        report = cleaner.scan_file("data.jsonl")

        # Einzelne Datei bereinigen
        result = cleaner.clean_file("data.jsonl", dry_run=True)

        # Text direkt bereinigen
        result = cleaner.clean_text("Max Mustermann wohnt in Berlin")

        # Verzeichnis scannen
        reports = cleaner.scan_directory("/pfad/zum/verzeichnis")
    """

    def __init__(self, tier: int = 3):
        self.tier = tier
        self.scanner = PIIScanner()

    # ─── Text-Level API ───────────────────────────────

    def scan_text(self, text: str, quelle: str = "") -> list[PIIFinding]:
        """Scannt Text auf PII und gibt Findings zurueck."""
        if not text or not text.strip():
            return []

        result = self.scanner.scan_detailed(text, tier=self.tier)
        findings: list[PIIFinding] = []

        # Tier 1+2: Kategorien mit Regex-Matches fuer genaue Position
        for kategorie in result["categories"]:
            if kategorie in ("Person", "Organisation", "Adresse"):
                continue  # Werden durch Tier 3 Entities abgedeckt
            matches = self._find_matches(text, kategorie)
            for wert, start in matches:
                # Zeilennummer berechnen
                zeile = text[:start].count("\n") + 1
                findings.append(PIIFinding(
                    kategorie=kategorie,
                    wert=wert,
                    ersetzt_durch=_next_mock(kategorie),
                    zeile=zeile,
                    spalte=start - text.rfind("\n", 0, start) - 1,
                    datei=quelle,
                ))

        # Tier 3: NLP Entities
        for entity in result["entities"]:
            label = entity["label"]
            findings.append(PIIFinding(
                kategorie=label,
                wert=entity["text"],
                ersetzt_durch=_next_mock(label),
                score=entity.get("score", 1.0),
                datei=quelle,
            ))

        return findings

    def clean_text(self, text: str, quelle: str = "") -> CleanResult:
        """Bereinigt Text: ersetzt PII durch Mock-Daten."""
        if not text or not text.strip():
            return CleanResult(datei=quelle, original=text, bereinigt=text)

        _reset_mock_counters()
        findings = self.scan_text(text, quelle=quelle)

        if not findings:
            return CleanResult(datei=quelle, original=text, bereinigt=text)

        # Ersetzungen von hinten nach vorne (damit Offsets stimmen)
        bereinigt = text
        # Sammle alle Ersetzungen mit Position
        replacements = self._build_replacements(text, findings)

        # Sortiere absteigend nach Position
        replacements.sort(key=lambda r: r[0], reverse=True)
        for start, end, mock_wert in replacements:
            bereinigt = bereinigt[:start] + mock_wert + bereinigt[end:]

        return CleanResult(
            datei=quelle,
            original=text,
            bereinigt=bereinigt,
            findings=findings,
            geaendert=(bereinigt != text),
        )

    # ─── Datei-Level API ──────────────────────────────

    def scan_file(self, pfad: str | Path) -> ScanReport:
        """Scannt eine einzelne Datei auf PII."""
        pfad = Path(pfad)
        datei = str(pfad)

        if not pfad.exists():
            return ScanReport(datei=datei, fehler=f"Datei nicht gefunden: {pfad}")

        try:
            content = pfad.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return ScanReport(datei=datei, fehler=f"Lesefehler: {e}")

        suffix = pfad.suffix.lower()

        if suffix == ".jsonl":
            findings = self._scan_jsonl(content, datei)
        elif suffix == ".json":
            findings = self._scan_json(content, datei)
        else:
            findings = self._scan_text_lines(content, datei)

        return ScanReport(datei=datei, findings=findings)

    def clean_file(
        self,
        pfad: str | Path,
        dry_run: bool = False,
        backup: bool = False,
    ) -> CleanResult:
        """Bereinigt eine Datei: ersetzt PII durch Mock-Daten.

        Args:
            pfad: Dateipfad
            dry_run: Nur Vorschau, keine Aenderung
            backup: .bak-Sicherung vor Aenderung erstellen
        """
        pfad = Path(pfad)
        datei = str(pfad)
        _reset_mock_counters()

        if not pfad.exists():
            return CleanResult(
                datei=datei, original="", bereinigt="",
                fehler=f"Datei nicht gefunden: {pfad}",
            )

        try:
            content = pfad.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return CleanResult(
                datei=datei, original="", bereinigt="",
                fehler=f"Lesefehler: {e}",
            )

        suffix = pfad.suffix.lower()

        if suffix == ".jsonl":
            result = self._clean_jsonl(content, datei)
        elif suffix == ".json":
            result = self._clean_json(content, datei)
        else:
            result = self.clean_text(content, quelle=datei)

        if not dry_run and result.geaendert:
            if backup:
                shutil.copy2(pfad, str(pfad) + ".bak")
            pfad.write_text(result.bereinigt, encoding="utf-8")

        return result

    # ─── Verzeichnis-Level API ────────────────────────

    def scan_directory(
        self,
        verzeichnis: str | Path,
        muster: list[str] | None = None,
        rekursiv: bool = True,
    ) -> list[ScanReport]:
        """Scannt alle passenden Dateien in einem Verzeichnis.

        Args:
            verzeichnis: Zu scannendes Verzeichnis
            muster: Glob-Patterns (default: gaengige Textdateien)
            rekursiv: Unterverzeichnisse einbeziehen
        """
        verzeichnis = Path(verzeichnis)
        if not verzeichnis.is_dir():
            return [ScanReport(datei=str(verzeichnis), fehler="Kein Verzeichnis")]

        if muster is None:
            muster = [
                "*.jsonl", "*.json", "*.txt", "*.md", "*.log",
                "*.csv", "*.tsv", "*.yml", "*.yaml",
                "*.py", "*.js", "*.ts", "*.sh",
            ]

        dateien: set[Path] = set()
        for m in muster:
            glob_fn = verzeichnis.rglob if rekursiv else verzeichnis.glob
            dateien.update(glob_fn(m))

        # Sortiert nach Name
        reports = []
        for datei in sorted(dateien):
            if datei.is_file() and not self._soll_uebersprungen(datei):
                reports.append(self.scan_file(datei))

        return reports

    def clean_directory(
        self,
        verzeichnis: str | Path,
        muster: list[str] | None = None,
        dry_run: bool = False,
        backup: bool = False,
        rekursiv: bool = True,
    ) -> list[CleanResult]:
        """Bereinigt alle passenden Dateien in einem Verzeichnis."""
        verzeichnis = Path(verzeichnis)
        if not verzeichnis.is_dir():
            return []

        if muster is None:
            muster = ["*.jsonl", "*.json", "*.txt", "*.md", "*.log"]

        dateien: set[Path] = set()
        for m in muster:
            glob_fn = verzeichnis.rglob if rekursiv else verzeichnis.glob
            dateien.update(glob_fn(m))

        results = []
        for datei in sorted(dateien):
            if datei.is_file() and not self._soll_uebersprungen(datei):
                results.append(self.clean_file(datei, dry_run=dry_run, backup=backup))

        return results

    # ─── Format-spezifische Scanner ───────────────────

    def _scan_jsonl(self, content: str, datei: str) -> list[PIIFinding]:
        """Scannt JSONL zeilenweise, gibt Findings mit JSON-Pfaden zurueck."""
        findings: list[PIIFinding] = []
        for nr, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # Zeile als Plain-Text scannen
                for f in self.scan_text(line, quelle=datei):
                    f.zeile = nr
                    findings.append(f)
                continue

            # JSON-Werte rekursiv scannen
            self._scan_json_value(obj, findings, datei, zeile=nr, pfad_prefix=f"[{nr}]")

        return findings

    def _scan_json(self, content: str, datei: str) -> list[PIIFinding]:
        """Scannt JSON-Datei, gibt Findings mit JSON-Pfaden zurueck."""
        findings: list[PIIFinding] = []
        try:
            obj = json.loads(content)
        except json.JSONDecodeError:
            return self._scan_text_lines(content, datei)

        self._scan_json_value(obj, findings, datei, pfad_prefix="$")
        return findings

    def _scan_json_value(
        self,
        value: object,
        findings: list[PIIFinding],
        datei: str,
        zeile: int = 0,
        pfad_prefix: str = "$",
    ) -> None:
        """Rekursiver Scan ueber JSON-Werte."""
        if isinstance(value, str) and value.strip():
            for f in self.scan_text(value, quelle=datei):
                f.zeile = zeile
                f.pfad = pfad_prefix
                findings.append(f)
        elif isinstance(value, dict):
            for key, val in value.items():
                self._scan_json_value(val, findings, datei, zeile, f"{pfad_prefix}.{key}")
        elif isinstance(value, list):
            for i, item in enumerate(value):
                self._scan_json_value(item, findings, datei, zeile, f"{pfad_prefix}[{i}]")

    def _scan_text_lines(self, content: str, datei: str) -> list[PIIFinding]:
        """Scannt Text zeilenweise."""
        findings: list[PIIFinding] = []
        for nr, line in enumerate(content.splitlines(), 1):
            if not line.strip():
                continue
            for f in self.scan_text(line, quelle=datei):
                f.zeile = nr
                findings.append(f)
        return findings

    # ─── Format-spezifische Bereiniger ────────────────

    def _clean_jsonl(self, content: str, datei: str) -> CleanResult:
        """Bereinigt JSONL: ersetzt PII-Werte in JSON-Strukturen."""
        lines = content.splitlines()
        neue_zeilen: list[str] = []
        alle_findings: list[PIIFinding] = []
        geaendert = False

        for nr, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                neue_zeilen.append(line)
                continue

            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                # Plain-Text-Zeile bereinigen
                result = self.clean_text(stripped, quelle=datei)
                neue_zeilen.append(result.bereinigt)
                for f in result.findings:
                    f.zeile = nr
                alle_findings.extend(result.findings)
                if result.geaendert:
                    geaendert = True
                continue

            # JSON-Objekt rekursiv bereinigen
            neues_obj, zf = self._clean_json_value(obj, datei, zeile=nr, pfad_prefix=f"[{nr}]")
            alle_findings.extend(zf)
            neue_zeile = json.dumps(neues_obj, ensure_ascii=False)
            if neue_zeile != stripped:
                geaendert = True
            neue_zeilen.append(neue_zeile)

        bereinigt = "\n".join(neue_zeilen)
        # Original-Zeilenende beibehalten
        if content.endswith("\n"):
            bereinigt += "\n"

        return CleanResult(
            datei=datei,
            original=content,
            bereinigt=bereinigt,
            findings=alle_findings,
            geaendert=geaendert,
        )

    def _clean_json(self, content: str, datei: str) -> CleanResult:
        """Bereinigt JSON-Datei: ersetzt PII-Werte."""
        try:
            obj = json.loads(content)
        except json.JSONDecodeError:
            return self.clean_text(content, quelle=datei)

        neues_obj, findings = self._clean_json_value(obj, datei, pfad_prefix="$")
        bereinigt = json.dumps(neues_obj, ensure_ascii=False, indent=2) + "\n"
        geaendert = (bereinigt.strip() != content.strip())

        return CleanResult(
            datei=datei,
            original=content,
            bereinigt=bereinigt,
            findings=findings,
            geaendert=geaendert,
        )

    def _clean_json_value(
        self,
        value: object,
        datei: str,
        zeile: int = 0,
        pfad_prefix: str = "$",
    ) -> tuple[object, list[PIIFinding]]:
        """Rekursive Bereinigung von JSON-Werten."""
        findings: list[PIIFinding] = []

        if isinstance(value, str) and value.strip():
            result = self.clean_text(value, quelle=datei)
            for f in result.findings:
                f.zeile = zeile
                f.pfad = pfad_prefix
            findings.extend(result.findings)
            return result.bereinigt, findings

        elif isinstance(value, dict):
            neues_dict = {}
            for key, val in value.items():
                neuer_val, vf = self._clean_json_value(val, datei, zeile, f"{pfad_prefix}.{key}")
                neues_dict[key] = neuer_val
                findings.extend(vf)
            return neues_dict, findings

        elif isinstance(value, list):
            neue_liste = []
            for i, item in enumerate(value):
                neues_item, lf = self._clean_json_value(item, datei, zeile, f"{pfad_prefix}[{i}]")
                neue_liste.append(neues_item)
                findings.extend(lf)
            return neue_liste, findings

        return value, findings

    # ─── Hilfsfunktionen ──────────────────────────────

    def _find_matches(self, text: str, kategorie: str) -> list[tuple[str, int]]:
        """Findet alle Matches einer Kategorie mit Position."""
        matches: list[tuple[str, int]] = []

        # Tier 1: Regex-Patterns direkt vom Scanner
        pattern = self.scanner.PATTERNS.get(kategorie)
        if pattern:
            for m in pattern.finditer(text):
                wert = m.group()
                # False-Positives filtern
                if kategorie == "Email" and self.scanner._is_safe_email(wert):
                    continue
                if kategorie == "IBAN" and self.scanner.SAFE_IBAN_PATTERN.match(wert):
                    continue
                if kategorie == "IPv4_extern" and self.scanner._is_private_ip(wert):
                    continue
                matches.append((wert, m.start()))
            return matches

        # Tier 2: Keyword-Patterns
        pattern_lists = {
            "Credentials": self.scanner.CREDENTIAL_PATTERNS,
            "Connection_String": self.scanner.CONNECTION_STRING_PATTERNS,
            "API_Key": self.scanner.API_KEY_PATTERNS,
        }
        patterns = pattern_lists.get(kategorie, [])
        for p in patterns:
            for m in p.finditer(text):
                matches.append((m.group(), m.start()))

        return matches

    def _build_replacements(
        self, text: str, findings: list[PIIFinding]
    ) -> list[tuple[int, int, str]]:
        """Baut Ersetzungsliste: (start, end, mock_wert)."""
        replacements: list[tuple[int, int, str]] = []
        used_ranges: list[tuple[int, int]] = []

        for f in findings:
            # Position im Text finden
            start = text.find(f.wert)
            if start == -1:
                continue

            end = start + len(f.wert)

            # Ueberlappungen vermeiden
            overlaps = any(
                not (end <= us or start >= ue) for us, ue in used_ranges
            )
            if overlaps:
                continue

            used_ranges.append((start, end))
            replacements.append((start, end, f.ersetzt_durch))

        return replacements

    def _soll_uebersprungen(self, pfad: Path) -> bool:
        """Prueft ob eine Datei uebersprungen werden soll."""
        name = pfad.name.lower()
        # .clean und .bak Dateien ueberspringen
        if name.endswith((".clean", ".bak")):
            return True
        # __pycache__ und .git
        parts = pfad.parts
        if "__pycache__" in parts or ".git" in parts:
            return True
        # Binaerdateien
        if pfad.suffix.lower() in (".pyc", ".pyo", ".so", ".dll", ".exe", ".bin"):
            return True
        return False


# ─── CLI Ausgabe-Hilfsfunktionen ──────────────────────


def _print_findings(findings: list[PIIFinding], farbig: bool = True) -> None:
    """Gibt Findings formatiert aus."""
    if not findings:
        print("  Keine PII gefunden.")
        return

    for f in findings:
        ort = f"Z.{f.zeile}" if f.zeile else ""
        if f.pfad:
            ort = f"{ort} {f.pfad}" if ort else f.pfad
        score_str = f" ({f.score:.0%})" if f.score < 1.0 else ""

        if farbig:
            print(
                f"  \033[31m{f.kategorie}\033[0m{score_str}: "
                f"\033[33m{f.wert}\033[0m → \033[32m{f.ersetzt_durch}\033[0m"
                f"  {ort}"
            )
        else:
            print(
                f"  {f.kategorie}{score_str}: "
                f"{f.wert} -> {f.ersetzt_durch}"
                f"  {ort}"
            )


def _print_report(report: ScanReport) -> None:
    """Gibt einen Scan-Report aus."""
    if report.fehler:
        print(f"\n\033[31mFehler\033[0m: {report.datei}: {report.fehler}")
        return

    if not report.hat_pii:
        print(f"\n\033[32m✓\033[0m {report.datei}: Keine PII")
        return

    print(f"\n\033[31m✗\033[0m {report.datei}: {len(report.findings)} PII-Funde")
    _print_findings(report.findings)


# ─── CLI Commands ─────────────────────────────────────


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan-Befehl: Dateien/Verzeichnisse auf PII pruefen."""
    cleaner = PIICleaner(tier=args.tier)
    pfad = Path(args.pfad)

    if pfad.is_file():
        report = cleaner.scan_file(pfad)
        _print_report(report)
        return 1 if report.hat_pii else 0

    elif pfad.is_dir():
        muster = args.muster.split(",") if args.muster else None
        reports = cleaner.scan_directory(pfad, muster=muster)

        if not reports:
            print("Keine scannbaren Dateien gefunden.")
            return 0

        pii_count = 0
        for r in reports:
            if r.hat_pii or args.alle:
                _print_report(r)
            if r.hat_pii:
                pii_count += 1

        print(f"\n{'─' * 50}")
        print(f"Gesamt: {len(reports)} Dateien gescannt, {pii_count} mit PII")
        return 1 if pii_count > 0 else 0

    else:
        print(f"Pfad nicht gefunden: {pfad}")
        return 2


def cmd_clean(args: argparse.Namespace) -> int:
    """Clean-Befehl: PII in Dateien ersetzen."""
    cleaner = PIICleaner(tier=args.tier)
    pfad = Path(args.pfad)

    if pfad.is_file():
        result = cleaner.clean_file(pfad, dry_run=args.dry, backup=args.backup)

        if result.fehler:
            print(f"Fehler: {result.fehler}")
            return 2

        if not result.geaendert:
            print(f"\033[32m✓\033[0m {pfad}: Keine PII gefunden")
            return 0

        modus = "VORSCHAU" if args.dry else "BEREINIGT"
        print(f"\033[33m{modus}\033[0m {pfad}: {len(result.findings)} Ersetzungen")
        _print_findings(result.findings)

        if not args.dry:
            if args.backup:
                print(f"  Sicherung: {pfad}.bak")
            print(f"  Datei bereinigt: {pfad}")

        return 0

    elif pfad.is_dir():
        muster = args.muster.split(",") if args.muster else None
        results = cleaner.clean_directory(
            pfad, muster=muster, dry_run=args.dry, backup=args.backup,
        )

        if not results:
            print("Keine bearbeitbaren Dateien gefunden.")
            return 0

        geaendert_count = 0
        for r in results:
            if r.geaendert:
                modus = "VORSCHAU" if args.dry else "BEREINIGT"
                print(f"\n\033[33m{modus}\033[0m {r.datei}: {len(r.findings)} Ersetzungen")
                _print_findings(r.findings)
                geaendert_count += 1
            elif args.alle:
                print(f"\n\033[32m✓\033[0m {r.datei}: Keine PII")

        print(f"\n{'─' * 50}")
        modus = "Vorschau" if args.dry else "Bereinigt"
        print(f"{modus}: {geaendert_count}/{len(results)} Dateien mit PII")
        return 0

    else:
        print(f"Pfad nicht gefunden: {pfad}")
        return 2


def cmd_interaktiv() -> int:
    """Interaktiver Modus: Menu-gesteuert."""
    print("=" * 55)
    print("  DSGVO PII-Cleaner — Interaktiver Modus")
    print("=" * 55)
    print()
    print("  1. Verzeichnis scannen")
    print("  2. Datei scannen")
    print("  3. Datei bereinigen (Vorschau)")
    print("  4. Datei bereinigen (in-place)")
    print("  5. .claude/ Verzeichnis scannen")
    print("  6. logs/ Verzeichnis scannen")
    print()

    try:
        wahl = input("Auswahl [1-6]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return 0

    cleaner = PIICleaner(tier=3)

    if wahl == "1":
        pfad = input("Verzeichnis: ").strip() or "."
        reports = cleaner.scan_directory(pfad)
        for r in reports:
            _print_report(r)
        pii_count = sum(1 for r in reports if r.hat_pii)
        print(f"\n{len(reports)} Dateien gescannt, {pii_count} mit PII")

    elif wahl == "2":
        pfad = input("Datei: ").strip()
        if pfad:
            _print_report(cleaner.scan_file(pfad))

    elif wahl == "3":
        pfad = input("Datei: ").strip()
        if pfad:
            result = cleaner.clean_file(pfad, dry_run=True)
            if result.geaendert:
                print(f"VORSCHAU: {len(result.findings)} Ersetzungen")
                _print_findings(result.findings)
            else:
                print("Keine PII gefunden.")

    elif wahl == "4":
        pfad = input("Datei: ").strip()
        if pfad:
            confirm = input(f"Datei '{pfad}' in-place bereinigen? [j/N] ").strip().lower()
            if confirm == "j":
                result = cleaner.clean_file(pfad, backup=True)
                if result.geaendert:
                    print(f"BEREINIGT: {len(result.findings)} Ersetzungen (.bak erstellt)")
                    _print_findings(result.findings)
                else:
                    print("Keine PII gefunden.")

    elif wahl == "5":
        reports = cleaner.scan_directory(".claude", muster=["*.jsonl", "*.json", "*.md"])
        for r in reports:
            _print_report(r)
        pii_count = sum(1 for r in reports if r.hat_pii)
        print(f"\n{len(reports)} Dateien gescannt, {pii_count} mit PII")

    elif wahl == "6":
        reports = cleaner.scan_directory("logs", muster=["*.jsonl", "*.log", "*.json"])
        for r in reports:
            _print_report(r)
        pii_count = sum(1 for r in reports if r.hat_pii)
        print(f"\n{len(reports)} Dateien gescannt, {pii_count} mit PII")

    else:
        print("Ungueltige Auswahl.")
        return 1

    return 0


# ─── Main ─────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DSGVO PII-Cleaner — Dateien scannen und bereinigen",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  %(prog)s scan .claude/                     # .claude Verzeichnis scannen
  %(prog)s scan logs/ --muster "*.jsonl"     # Nur JSONL-Dateien
  %(prog)s clean data.jsonl --dry            # Vorschau der Bereinigung
  %(prog)s clean data.jsonl --backup         # In-place mit Sicherung
  %(prog)s clean logs/ --dry --tier 2        # Schneller Scan (nur Regex+Keywords)

Als Library:
  from pii_cleaner import PIICleaner
  cleaner = PIICleaner(tier=3)
  report = cleaner.scan_file("data.jsonl")
  result = cleaner.clean_file("data.jsonl", dry_run=True)
""",
    )
    sub = parser.add_subparsers(dest="befehl")

    # scan
    scan_p = sub.add_parser("scan", help="Dateien/Verzeichnisse auf PII scannen")
    scan_p.add_argument("pfad", help="Datei oder Verzeichnis")
    scan_p.add_argument("--tier", type=int, default=3, choices=[1, 2, 3],
                        help="Scanner-Tiefe: 1=Regex, 2=+Keywords, 3=+NLP (default: 3)")
    scan_p.add_argument("--muster", "-m", help="Glob-Patterns, kommagetrennt (z.B. '*.jsonl,*.json')")
    scan_p.add_argument("--alle", "-a", action="store_true", help="Auch saubere Dateien anzeigen")

    # clean
    clean_p = sub.add_parser("clean", help="PII in Dateien durch Mock-Daten ersetzen")
    clean_p.add_argument("pfad", help="Datei oder Verzeichnis")
    clean_p.add_argument("--dry", action="store_true", help="Nur Vorschau, keine Aenderung")
    clean_p.add_argument("--backup", action="store_true", help=".bak-Sicherung erstellen")
    clean_p.add_argument("--tier", type=int, default=3, choices=[1, 2, 3],
                         help="Scanner-Tiefe (default: 3)")
    clean_p.add_argument("--muster", "-m", help="Glob-Patterns, kommagetrennt")
    clean_p.add_argument("--alle", "-a", action="store_true", help="Auch saubere Dateien anzeigen")

    args = parser.parse_args()

    if args.befehl == "scan":
        return cmd_scan(args)
    elif args.befehl == "clean":
        return cmd_clean(args)
    else:
        return cmd_interaktiv()


if __name__ == "__main__":
    sys.exit(main())
