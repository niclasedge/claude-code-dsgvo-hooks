"""
Tests fuer PIIScanner Tier 3 (GLiNER NLP)
==========================================
Testet Named Entity Recognition fuer unstrukturierte PII.
Erfordert gliner-Installation — Tests werden uebersprungen wenn nicht verfuegbar.
"""
from __future__ import annotations

import pytest

try:
    from gliner import GLiNER  # noqa: F401
    HAS_GLINER = True
except ImportError:
    HAS_GLINER = False

# PIIScanner importieren
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / ".claude" / "hooks"))
from pii_scanner_engine import PIIScanner


# ─── Tier 3: Deutsche Personennamen ──────────────────────

@pytest.mark.skipif(not HAS_GLINER, reason="GLiNER nicht installiert")
class TestTier3PersonenDeutsch:
    """Deutsche Personennamen muessen erkannt werden."""

    def test_vollstaendiger_name(self):
        scanner = PIIScanner()
        findings = scanner.scan("Max Mustermann hat angerufen.", tier=3)
        assert "Person" in findings

    def test_name_im_satz(self):
        scanner = PIIScanner()
        findings = scanner.scan("Bitte kontaktieren Sie Frau Erika Schmidt bezueglich des Angebots.", tier=3)
        assert "Person" in findings

    def test_mehrere_namen(self):
        scanner = PIIScanner()
        findings = scanner.scan("Das Meeting mit Hans Mueller und Petra Wagner findet morgen statt.", tier=3)
        assert "Person" in findings

    def test_name_mit_titel(self):
        scanner = PIIScanner()
        findings = scanner.scan("Dr. Friedrich Weber hat den Bericht unterschrieben.", tier=3)
        assert "Person" in findings

    def test_name_mit_umlaut(self):
        scanner = PIIScanner()
        findings = scanner.scan("Herr Juergen Schroeder ist der Ansprechpartner.", tier=3)
        assert "Person" in findings


# ─── Tier 3: Deutsche Adressen ───────────────────────────

@pytest.mark.skipif(not HAS_GLINER, reason="GLiNER nicht installiert")
class TestTier3AdressenDeutsch:
    """Deutsche Adressen muessen erkannt werden."""

    def test_strasse_mit_plz(self):
        scanner = PIIScanner()
        findings = scanner.scan("Die Filiale befindet sich in der Berliner Str. 42, 10115 Berlin.", tier=3)
        assert "Adresse" in findings

    def test_postfach_adresse(self):
        scanner = PIIScanner()
        findings = scanner.scan("Senden Sie die Unterlagen an Hauptstrasse 15, 80331 Muenchen.", tier=3)
        assert "Adresse" in findings

    def test_adresse_ohne_plz(self):
        scanner = PIIScanner()
        findings = scanner.scan("Das Buero ist am Alexanderplatz 1 in Berlin.", tier=3)
        assert "Adresse" in findings


# ─── Tier 3: Organisationen ──────────────────────────────

@pytest.mark.skipif(not HAS_GLINER, reason="GLiNER nicht installiert")
class TestTier3Organisationen:
    """Organisationsnamen muessen erkannt werden."""

    def test_deutsche_firma(self):
        scanner = PIIScanner()
        findings = scanner.scan("Die Siemens AG hat den Auftrag erhalten.", tier=3)
        assert "Organisation" in findings

    def test_bank(self):
        scanner = PIIScanner()
        findings = scanner.scan("Die Deutsche Bank hat die Ueberweisung bestaetigt.", tier=3)
        assert "Organisation" in findings

    def test_verein(self):
        scanner = PIIScanner()
        findings = scanner.scan("Der FC Bayern Muenchen spielt morgen.", tier=3)
        assert "Organisation" in findings


# ─── Tier 3: Englische Namen ─────────────────────────────

@pytest.mark.skipif(not HAS_GLINER, reason="GLiNER nicht installiert")
class TestTier3EnglischeNamen:
    """Englische Personennamen muessen ebenfalls erkannt werden."""

    def test_englischer_name(self):
        scanner = PIIScanner()
        findings = scanner.scan("Please contact John Smith regarding the proposal.", tier=3)
        assert "Person" in findings

    def test_englischer_name_mit_middle(self):
        scanner = PIIScanner()
        findings = scanner.scan("The report was written by Sarah Jane Miller.", tier=3)
        assert "Person" in findings


# ─── Tier 3: Gemischte Erkennung (Regex + NLP) ──────────

@pytest.mark.skipif(not HAS_GLINER, reason="GLiNER nicht installiert")
class TestTier3Gemischt:
    """Tier 1+2 Regex UND Tier 3 NLP muessen zusammen funktionieren."""

    def test_name_plus_email(self):
        scanner = PIIScanner()
        findings = scanner.scan(
            "Max Mustermann ist erreichbar unter max@example.de", tier=3
        )
        assert "Person" in findings, "NLP muss Name erkennen"
        assert "Email" in findings, "Regex muss Email erkennen"

    def test_name_plus_iban(self):
        scanner = PIIScanner()
        findings = scanner.scan(
            "Konto von Hans Mueller: DE89 3704 0044 0532 0130 00", tier=3
        )
        assert "Person" in findings
        assert "IBAN" in findings

    def test_adresse_plus_telefon(self):
        scanner = PIIScanner()
        findings = scanner.scan(
            "Berliner Str. 42, 10115 Berlin. Tel: +49 170 1234567", tier=3
        )
        assert "Adresse" in findings
        assert "Telefon" in findings

    def test_firma_plus_credentials(self):
        scanner = PIIScanner()
        findings = scanner.scan(
            "Siemens AG Zugang: password=geheim123", tier=3
        )
        assert "Organisation" in findings
        assert "Credentials" in findings


# ─── Tier 3: Sauberer Text ──────────────────────────────

@pytest.mark.skipif(not HAS_GLINER, reason="GLiNER nicht installiert")
class TestTier3SauberText:
    """Sauberer Text ohne PII darf keine NLP-Findings erzeugen."""

    def test_technischer_text(self):
        scanner = PIIScanner()
        findings = scanner.scan(
            "Die Funktion gibt einen Boolean zurueck. Der Algorithmus ist O(n).", tier=3
        )
        assert "Person" not in findings
        assert "Adresse" not in findings
        assert "Organisation" not in findings

    def test_code_snippet(self):
        scanner = PIIScanner()
        findings = scanner.scan(
            "def calculate_sum(a, b): return a + b", tier=3
        )
        assert "Person" not in findings

    def test_leerer_text(self):
        scanner = PIIScanner()
        findings = scanner.scan("", tier=3)
        assert len(findings) == 0


# ─── Tier 3: Fallback ohne GLiNER ───────────────────────

class TestTier3Fallback:
    """Ohne GLiNER-Installation muss Tier 3 graceful zurueckfallen."""

    def test_tier2_unaffected(self):
        """Tier 2 darf nicht von GLiNER-Verfuegbarkeit abhaengen."""
        scanner = PIIScanner()
        findings = scanner.scan("max@example.de", tier=2)
        assert "Email" in findings

    def test_tier3_returns_tier2_if_no_gliner(self):
        """Wenn GLiNER fehlt, soll Tier 3 mindestens Tier 2 liefern."""
        scanner = PIIScanner()
        findings = scanner.scan("max@example.de", tier=3)
        assert "Email" in findings


# ─── Tier 3: Score und Details ───────────────────────────

@pytest.mark.skipif(not HAS_GLINER, reason="GLiNER nicht installiert")
class TestTier3Details:
    """scan_detailed() soll Entity-Text und Score zurueckgeben."""

    def test_scan_detailed_returns_entities(self):
        scanner = PIIScanner()
        result = scanner.scan_detailed(
            "Max Mustermann wohnt in Berlin.", tier=3
        )
        assert isinstance(result, dict)
        assert "categories" in result
        assert "entities" in result
        assert "Person" in result["categories"]
        # entities sollen text, label, score haben
        person_entities = [e for e in result["entities"] if e["label"] == "Person"]
        assert len(person_entities) > 0
        assert "text" in person_entities[0]
        assert "score" in person_entities[0]

    def test_scan_detailed_tier2_only(self):
        scanner = PIIScanner()
        result = scanner.scan_detailed("max@example.de", tier=2)
        assert "Email" in result["categories"]
        # Keine NLP-Entities bei Tier 2
        assert len(result.get("entities", [])) == 0


# ─── Tier 1+2 Regression ────────────────────────────────

class TestTier12Regression:
    """Bestehende Tier 1+2 Funktionalitaet darf nicht brechen."""

    def test_tier1_email(self):
        scanner = PIIScanner()
        assert "Email" in scanner.scan("max@example.de", tier=1)

    def test_tier1_iban(self):
        scanner = PIIScanner()
        assert "IBAN" in scanner.scan("DE89 3704 0044 0532 0130 00", tier=1)

    def test_tier2_credentials(self):
        scanner = PIIScanner()
        assert "Credentials" in scanner.scan("password=geheim123", tier=2)

    def test_tier2_default(self):
        """Default tier muss weiterhin 2 sein."""
        scanner = PIIScanner()
        findings = scanner.scan("password=geheim123")
        assert "Credentials" in findings
