# /// script
# requires-python = ">=3.10"
# dependencies = ["pytest"]
# ///
"""
TDD-Tests fuer den DSGVO Prompt-Guard Hook
============================================
Testet ob der Hook personenbezogene Daten in Prompts erkennt und blockiert.

Hook: dsgvo-prompt-guard.py (UserPromptSubmit)
"""
from __future__ import annotations

from tests.helpers import make_prompt_input, run_hook

HOOK = "dsgvo-prompt-guard.py"


class TestBlockPiiInPrompts:
    """Prompts mit personenbezogenen Daten muessen blockiert werden."""

    def test_block_iban(self):
        """IBAN im Prompt wird erkannt."""
        result = run_hook(HOOK, make_prompt_input(
            "Ueberweise an DE89370400440532013000"
        ))
        assert result.get("decision") == "block"

    def test_block_phone_number(self):
        """Telefonnummer wird erkannt."""
        result = run_hook(HOOK, make_prompt_input(
            "Ruf mal +49 170 1234567 an"
        ))
        assert result.get("decision") == "block"

    def test_block_birthdate(self):
        """Geburtsdatum wird erkannt."""
        result = run_hook(HOOK, make_prompt_input(
            "Geboren am 15.03.1985"
        ))
        assert result.get("decision") == "block"

    def test_block_sozialversicherungsnr(self):
        """Sozialversicherungsnummer wird erkannt."""
        result = run_hook(HOOK, make_prompt_input(
            "SVN: 12A345678B901"
        ))
        assert result.get("decision") == "block"


class TestAllowSafePrompts:
    """Technische Prompts ohne PII muessen erlaubt werden."""

    def test_allow_code_question(self):
        """Technische Fragen sind erlaubt."""
        result = run_hook(HOOK, make_prompt_input(
            "Wie implementiere ich einen REST-Endpunkt in FastAPI?"
        ))
        assert result.get("decision") == "allow"

    def test_allow_file_operation(self):
        """Dateioperationen sind erlaubt."""
        result = run_hook(HOOK, make_prompt_input(
            "Lies die Datei config.json und zeige den Inhalt"
        ))
        assert result.get("decision") == "allow"

    def test_allow_empty_prompt(self):
        """Leerer Prompt wird erlaubt."""
        result = run_hook(HOOK, make_prompt_input(""))
        assert result.get("decision") == "allow"

    def test_allow_mock_iban(self):
        """Offensichtliche Test-IBAN (DE00...) ist erlaubt."""
        result = run_hook(HOOK, make_prompt_input(
            "Nutze die Test-IBAN DE00000000000000000000"
        ))
        # Dieser Test definiert gewuenschtes Verhalten:
        # Dummy-IBANs mit nur Nullen sollten nicht blockiert werden
        assert result.get("decision") == "allow"


class TestPromptGuardEdgeCases:
    """Grenzfaelle."""

    def test_no_prompt_field(self):
        """Fehlender prompt-Key wird erlaubt."""
        result = run_hook(HOOK, {"other_field": "value"})
        assert result.get("decision") == "allow"

    def test_invalid_json(self):
        """Leerer Input ohne prompt-Feld wird erlaubt (leerer Prompt)."""
        result = run_hook(HOOK, {})
        assert result.get("decision") == "allow"
