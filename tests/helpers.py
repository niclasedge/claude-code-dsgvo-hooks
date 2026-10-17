"""
DSGVO Hook Test-Hilfsfunktionen
=================================
Shared Utilities fuer alle Hook-Tests.
Hooks werden als Subprozesse getestet — genau wie Claude Code sie aufruft.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Projekt-Root
ROOT = Path(__file__).parent.parent
HOOKS_DIR = ROOT / ".claude" / "hooks"
TESTFILES_DIR = ROOT / "testfiles"


def require_mock_data_stack() -> None:
    """Skip the calling module unless the Presidio/spaCy stack and the German model are installed.

    Install: ``uv run --extra mock-data``, plus the spaCy model ``de_core_news_lg``.
    """
    pytest.importorskip("presidio_analyzer")
    spacy = pytest.importorskip("spacy")
    if not spacy.util.is_package("de_core_news_lg"):
        pytest.skip("spaCy model de_core_news_lg not installed", allow_module_level=True)


def run_hook(hook_name: str, stdin_data: dict, cwd: Path | None = None) -> dict:
    """
    Fuehrt einen Hook als Subprozess aus und gibt das JSON-Ergebnis zurueck.

    Args:
        hook_name: Dateiname des Hooks (z.B. 'dsgvo-pii-file-guard.py')
        stdin_data: Dict das als JSON via stdin gesendet wird
        cwd: Arbeitsverzeichnis (default: Projekt-Root)

    Returns:
        Geparstes JSON-Dict der Hook-Ausgabe
    """
    hook_path = HOOKS_DIR / hook_name
    if not hook_path.exists():
        pytest.fail(f"Hook nicht gefunden: {hook_path}")

    result = subprocess.run(
        [sys.executable, str(hook_path)],
        input=json.dumps(stdin_data),
        capture_output=True,
        text=True,
        timeout=10,
        cwd=str(cwd or ROOT),
        env={**os.environ, "CLAUDE_PROJECT_DIR": str(ROOT)},
    )

    if result.returncode not in (0, 2):
        pytest.fail(
            f"Hook '{hook_name}' Exit-Code {result.returncode}\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

    # Exit-Code 2 = blockierender Fehler (PostToolUse: Output verworfen)
    if result.returncode == 2:
        return {"error": result.stderr.strip() or "Hook blocked with exit code 2"}

    stdout = result.stdout.strip()
    if not stdout:
        return {}

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        pytest.fail(f"Hook '{hook_name}' kein valides JSON: {stdout}")
        return {}  # unreachable, fuer Type Checker

    # Normalisierung: Einheitliches Format fuer Tests
    # Damit Tests sowohl result.get("decision") als auch result["hookSpecificOutput"] nutzen koennen
    if "decision" not in parsed:
        hso = parsed.get("hookSpecificOutput")
        if isinstance(hso, dict):
            perm = hso.get("permissionDecision", "")
            if perm == "deny":
                parsed["decision"] = "block"
                parsed["reason"] = hso.get("permissionDecisionReason", "")
            elif perm == "allow":
                parsed["decision"] = "allow"
        elif not parsed or (len(parsed) == 1 and "message" in parsed):
            # Leere Antwort {} oder nur {"message": ...} = erlaubt
            parsed["decision"] = "allow"

    return parsed


def make_read_input(file_path: str | Path) -> dict:
    """Erstellt PreToolUse-Input fuer Read-Tool."""
    return {
        "tool_name": "Read",
        "tool_input": {"file_path": str(file_path)},
    }


def make_bash_input(command: str) -> dict:
    """Erstellt PreToolUse-Input fuer Bash-Tool."""
    return {
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


def make_write_input(file_path: str | Path, content: str = "") -> dict:
    """Erstellt PreToolUse-Input fuer Write-Tool."""
    return {
        "tool_name": "Write",
        "tool_input": {"file_path": str(file_path), "content": content},
    }


def make_prompt_input(prompt: str) -> dict:
    """Erstellt UserPromptSubmit-Input."""
    return {"prompt": prompt}
