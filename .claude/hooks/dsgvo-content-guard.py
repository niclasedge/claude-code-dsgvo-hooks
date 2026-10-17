#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
PostToolUse Hook: DSGVO Content Guard (Read)
==============================================

Scannt gelesenen Dateiinhalt auf PII.
Bei Fund: Exit-Code 2 -> Dateiinhalt wird aus dem Kontext entfernt.

Claude sieht nur die Fehlermeldung aus stderr, nicht den PII-haltigen Inhalt.
"""

import json
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from hook_logger import HookLog
from pii_scanner_engine import PIIScanner

# Source-Code-Dateien werden nicht gescannt — Claude braucht sie zum Arbeiten.
# PII in Code-Dateien sind fast immer Mock-Daten oder Pattern-Definitionen.
# Config-Dateien (.ini, .yml, .cfg, .toml) werden weiterhin gescannt (Credentials).
_SOURCE_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".rb", ".java",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt", ".scala",
    ".md", ".rst",
    ".html", ".css", ".scss", ".less",
    ".sh", ".bash", ".zsh", ".fish",
    ".gitignore", ".dockerignore", ".editorconfig",
    ".lock", ".sum",
    ".svelte", ".vue", ".astro",
}

# Dateien die immer erlaubt sind (Claude-Konfiguration etc.)
_SAFE_PATHS = {
    "settings.json",
    "settings.local.json",
}

def _is_safe_path(file_path: str) -> bool:
    """Prueft ob der Pfad eine Claude-Konfigurationsdatei ist (.claude/settings*)."""
    if not file_path:
        return False
    # .claude/settings.json und .claude/settings.local.json immer erlauben
    parts = file_path.replace("\\", "/").split("/")
    if len(parts) >= 2 and parts[-2] == ".claude" and parts[-1] in _SAFE_PATHS:
        return True
    return False


def main() -> None:
    log = HookLog("dsgvo-content-guard")
    scanner = PIIScanner()

    try:
        raw = sys.stdin.read().strip()
        if not raw:
            print("DSGVO: Kein Input erhalten — Dateiinhalt blockiert.", file=sys.stderr)
            sys.exit(2)

        data = json.loads(raw)

        tool_input = data.get("tool_input", {})
        tool_response = data.get("tool_response")

        file_path = ""
        if isinstance(tool_input, dict):
            file_path = tool_input.get("file_path", "")

        # Claude-Konfigurationsdateien immer erlauben
        if _is_safe_path(file_path):
            log.write("SKIP", f"Read {file_path}: Claude-Config (safe path)")
            print(json.dumps({}))
            return

        # .clean-Dateien ueberspringen — bereits anonymisiert, Mock-Daten erlaubt
        # Pruefe als Suffix, nicht Substring (verhindert Bypass via .cleandata.csv)
        if file_path and file_path.lower().endswith(".clean"):
            log.write("SKIP", f"Read {file_path}: Anonymisierte .clean-Datei")
            print(json.dumps({}))
            return

        # Source-Code-Dateien ueberspringen — PreToolUse blockiert bereits PII-Dateitypen
        if file_path:
            ext = os.path.splitext(file_path)[1].lower()
            if ext in _SOURCE_CODE_EXTENSIONS:
                log.write("SKIP", f"Read {file_path}: Source-Code ({ext})")
                print(json.dumps({}))
                return

        if not isinstance(tool_response, dict):
            print("DSGVO: Fehlendes/ungueltiges tool_response — Dateiinhalt blockiert.", file=sys.stderr)
            sys.exit(2)

        # Dateiinhalt aus tool_response extrahieren
        # Format: tool_response.file.content (Read-Tool)
        file_data = tool_response.get("file", {})
        if isinstance(file_data, dict):
            content = str(file_data.get("content", ""))
        else:
            # Fallback: direkt als output
            content = str(tool_response.get("output", ""))

        findings = scanner.scan(content)

        if findings:
            categories = ", ".join(findings)
            log.write("BLOCKED", f"Read {file_path}: PII im Inhalt: {categories}")
            print(
                f"DSGVO-WARNUNG: Datei '{file_path}' enthaelt Personendaten "
                f"({categories}). Inhalt wurde nicht in den Kontext uebernommen.",
                file=sys.stderr,
            )
            sys.exit(2)

        log.write("ALLOWED", f"Read {file_path}: Inhalt sauber")
        print(json.dumps({}))

    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        log.write("ERROR", f"Fail-closed: {exc}")
        print(f"DSGVO: Fehler bei Inhalts-Pruefung — blockiert: {exc}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        log.write("ERROR", f"Fail-closed: {exc}")
        print(f"DSGVO: Unerwarteter Fehler — Dateiinhalt blockiert: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
