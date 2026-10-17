#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
PostToolUse Hook: DSGVO Output Guard (Bash)
=============================================

Scannt Tool-Output (stdout/stderr) auf PII.
Bei Fund: Exit-Code 2 -> Output wird aus dem Kontext entfernt.

Claude sieht nur die Fehlermeldung aus stderr, nicht den PII-haltigen Output.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from hook_logger import HookLog
from pii_scanner_engine import PIIScanner


def main() -> None:
    log = HookLog("dsgvo-output-guard")
    scanner = PIIScanner()

    try:
        raw = sys.stdin.read().strip()
        if not raw:
            # Kein Input -> fail-closed
            print("DSGVO: Kein Input erhalten — Output blockiert.", file=sys.stderr)
            sys.exit(2)

        data = json.loads(raw)

        tool_name = data.get("tool_name", "")
        tool_response = data.get("tool_response")

        if not isinstance(tool_response, dict):
            print("DSGVO: Fehlendes/ungueltiges tool_response — Output blockiert.", file=sys.stderr)
            sys.exit(2)

        # Pruefen ob der Befehl oder Output .clean-Dateien verarbeitet
        tool_input = data.get("tool_input", {})
        command = ""
        if isinstance(tool_input, dict):
            command = str(tool_input.get("command", ""))

        stdout = str(tool_response.get("stdout", ""))
        stderr = str(tool_response.get("stderr", ""))

        # .clean-Dateien im Befehl oder DSGVO-Marker im Output = anonymisierte Daten
        # Pruefe ob der Befehl eine .clean-Datei referenziert (als Wortgrenze, nicht beliebiger Substring)
        if re.search(r"\.clean\b", command) or "[DSGVO] Verwende anonymisierte Version" in stdout:
            log.write("SKIP", f"{tool_name}: Verarbeitet anonymisierte .clean-Daten")
            print(json.dumps({}))
            return

        combined = f"{stdout}\n{stderr}"

        findings = scanner.scan(combined)

        if findings:
            categories = ", ".join(findings)
            log.write("BLOCKED", f"{tool_name}: PII im Output: {categories}")
            print(
                f"DSGVO-WARNUNG: Tool-Output enthaelt Personendaten "
                f"({categories}). Output wurde nicht in den Kontext uebernommen.",
                file=sys.stderr,
            )
            sys.exit(2)

        log.write("ALLOWED", f"{tool_name}: Output sauber")
        print(json.dumps({}))

    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        log.write("ERROR", f"Fail-closed: {exc}")
        print(f"DSGVO: Fehler bei Output-Pruefung — Output blockiert: {exc}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        log.write("ERROR", f"Fail-closed: {exc}")
        print(f"DSGVO: Unerwarteter Fehler — Output blockiert: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
