#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
SessionStart Hook: DSGVO Session Guard
========================================

Prueft CLAUDE.md-Dateien auf Personendaten beim Session-Start.
Gibt Warnung aus, wenn PII gefunden wird.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from hook_logger import HookLog
from pii_scanner_engine import PIIScanner


def main() -> None:
    log = HookLog("dsgvo-session-guard")
    scanner = PIIScanner()

    try:
        raw = sys.stdin.read().strip()
        if not raw:
            print(json.dumps({"message": ""}))
            return

        data = json.loads(raw)
        project_dir = data.get("project_dir", "")

        if not project_dir:
            print(json.dumps({"message": ""}))
            return

        project_path = Path(project_dir)

        # CLAUDE.md-Dateien pruefen
        claude_md_locations = [
            project_path / "CLAUDE.md",
            project_path / ".claude" / "CLAUDE.md",
        ]

        warnings: list[str] = []

        for path in claude_md_locations:
            if not path.exists():
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            findings = scanner.scan(content)
            if findings:
                categories = ", ".join(findings)
                warnings.append(
                    f"WARNUNG: {path} enthaelt Personendaten: {categories}"
                )
                log.write("WARNING", f"{path}: PII gefunden: {categories}")

        if warnings:
            message = "\n".join(warnings)
            message += "\nBitte CLAUDE.md bereinigen bevor Sie fortfahren."
        else:
            message = ""
            log.write("OK", "Keine PII in CLAUDE.md gefunden")

        print(json.dumps({"message": message}))

    except Exception as exc:
        log.write("ERROR", f"Session-Guard Fehler: {exc}")
        print(json.dumps({"message": ""}))


if __name__ == "__main__":
    main()
