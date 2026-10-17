#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
PostToolUse Hook: Code Validation nach Write/Edit
====================================================

Automatische Validierung nach jeder Datei-Aenderung.
Unterstuetzt Python (ruff) und JSON.

Rueckgabe:
  {"decision": "block", "reason": "..."} -> Claude sieht Fehler und fixt sie
  {}                                      -> Kein Problem
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))
from hook_logger import HookLog


VALIDATOR_TIMEOUT = 30
MAX_ERROR_LENGTH = 2000


def run_cmd(cmd: list[str], timeout: int = VALIDATOR_TIMEOUT) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout nach {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Nicht gefunden: {cmd[0]}"
    except OSError as e:
        return -1, "", str(e)


def validate_python(file_path: str) -> Optional[str]:
    """Validiert Python mit ruff (uvx ruff oder ruff direkt)."""
    uvx = shutil.which("uvx")
    ruff = shutil.which("ruff")

    if uvx:
        lint_cmd = [uvx, "ruff", "check", file_path]
    elif ruff:
        lint_cmd = [ruff, "check", file_path]
    else:
        return None

    rc, stdout, stderr = run_cmd(lint_cmd)
    if rc > 0:
        output = stdout or stderr
        if output:
            return f"Ruff lint:\n{output[:MAX_ERROR_LENGTH]}"
    return None


def validate_json(file_path: str) -> Optional[str]:
    """Validiert JSON-Syntax."""
    try:
        with open(file_path, encoding="utf-8") as f:
            json.load(f)
        return None
    except json.JSONDecodeError as e:
        return f"JSON ungueltig: Zeile {e.lineno}, Spalte {e.colno}: {e.msg}"
    except Exception as e:
        return f"JSON Lesefehler: {e}"


VALIDATORS = {
    ".py": validate_python,
    ".json": validate_json,
}


def main() -> None:
    log = HookLog("post-write-validate")

    try:
        raw = sys.stdin.read().strip()
        if not raw:
            print(json.dumps({}))
            return
        data = json.loads(raw)
    except Exception:
        print(json.dumps({}))
        return

    tool_input = data.get("tool_input", {})
    file_path = tool_input.get("file_path", "")
    basename = os.path.basename(file_path) if file_path else "?"

    if not file_path or not os.path.isfile(file_path):
        print(json.dumps({}))
        return

    ext = Path(file_path).suffix.lower()
    validator = VALIDATORS.get(ext)

    if not validator:
        log.write("SKIP", f"{basename} ({ext}) kein Validator")
        print(json.dumps({}))
        return

    error = validator(file_path)

    if error:
        log.write("BLOCKED", f"{basename}: {error[:100]}")
        result = {
            "decision": "block",
            "reason": f"Validierung fehlgeschlagen fuer {basename}:\n{error}"
        }
        print(json.dumps(result))
    else:
        log.write("OK", basename)
        print(json.dumps({}))


if __name__ == "__main__":
    main()
