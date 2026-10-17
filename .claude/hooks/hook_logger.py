"""
Shared Hook Logger
===================

Einzeilig pro Hook-Aufruf, eine Datei pro Tag.
Schreibt in: {projekt}/logs/hooks-{YYYY-MM-DD}.log

Format:
  20:15:33 | pre-tool-safety    | ALLOWED | Bash: ls /foo
  20:15:34 | post-write-validate| BLOCKED | ruff: F821 undefined name

Verwendung:
    from hook_logger import HookLog
    log = HookLog("pre-tool-safety")
    log.write("ALLOWED", "Bash: ls /foo")
    log.write("BLOCKED", "rm -rf / blockiert")
"""

import os
from datetime import datetime, timezone
from pathlib import Path


class HookLog:
    def __init__(self, hook_name: str, cwd: str | None = None):
        self.hook_name = hook_name
        self.cwd = Path(cwd) if cwd else Path(os.getcwd())
        self.now = datetime.now(timezone.utc)

    def write(self, status: str, detail: str = "") -> None:
        """Schreibt eine Zeile ins Tages-Log."""
        time_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
        detail = detail.replace("\n", " ").replace("\r", "")[:150]
        line = f"{time_str} | {self.hook_name:25s} | {status:7s} | {detail}\n"

        date_str = self.now.strftime("%Y-%m-%d")
        log_dir = self.cwd / "logs"
        log_file = log_dir / f"hooks-{date_str}.log"

        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass
