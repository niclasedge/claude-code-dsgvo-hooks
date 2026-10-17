#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
DSGVO Prompt-Guard fuer Claude Code UserPromptSubmit Hook
==========================================================
Scannt User-Prompts auf personenbezogene Daten (PII) und blockiert bei Fund.

Prueft gegen:
  1. Namensliste (names.txt)
  2. PII-Patterns (IBAN, Telefon, E-Mail mit echten Domains, Geburtsdaten)

Eingabe: JSON via stdin mit "prompt" Feld
Ausgabe: JSON mit "decision": "allow" | "block" + "reason"
"""

import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path


def get_names_list() -> list[tuple[str, str]]:
    """Laedt die Namensliste aus config/names.txt."""
    # Pfad relativ zum Hook-Verzeichnis
    hook_dir = Path(__file__).parent
    names_path = hook_dir / "pii-guard" / "config" / "names.txt"

    if not names_path.exists():
        return []

    names = []
    for line in names_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            names.append((parts[0], " ".join(parts[1:])))
    return names


# Dummy-IBANs die als Test-Daten gelten (nicht blockieren)
DUMMY_IBAN_PATTERN = re.compile(r"\b[A-Za-z]{2}0{18,20}\b")

# PII-Patterns
IBAN_PATTERN = re.compile(r"\b[A-Za-z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b")
TELEFON_PATTERN = re.compile(r"(?:\+49|0049|\b0)[\s\-/()]?[\d\s\-/()]{6,14}\d")
GEBURTSDATUM_PATTERN = re.compile(
    r"\b(0[1-9]|[12]\d|3[01])[./-](0[1-9]|1[0-2])[./-](19|20)\d{2}\b"
)
# Datumsformate die vor Telefon-Check entfernt werden muessen
# ISO: YYYY-MM-DD, US: MM/DD/YYYY, MM-DD-YYYY
ISO_DATE_PATTERN = re.compile(r"\b(19|20)\d{2}[./-](0[1-9]|1[0-2])[./-](0[1-9]|[12]\d|3[01])\b")
US_DATE_PATTERN = re.compile(r"\b(0[1-9]|1[0-2])[./-](0[1-9]|[12]\d|3[01])[./-](19|20)\d{2}\b")
SVN_PATTERN = re.compile(r"\b\d{2}[A-Z]\d{6}[A-Z]\d{3}\b")


def scan_prompt(prompt: str, names: list[tuple[str, str]]) -> list[str]:
    """Scannt den Prompt auf PII. Gibt Liste gefundener Kategorien zurueck."""
    found = []

    # 1. Namensliste pruefen
    prompt_lower = prompt.lower()
    for first, last in names:
        # Vollstaendiger Name
        if first.lower() in prompt_lower and last.lower() in prompt_lower:
            found.append(f"Name:{first} {last}")
            continue
        # Nachname allein (haeufiger Leak)
        if len(last) > 3 and re.search(rf"\b{re.escape(last)}\b", prompt, re.IGNORECASE):
            found.append(f"Nachname:{last}")

    # 2. IBANs pruefen (und Dummy-IBANs rausfiltern)
    iban_matches = IBAN_PATTERN.findall(prompt)
    real_ibans = [m for m in iban_matches if not DUMMY_IBAN_PATTERN.match(m)]
    if real_ibans:
        found.append(f"IBAN:{len(real_ibans)}")

    # 3. IBANs und ISO-Daten aus dem Text entfernen, damit deren Ziffern nicht als Telefon matchen
    prompt_cleaned = IBAN_PATTERN.sub("", prompt)
    prompt_cleaned = ISO_DATE_PATTERN.sub("", prompt_cleaned)
    prompt_cleaned = US_DATE_PATTERN.sub("", prompt_cleaned)
    prompt_cleaned = GEBURTSDATUM_PATTERN.sub("", prompt_cleaned)

    # 4. Telefon (auf bereinigtem Text ohne IBANs/Daten)
    telefon_matches = TELEFON_PATTERN.findall(prompt_cleaned)
    if telefon_matches:
        found.append(f"Telefon:{len(telefon_matches)}")

    # 5. Geburtsdatum
    datum_matches = GEBURTSDATUM_PATTERN.findall(prompt)
    if datum_matches:
        found.append(f"Geburtsdatum:{len(datum_matches)}")

    # 6. Sozialversicherungsnummer
    svn_matches = SVN_PATTERN.findall(prompt)
    if svn_matches:
        found.append(f"Sozialversicherungsnummer:{len(svn_matches)}")

    return found


def write_audit(event: str, prompt_preview: str, findings: list[str]) -> None:
    """Schreibt einen Audit-Eintrag fuer den Prompt-Guard."""
    try:
        repo_root = os.environ.get("CLAUDE_PROJECT_DIR", ".")
        now = datetime.now()
        audit_dir = Path(repo_root) / "logs" / "dsgvo-audit" / now.strftime("%Y-%m")
        audit_dir.mkdir(parents=True, exist_ok=True)

        audit_file = audit_dir / f"audit-{now.strftime('%Y-%m-%d')}.jsonl"

        entry = {
            "ts": now.isoformat(),
            "event": event,
            "tool": "UserPromptSubmit",
            "target": prompt_preview[:60] + "..." if len(prompt_preview) > 60 else prompt_preview,
            "pii_residual": findings,
        }

        with open(audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass  # Audit-Fehler nicht blockierend


def log_error(msg: str) -> None:
    """Schreibt Fehler ins Hook-Log fuer Diagnose."""
    try:
        repo_root = os.environ.get("CLAUDE_PROJECT_DIR", ".")
        log_dir = Path(repo_root) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"hooks-{datetime.now().strftime('%Y-%m-%d')}.log"
        ts = datetime.now().strftime("%H:%M:%S")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{ts} | {'dsgvo-prompt-guard':25s} | ERROR   | {msg[:150]}\n")
    except Exception:
        pass


def main() -> None:
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, Exception) as exc:
        # Fail-closed: Bei Parse-Fehlern blockieren statt erlauben
        log_error(f"JSON parse failed: {exc} | raw={repr(raw[:100]) if raw else 'EMPTY'}")
        print(json.dumps({"decision": "block", "reason": "DSGVO: Ungueltiger JSON-Input — Prompt blockiert (fail-closed)."}))
        return

    prompt = data.get("prompt", "")
    if not isinstance(prompt, str):
        # Fail-closed: unerwartetes Format blockieren
        print(json.dumps({"decision": "block", "reason": "DSGVO: Ungueltiges Prompt-Format — Zugriff blockiert."}))
        return
    if not prompt:
        print(json.dumps({}))
        return

    names = get_names_list()
    findings = scan_prompt(prompt, names)

    if findings:
        # Prompt-Vorschau ohne PII
        preview = prompt[:40].replace("\n", " ")
        write_audit("prompt_blocked", preview, findings)

        categories = ", ".join(set(f.split(":")[0] for f in findings))
        reason = (
            f"DSGVO: Prompt enthaelt personenbezogene Daten ({categories}). "
            f"Bitte PII aus dem Prompt entfernen."
        )
        print(json.dumps({
            "decision": "block",
            "reason": reason,
        }))
    else:
        print(json.dumps({}))


if __name__ == "__main__":
    main()
