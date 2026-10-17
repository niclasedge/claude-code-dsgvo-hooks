#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
DSGVO PII-Datei-Guard fuer Claude Code PreToolUse Hook
=========================================================
Blockiert das Lesen von Dateien die personenbezogene Daten,
Zertifikate/Keys oder Auth-Credentials enthalten koennten.

Kategorien:
  1. PII-Daten: .csv, .tsv, .xlsx, .xls, .vcf, .ldif, .sql, .db, .sqlite
  2. Zertifikate/Keys: .pem, .key, .p12, .pfx, .cer, .crt, .csr, .jks
  3. Auth/Secrets: .env*, auth.*, secrets.*, oauth_*
  4. Bedingt: .json/.xml mit PII-Indikatoren im Namen

Erlaubt:
  - .clean-Dateien, mock_*-Prefix
  - Code-Dateien (.py, .js, .ts, .go, etc.)
  - Config-Dateien ohne PII-Indikatoren

Eingabe: JSON via stdin mit tool_name und tool_input
Ausgabe: JSON mit decision + reason
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# ─── Dateitypen: Immer blockiert (PII-Risiko) ─────────
ALWAYS_BLOCKED_EXTENSIONS = {
    ".csv", ".tsv", ".xlsx", ".xls", ".xlsm",
    ".vcf", ".ldif", ".sql",
    ".db", ".sqlite", ".sqlite3",
}

# ─── Dateitypen: Zertifikate und Keys ─────────────────
CERT_KEY_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx", ".cer", ".crt", ".csr", ".jks",
}

# ─── Dateitypen: Bedingt blockiert (mit PII-Indikatoren) ──
CONDITIONAL_EXTENSIONS = {".json", ".xml"}

# ─── PII-Indikatoren in Dateinamen (case-insensitive) ──
PII_NAME_INDICATORS = [
    "customer", "kunden", "mitarbeiter", "employee", "personal",
    "kontakt", "contact", "patient", "bewerber", "applicant",
    "user", "nutzer", "person", "gehalt", "salary", "lohn",
    "adress", "address", "telefon", "phone", "email",
    "sozialversicherung", "insurance", "krankenkasse",
    "backup", "export", "dump", "report",
]

# ─── Auth/Secret-Indikatoren in Dateinamen ─────────────
AUTH_NAME_INDICATORS = [
    "auth", "oauth", "credential", "secret", "token",
    "login", "password", "passwd",
]

# ─── Dateien/Patterns die IMMER erlaubt sind ──────────
SAFE_PATTERNS = [
    "fixture",      # Test-Fixtures
    "example",      # Beispieldaten
    "sample",       # Beispieldaten
    "template",     # Templates
    "schema",       # Schema-Definitionen
    "package.json", # NPM Config
    "tsconfig",     # TypeScript Config
]

# ─── Sichere Dateierweiterungen (nie blockieren) ───────
SAFE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".rb", ".java",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt",
    ".md", ".rst", ".txt", ".log",
    ".toml", ".ini", ".cfg",
    ".html", ".css", ".scss", ".less",
    ".gitignore", ".dockerignore", ".editorconfig",
    ".lock", ".sum",
}

# ─── Geschuetzte Dateinamen (exakt, case-insensitive) ──
PROTECTED_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.test",
}


def is_safe_file(file_path: str) -> bool:
    """Prueft ob eine Datei als sicher gilt (keine Pruefung noetig)."""
    lower = file_path.lower()
    basename = get_basename_lower(file_path)

    # .clean als Suffix (z.B. datei.csv.clean) — nicht als Substring
    if lower.endswith(".clean"):
        return True

    # mock_-Prefix im Dateinamen (z.B. mock_customers.csv)
    if basename.startswith("mock_"):
        return True

    # Andere sichere Patterns (fixture, example, etc.)
    for pattern in SAFE_PATTERNS:
        if pattern in lower:
            return True

    # Sichere Erweiterungen
    ext = Path(lower).suffix
    if ext in SAFE_EXTENSIONS:
        return True

    return False


def get_basename_lower(file_path: str) -> str:
    """Gibt den Dateinamen in Kleinbuchstaben zurueck."""
    return os.path.basename(file_path.replace("\\", "/")).lower()


def has_pii_indicator(file_path: str) -> bool:
    """Prueft ob der Dateiname PII-Indikatoren enthaelt."""
    lower = get_basename_lower(file_path)
    return any(indicator in lower for indicator in PII_NAME_INDICATORS)


def has_auth_indicator(file_path: str) -> bool:
    """Prueft ob der Dateiname Auth/Secret-Indikatoren enthaelt."""
    lower = get_basename_lower(file_path)
    return any(indicator in lower for indicator in AUTH_NAME_INDICATORS)


def is_protected_filename(file_path: str) -> bool:
    """Prueft ob der Dateiname ein geschuetzter Name ist (.env etc)."""
    basename = get_basename_lower(file_path)
    return basename in PROTECTED_FILENAMES


def is_auth_script(file_path: str) -> bool:
    """Prueft ob die Datei ein Auth-Skript ist (auth.ps1, deploy_auth.sh etc)."""
    basename = get_basename_lower(file_path)
    ext = Path(basename).suffix
    # Skripte mit auth im Namen
    if ext in (".ps1", ".sh", ".bat", ".cmd") and has_auth_indicator(file_path):
        return True
    return False


def is_secrets_file(file_path: str) -> bool:
    """Prueft ob die Datei eine Secrets-Datei ist (secrets.yaml, etc)."""
    basename = get_basename_lower(file_path)
    ext = Path(basename).suffix
    name_without_ext = Path(basename).stem
    # secrets.yaml, secrets.yml
    if name_without_ext == "secrets" and ext in (".yaml", ".yml", ".json"):
        return True
    return False


def get_pii_suggestion(file_path: str) -> str:
    """Generiert Vorschlag fuer PII-Datei-Alternative."""
    basename = os.path.basename(file_path)
    clean_path = f"{file_path}.clean"
    return (
        f"DSGVO: Zugriff auf '{basename}' blockiert — Datei koennte personenbezogene Daten enthalten.\n"
        f"\n"
        f"Alternativen:\n"
        f"  1. Nutze die anonymisierte Version: {clean_path}\n"
        f"  2. Erstelle Mock-Daten: uv run --extra mock-data .claude/tools/generate_mock_data.py {file_path}\n"
        f"  3. Nutze --dry um PII-Fundstellen zu sehen: uv run --extra mock-data .claude/tools/generate_mock_data.py --dry {file_path}\n"
        f"  4. Dateien mit .clean-Suffix oder mock_-Prefix sind immer erlaubt\n"
        f"\n"
        f"DSGVO Art. 5: Personenbezogene Daten duerfen nur zweckgebunden verarbeitet werden."
    )


def get_cert_suggestion(file_path: str) -> str:
    """Generiert Vorschlag fuer Zertifikats-/Key-Datei."""
    basename = os.path.basename(file_path)
    return (
        f"Sicherheit: Zugriff auf Zertifikat/Key '{basename}' blockiert.\n"
        f"\n"
        f"Zertifikate und private Keys duerfen nicht gelesen werden.\n"
        f"  - Private Keys (.key, .pem) enthalten geheimes Schluesselmaterial\n"
        f"  - Keystores (.p12, .pfx, .jks) enthalten verschluesselte Credentials\n"
        f"\n"
        f"Wenn du die Zertifikats-Konfiguration pruefen willst,\n"
        f"nutze: openssl x509 -noout -subject -in <cert> (nur Metadaten, kein Key)."
    )


def get_auth_suggestion(file_path: str) -> str:
    """Generiert Vorschlag fuer Auth-/Secret-Datei."""
    basename = os.path.basename(file_path)
    return (
        f"Sicherheit: Zugriff auf Auth/Secret-Datei '{basename}' blockiert.\n"
        f"\n"
        f"Auth-Dateien und Secrets duerfen nicht gelesen werden:\n"
        f"  - .env-Dateien enthalten Umgebungsvariablen mit Secrets\n"
        f"  - Auth-Skripte enthalten Credentials und Tokens\n"
        f"  - secrets.yaml/json enthalten sensitive Konfiguration\n"
        f"\n"
        f"Nutze Umgebungsvariablen oder einen Secret-Manager statt Datei-Zugriff."
    )


def check_file(file_path: str) -> dict:
    """Prueft ob eine Datei gelesen werden darf."""
    if not file_path:
        return {}

    # Symlinks aufloesen bevor Extension geprueft wird
    try:
        resolved = str(Path(file_path).resolve())
        if resolved != file_path:
            # Pruefe sowohl Original als auch aufgeloestes Ziel
            result = _check_file_inner(resolved)
            if result.get("hookSpecificOutput"):
                return result
    except (OSError, ValueError):
        pass

    return _check_file_inner(file_path)


def _make_block(reason: str) -> dict:
    """Erstellt ein Block-Ergebnis im korrekten PreToolUse-Format."""
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _check_file_inner(file_path: str) -> dict:
    """Innere Pruefung einer Datei (nach Symlink-Aufloesung)."""
    if not file_path:
        return {}

    # Sichere Dateien sofort erlauben
    if is_safe_file(file_path):
        return {}

    basename = get_basename_lower(file_path)
    ext = Path(basename).suffix

    # Dateien ohne Erweiterung: .env-Varianten pruefen
    if is_protected_filename(file_path):
        return _make_block(get_auth_suggestion(file_path))

    # Zertifikate und Keys — immer blockieren
    if ext in CERT_KEY_EXTENSIONS:
        return _make_block(get_cert_suggestion(file_path))

    # PII-Dateien — immer blockieren
    if ext in ALWAYS_BLOCKED_EXTENSIONS:
        return _make_block(get_pii_suggestion(file_path))

    # Auth-Skripte (auth.ps1, deploy_auth.sh, etc.)
    if is_auth_script(file_path):
        return _make_block(get_auth_suggestion(file_path))

    # Secrets-Dateien (secrets.yaml, secrets.yml)
    if is_secrets_file(file_path):
        return _make_block(get_auth_suggestion(file_path))

    # Bedingt blockiert: JSON/XML mit PII- oder Auth-Indikatoren
    if ext in CONDITIONAL_EXTENSIONS:
        if has_pii_indicator(file_path):
            return _make_block(get_pii_suggestion(file_path))
        if has_auth_indicator(file_path):
            return _make_block(get_auth_suggestion(file_path))

    # YAML/YML mit Auth-Indikatoren
    if ext in (".yaml", ".yml") and has_auth_indicator(file_path):
        return _make_block(get_auth_suggestion(file_path))

    # config.json etc — erlaubt (kein PII/Auth-Indikator)
    return {}


def main() -> None:
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, Exception):
        # Fail-closed: Bei Parse-Fehlern blockieren statt erlauben
        print(json.dumps(_make_block("DSGVO: Ungueltiger JSON-Input — Zugriff blockiert (fail-closed).")))
        return

    tool_name = data.get("tool_name", "")

    # Nur Read-Tool pruefen
    if tool_name != "Read":
        print(json.dumps({}))
        return

    tool_input = data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        # Fail-closed: unerwartetes Format blockieren
        print(json.dumps(_make_block("DSGVO: Ungueltiges tool_input Format — Zugriff blockiert.")))
        return
    file_path = tool_input.get("file_path", "")

    result = check_file(file_path)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
