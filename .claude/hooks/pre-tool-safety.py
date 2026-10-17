#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
PreToolUse Hook: Safety Guard
================================

Blockiert gefaehrliche Operationen bevor sie ausgefuehrt werden.
Deckt Bash, PowerShell/pwsh und Write/Edit ab.

Rueckgabe:
  Erlauben:  {}
  Blockieren: {"hookSpecificOutput": {"hookEventName": "PreToolUse",
               "permissionDecision": "deny", "permissionDecisionReason": "..."}}
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from hook_logger import HookLog


# === Gefaehrliche Bash-Patterns ===
DANGEROUS_BASH = [
    (r"rm\s+-rf\s+/(?:\s|$|;|&|\|)", "rm -rf / ist nicht erlaubt"),
    (r"rm\s+-rf\s+/\*", "rm -rf /* ist nicht erlaubt"),
    (r"rm\s+-rf\s+~", "rm -rf ~ ist nicht erlaubt"),
    (r"rm\s+-rf\s+\.(?:\s|$|;|&|\|)", "rm -rf . ist nicht erlaubt"),
    (r"git\s+push\s+.*(?:--force|-f).*(?:main|master)", "Force-Push auf main/master blockiert"),
    (r"git\s+push\s+.*(?:main|master).*(?:--force|-f)", "Force-Push auf main/master blockiert"),
    (r"git\s+reset\s+--hard", "git reset --hard blockiert - nutze git stash"),
    (r"git\s+clean\s+-[a-z]*f", "git clean -f blockiert"),
    (r"chmod\s+777", "chmod 777 ist ein Sicherheitsrisiko"),
    (r"curl\s+.*\|\s*(?:ba)?sh", "Pipe von curl nach sh blockiert"),
    (r"wget\s+.*\|\s*(?:ba)?sh", "Pipe von wget nach sh blockiert"),
    (r"DROP\s+(?:TABLE|DATABASE)", "DROP TABLE/DATABASE blockiert"),
    (r"TRUNCATE\s+TABLE", "TRUNCATE TABLE blockiert"),
    (r"mkfs\.", "mkfs blockiert"),
    (r"dd\s+if=", "dd blockiert"),
    (r">\s*/dev/sd[a-z]", "Schreiben auf Block-Device blockiert"),
]

# === PowerShell/pwsh gefaehrliche Patterns ===
# Werden case-insensitive geprueft
DANGEROUS_POWERSHELL = [
    # Invoke-* Cmdlets (alle Varianten)
    (r"invoke-webrequest", "Invoke-WebRequest blockiert - nutze curl oder Python requests"),
    (r"invoke-restmethod", "Invoke-RestMethod blockiert - nutze Python requests"),
    (r"invoke-expression", "Invoke-Expression blockiert - Sicherheitsrisiko"),
    (r"invoke-command", "Invoke-Command blockiert - nutze direkte Ausfuehrung"),
    (r"invoke-item", "Invoke-Item blockiert"),
    (r"invoke-wmimethod", "Invoke-WmiMethod blockiert"),
    (r"invoke-cimmethod", "Invoke-CimMethod blockiert"),
    (r"\biex\b", "IEX (Invoke-Expression Alias) blockiert"),
    (r"\birm\b\s+-recurse\s+-force", "Remove-Item -Recurse -Force blockiert"),
    # Download/Execution Patterns
    (r"new-object\s+(?:system\.)?net\.webclient", "New-Object Net.WebClient blockiert"),
    (r"downloadstring\s*\(", "DownloadString blockiert"),
    (r"downloadfile\s*\(", "DownloadFile blockiert"),
    (r"start-bitstransfer", "Start-BitsTransfer blockiert"),
    # Process/Execution
    (r"start-process", "Start-Process blockiert - nutze direkte Ausfuehrung"),
    (r"set-executionpolicy", "Set-ExecutionPolicy blockiert"),
    (r"\bencodedcommand\b", "-EncodedCommand blockiert (verschleierter Code)"),
    (r"-e\s+[A-Za-z0-9+/=]{20,}", "Base64-encoded PowerShell blockiert"),
    # Registry
    (r"set-itemproperty\s+.*hk(?:lm|cu)", "Registry-Aenderungen blockiert"),
    (r"new-itemproperty\s+.*hk(?:lm|cu)", "Registry-Aenderungen blockiert"),
    # Service/System
    (r"stop-service", "Stop-Service blockiert"),
    (r"remove-item\s+.*-recurse", "Remove-Item -Recurse blockiert - nutze gezielte Loeschung"),
    # Credential Extraction
    (r"get-credential", "Get-Credential blockiert"),
    (r"convertto-securestring", "ConvertTo-SecureString blockiert"),
]

# === Dateien die nicht geschrieben werden duerfen ===
PROTECTED_FILES = {
    ".env", ".env.local", ".env.production",
    "id_rsa", "id_ed25519", "id_ecdsa",
    "credentials.json", "service-account.json",
}

# === Geschuetzte Verzeichnisse ===
PROTECTED_DIRS = [
    "creds",
    ".ssh",
    ".aws",
]


def is_powershell_context(command: str) -> bool:
    """Prueft ob ein Befehl in PowerShell-Kontext laeuft."""
    cmd_lower = command.lower().strip()
    ps_prefixes = ("powershell", "pwsh", "powershell.exe", "pwsh.exe")
    for prefix in ps_prefixes:
        if cmd_lower.startswith(prefix):
            return True
    # Auch PowerShell-spezifische Syntax erkennen
    if re.search(r"\$env:", command, re.IGNORECASE):
        return True
    if re.search(r"\|.*where-object|select-object|format-table", command, re.IGNORECASE):
        return True
    return False


def check_bash(command: str) -> str | None:
    """Prueft Bash-Kommandos gegen Blockliste."""
    # Standard-Bash-Patterns
    for pattern, reason in DANGEROUS_BASH:
        if re.search(pattern, command, re.IGNORECASE):
            return reason

    # PowerShell-Patterns (immer pruefen, nicht nur im PS-Kontext)
    cmd_lower = command.lower()
    for pattern, reason in DANGEROUS_POWERSHELL:
        if re.search(pattern, cmd_lower):
            return reason

    # PII/Cert/Auth-Dateizugriff via Bash blockieren
    reason = check_bash_file_access(command)
    if reason:
        return reason

    # Interpreter-Bypass: python/node/bash -c mit Dateizugriff
    reason = check_interpreter_bypass(command)
    if reason:
        return reason

    # Env-Dump blockieren
    reason = check_env_dump(command)
    if reason:
        return reason

    return None


# ─── PII-Dateizugriff via Bash ────────────────────────

# Dateitypen die immer blockiert werden
_BLOCKED_EXTENSIONS = {
    ".csv", ".tsv", ".xlsx", ".xls", ".xlsm",
    ".vcf", ".ldif", ".sql",
    ".db", ".sqlite", ".sqlite3",
}

# Zertifikate/Keys
_CERT_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx", ".cer", ".crt", ".csr", ".jks",
}

# Geschuetzte Dateinamen (exakt)
_PROTECTED_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.test",
}

# Sichere Patterns (erlaubt)
_SAFE_PATTERNS = ["fixture", "example", "sample", "template"]

# Sichere Erweiterungen (nie blockieren)
_SAFE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".rb", ".java",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt",
    ".md", ".rst", ".txt", ".log",
    ".toml", ".ini", ".cfg",
    ".html", ".css", ".scss", ".less",
    ".gitignore", ".dockerignore", ".editorconfig",
    ".lock", ".sum",
}

# Auth-Indikatoren in Dateinamen
_AUTH_INDICATORS = [
    "auth", "oauth", "credential", "secret", "token",
    "login", "password", "passwd",
]

# PII-Indikatoren in Dateinamen (fuer .json/.xml)
_PII_INDICATORS = [
    "customer", "kunden", "mitarbeiter", "employee", "personal",
    "kontakt", "contact", "patient", "bewerber", "applicant",
    "user", "nutzer", "person", "gehalt", "salary", "lohn",
    "adress", "address", "telefon", "phone", "email",
    "sozialversicherung", "insurance", "krankenkasse",
    "backup", "export", "dump", "report",
]

# Bash-Befehle die Dateien lesen
_FILE_READ_COMMANDS = [
    "cat", "head", "tail", "less", "more",
    "grep", "awk", "sed", "wc", "sort", "cut",
    "strings", "xxd", "base64", "openssl",
    "source", "xargs",
]


def _extract_file_tokens(command: str) -> list[str]:
    """Extrahiert potentielle Dateinamen/Pfade aus einem Bash-Befehl."""
    # Quotes und Subshell-Syntax entfernen
    cleaned = command.replace('"', " ").replace("'", " ")
    cleaned = cleaned.replace("$(", " ").replace(")", " ")
    # Tokens extrahieren
    tokens = re.split(r"[\s;|&<>]+", cleaned)
    return [t for t in tokens if t and "=" not in t]


def _is_file_safe(filename: str) -> bool:
    """Prueft ob eine Datei als sicher gilt."""
    lower = filename.lower()
    basename = os.path.basename(lower.replace("\\", "/"))

    # .clean als Suffix (z.B. datei.csv.clean) — nicht als Substring
    if lower.endswith(".clean"):
        return True

    # mock_-Prefix im Dateinamen (z.B. mock_customers.csv)
    if basename.startswith("mock_"):
        return True

    # Andere sichere Patterns (fixture, example, etc.)
    for pattern in _SAFE_PATTERNS:
        if pattern in lower:
            return True

    from pathlib import Path as _Path
    ext = _Path(lower).suffix
    if ext in _SAFE_EXTENSIONS:
        return True
    return False


def _is_file_blocked(filename: str) -> str | None:
    """Prueft ob eine Datei blockiert werden soll. Gibt Grund zurueck oder None."""
    lower = filename.lower().replace("\\", "/")
    basename = os.path.basename(lower)
    from pathlib import Path as _Path
    ext = _Path(basename).suffix

    # Geschuetzte Dateinamen (.env etc)
    if basename in _PROTECTED_FILENAMES:
        return f"DSGVO: Zugriff auf Auth-Datei '{basename}' via Bash blockiert"

    # Zertifikate/Keys
    if ext in _CERT_EXTENSIONS:
        return f"Sicherheit: Zugriff auf Zertifikat/Key '{basename}' via Bash blockiert"

    # PII-Dateien (immer blockiert)
    if ext in _BLOCKED_EXTENSIONS:
        return f"DSGVO: Zugriff auf PII-Datei '{basename}' via Bash blockiert"

    # Auth-Skripte (.sh/.ps1/.bat/.cmd mit auth-Indikator)
    if ext in (".ps1", ".sh", ".bat", ".cmd"):
        if any(ind in basename for ind in _AUTH_INDICATORS):
            return f"Sicherheit: Zugriff auf Auth-Skript '{basename}' via Bash blockiert"

    # Secrets-Dateien
    name_without_ext = _Path(basename).stem
    if name_without_ext == "secrets" and ext in (".yaml", ".yml", ".json"):
        return f"Sicherheit: Zugriff auf Secrets-Datei '{basename}' via Bash blockiert"

    # JSON/XML mit PII/Auth-Indikatoren
    if ext in (".json", ".xml"):
        if any(ind in basename for ind in _PII_INDICATORS):
            return f"DSGVO: Zugriff auf PII-Datei '{basename}' via Bash blockiert"
        if any(ind in basename for ind in _AUTH_INDICATORS):
            return f"Sicherheit: Zugriff auf Auth-Datei '{basename}' via Bash blockiert"

    # YAML mit Auth-Indikatoren
    if ext in (".yaml", ".yml") and any(ind in basename for ind in _AUTH_INDICATORS):
        return f"Sicherheit: Zugriff auf Auth-Datei '{basename}' via Bash blockiert"

    return None


def check_bash_file_access(command: str) -> str | None:
    """Prueft ob ein Bash-Befehl auf geschuetzte Dateien zugreift."""
    cmd_lower = command.lower()

    # Pruefen ob ein datei-lesender Befehl enthalten ist
    has_read_cmd = False
    for cmd in _FILE_READ_COMMANDS:
        # Befehl am Anfang, nach Pipe, nach ; oder nach &&
        if re.search(rf"(?:^|[;|&]\s*){cmd}\b", cmd_lower):
            has_read_cmd = True
            break
        # source und . fuer .env
        if cmd == "source" and "source" in cmd_lower:
            has_read_cmd = True
            break

    # Auch ". .env" (dot-sourcing) erkennen
    if re.search(r"(?:^|[;|&]\s*)\.\s+\.", cmd_lower):
        has_read_cmd = True

    # Auch $() Subshells pruefen
    if "$(" in command:
        has_read_cmd = True

    if not has_read_cmd:
        return None

    # Alle Datei-Tokens extrahieren und pruefen
    tokens = _extract_file_tokens(command)
    for token in tokens:
        # Sichere Dateien ueberspringen
        if _is_file_safe(token):
            continue
        # Blockierte Dateien pruefen
        reason = _is_file_blocked(token)
        if reason:
            return reason

    return None


def check_interpreter_bypass(command: str) -> str | None:
    """Erkennt Interpreter-Wrapping mit Dateizugriff auf PII-Dateien."""
    # python3 -c "open('secret.csv')" / node -e "readFileSync('data.csv')" / bash -c "cat x.csv"
    interpreter_match = re.search(
        r"""(?:python3?|node|bash)\s+(?:-c|-e)\s+(?:"([^"]+)"|'([^']+)')""", command, re.IGNORECASE
    )
    if not interpreter_match:
        return None

    inner = interpreter_match.group(1) or interpreter_match.group(2)
    tokens = _extract_file_tokens(inner)
    for token in tokens:
        if _is_file_safe(token):
            continue
        reason = _is_file_blocked(token)
        if reason:
            return f"Interpreter-Bypass blockiert: {reason}"
    return None


# ─── Env-Dump Erkennung ──────────────────────────────

_ENV_DUMP_PATTERNS = [
    (r"(?:^|[;|&]\s*)env\s*(?:$|[|;>&])", "env-Dump blockiert — kann Secrets anzeigen"),
    (r"(?:^|[;|&]\s*)printenv\s*(?:$|[|;>&])", "printenv-Dump blockiert — kann Secrets anzeigen"),
    (r"(?:^|[;|&]\s*)export\s+-p\b", "export -p blockiert — kann Secrets anzeigen"),
    (r"(?:^|[;|&]\s*)set\s*(?:$|[|;>&])", "set-Dump blockiert — kann Secrets anzeigen"),
    (r"(?:cat|head|tail|less|more)\s+~/?\.\w*(?:bashrc|zshrc|profile|bash_profile)",
     "Zugriff auf Shell-Config blockiert — kann Secrets enthalten"),
]


def check_env_dump(command: str) -> str | None:
    """Blockiert Befehle die Umgebungsvariablen (inkl. Secrets) dumpen."""
    for pattern, reason in _ENV_DUMP_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return reason
    return None


def check_write(file_path: str) -> str | None:
    """Prueft ob eine Datei geschuetzt ist."""
    basename = os.path.basename(file_path)
    basename_lower = basename.lower()
    normalized = file_path.replace("\\", "/").lower()

    # Geschuetzte Dateien (case-insensitive)
    if basename_lower in PROTECTED_FILES:
        return f"Schreiben in geschuetzte Datei '{basename}' blockiert"

    # Geschuetzte Verzeichnisse
    for protected_dir in PROTECTED_DIRS:
        if (f"/{protected_dir}/" in normalized
            or normalized.endswith(f"/{protected_dir}")
            or normalized.startswith(f"{protected_dir}/")):
            return f"Schreiben in geschuetztes Verzeichnis '{protected_dir}/' blockiert"

    # Zertifikate und Keys (case-insensitive)
    if basename_lower.endswith((".key", ".pem", ".p12", ".pfx", ".cer")):
        return f"Schreiben in Zertifikat/Key-Datei '{basename}' blockiert"

    return None


def main() -> None:
    log = HookLog("pre-tool-safety")

    try:
        raw = sys.stdin.read().strip()
        if not raw:
            # Fail-closed: Kein Input = blockieren
            result = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "Sicherheit: Kein Input erhalten — blockiert (fail-closed)."
                }
            }
            print(json.dumps(result))
            return
        data = json.loads(raw)
    except Exception:
        # Fail-closed: Bei Parse-Fehlern blockieren statt erlauben
        result = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Sicherheit: Ungueltiger JSON-Input — blockiert (fail-closed)."
            }
        }
        print(json.dumps(result))
        return

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    reason = None

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        reason = check_bash(command)
        detail = f"Bash: {command[:100]}"
    elif tool_name in ("Write", "Edit"):
        file_path = tool_input.get("file_path", "")
        reason = check_write(file_path)
        detail = f"{tool_name}: {file_path}"
    else:
        detail = f"{tool_name}: skip"

    if reason:
        log.write("BLOCKED", f"{detail} -> {reason}")
        result = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason
            }
        }
        print(json.dumps(result))
    else:
        log.write("ALLOWED", detail)
        print(json.dumps({}))


if __name__ == "__main__":
    main()
