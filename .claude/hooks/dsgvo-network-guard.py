#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
PreToolUse Hook: Network Guard (URL-Whitelist)
================================================

Blockiert Netzwerkzugriffe (curl, wget, ssh, scp, etc.) die nicht
in der URL-Whitelist stehen. Fail-Closed: Unbekannte URLs werden blockiert.

Whitelist-Konfiguration: .claude/hooks/url-whitelist.json

Rueckgabe:
  Erlauben:  {}
  Blockieren: {"hookSpecificOutput": {"hookEventName": "PreToolUse",
               "permissionDecision": "deny", "permissionDecisionReason": "..."}}
"""

import fnmatch
import json
import os
import re
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(__file__))
from hook_logger import HookLog

# === Netzwerk-Tools die ueberwacht werden ===
NETZWERK_BEFEHLE = [
    "curl", "wget", "http", "https",  # HTTP-Clients
    "ssh", "scp", "sftp", "rsync",    # Remote-Zugriff
    "ftp", "tftp", "telnet",          # Legacy-Protokolle
    "nc", "ncat", "netcat", "socat",  # Netzwerk-Utilities
    "nmap", "ping",                    # Netzwerk-Scanning
    "dig", "nslookup", "host",        # DNS-Abfragen
    "aria2c", "axel",                  # Download-Manager
]

# Patterns die eine URL im Befehl erkennen
_URL_PATTERN = re.compile(
    r"""(?:https?://|ftp://|ssh://|sftp://|git://|s3://)"""
    r"""([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"""
    r"""(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*)"""
    r"""(?:[:/]|$)""",
    re.IGNORECASE,
)

# Pattern fuer hostname:port oder user@host (ssh/scp)
_HOST_PATTERN = re.compile(
    r"""(?:^|\s)(?:\w+@)?"""
    r"""([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"""
    r"""(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)+)"""
    r"""(?::\S*|\s|$)""",
)

# Sichere lokale Adressen (kein Whitelist-Check noetig)
_LOKALE_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "[::1]", "host.docker.internal",
}

# Lokale Netzwerk-Prefixes
_LOKALE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.")


def _lade_whitelist() -> dict:
    """Laedt die URL-Whitelist-Konfiguration."""
    config_pfad = os.path.join(os.path.dirname(__file__), "url-whitelist.json")
    if not os.path.exists(config_pfad):
        # Keine Whitelist = alles blockieren (fail-closed)
        return {"erlaubte_domains": [], "erlaubte_urls": [],
                "blockierte_domains": [], "fail_closed": True}
    with open(config_pfad, encoding="utf-8") as f:
        return json.load(f)


def _ist_domain_erlaubt(domain: str, config: dict) -> bool:
    """Prueft ob eine Domain in der Whitelist steht."""
    domain = domain.lower().strip(".")

    # Lokale Adressen immer erlaubt
    if domain in _LOKALE_HOSTS:
        return True
    if any(domain.startswith(p) for p in _LOKALE_PREFIXES):
        return True

    # Explizit blockierte Domains zuerst pruefen
    for blockiert in config.get("blockierte_domains", []):
        if fnmatch.fnmatch(domain, blockiert.lower()):
            return False

    # Erlaubte Domains pruefen (mit Wildcard-Support)
    for erlaubt in config.get("erlaubte_domains", []):
        erlaubt_lower = erlaubt.lower()
        if fnmatch.fnmatch(domain, erlaubt_lower):
            return True
        # Exakter Match
        if domain == erlaubt_lower:
            return True

    return False


def _ist_url_erlaubt(url: str, config: dict) -> bool:
    """Prueft ob eine vollstaendige URL in der Whitelist steht."""
    for erlaubt in config.get("erlaubte_urls", []):
        if url.startswith(erlaubt):
            return True
    return False


def _extrahiere_domains(command: str) -> list[str]:
    """Extrahiert alle Domains/Hosts aus einem Bash-Befehl."""
    domains = []

    # URLs mit Protokoll extrahieren
    for match in _URL_PATTERN.finditer(command):
        domain = match.group(1).lower()
        domains.append(domain)

    # Host-Patterns (user@host:path, host:port)
    for match in _HOST_PATTERN.finditer(command):
        host = match.group(1).lower()
        # Nur echte Hostnames (mind. 1 Punkt, kein reiner Dateipfad)
        if "." in host and not host.endswith((".py", ".sh", ".txt", ".json",
                                              ".csv", ".log", ".md", ".yaml",
                                              ".yml", ".toml", ".xml", ".html",
                                              ".js", ".ts", ".go", ".rs",
                                              ".cfg", ".ini", ".conf")):
            domains.append(host)

    return domains


def _extrahiere_urls(command: str) -> list[str]:
    """Extrahiert vollstaendige URLs aus einem Befehl."""
    url_pattern = re.compile(r"https?://\S+", re.IGNORECASE)
    return url_pattern.findall(command)


def _hat_netzwerk_befehl(command: str) -> bool:
    """Prueft ob der Befehl ein Netzwerk-Tool verwendet."""
    cmd_lower = command.lower()
    for befehl in NETZWERK_BEFEHLE:
        # Am Anfang, nach Pipe, nach ; oder nach &&
        if re.search(rf"(?:^|[;|&]\s*){re.escape(befehl)}\b", cmd_lower):
            return True
    # Python/Node mit Netzwerk-Modulen
    if re.search(r"(?:python3?|node)\s+(?:-c|-e)\s+", cmd_lower):
        netzwerk_module = [
            r"requests\.", "urllib", r"http\.client", "httpx",
            "aiohttp", r"socket\.", "paramiko",
            r"fetch\(", r"http\.get\(", "axios",
        ]
        for modul in netzwerk_module:
            if re.search(modul, command, re.IGNORECASE):
                return True
    # pip/npm install mit URL
    if re.search(r"(?:pip|npm|yarn)\s+install\s+.*https?://", cmd_lower):
        return True
    # git clone/fetch/pull mit URL
    if re.search(r"git\s+(?:clone|fetch|pull|push|remote\s+add)\s+.*(?:https?://|git@)",
                 cmd_lower):
        return True
    return False


def check_netzwerk(command: str) -> str | None:
    """
    Prueft ob ein Bash-Befehl Netzwerkzugriffe auf nicht-whitegelistete Domains macht.

    Returns:
        None wenn erlaubt, Blockierungsgrund als String wenn blockiert.
    """
    # Kein Netzwerk-Befehl → erlauben
    if not _hat_netzwerk_befehl(command):
        return None

    config = _lade_whitelist()

    # Domains extrahieren
    domains = _extrahiere_domains(command)
    urls = _extrahiere_urls(command)

    # Keine Domain gefunden aber Netzwerk-Befehl erkannt
    if not domains and not urls:
        # Befehle ohne erkennbare Domain: curl --help, wget --version etc.
        # Erkennung ob es ein reiner Hilfe/Info-Befehl ist
        if re.search(r"--help|--version|-h\b|-V\b|man\s", command):
            return None
        # ping/dig/nslookup ohne Domain = nur Tool-Check
        cmd_lower = command.lower().strip()
        for safe_cmd in ("which ", "type ", "command -v "):
            if cmd_lower.startswith(safe_cmd):
                return None
        # git push/pull ohne explizite URL (nutzt konfigurierte Remotes) erlauben
        if re.search(r"git\s+(?:push|pull|fetch)\s+(?:origin|upstream)\b", command):
            return None
        # Fail-closed: Netzwerk-Befehl ohne erkennbares Ziel
        if config.get("fail_closed", True):
            return ("Netzwerk: Befehl enthaelt Netzwerk-Tool ohne erkennbare Domain. "
                    "Nutze explizite URLs damit der Whitelist-Check funktioniert.")

    # Alle URLs gegen Whitelist pruefen
    for url in urls:
        if _ist_url_erlaubt(url, config):
            continue
        # URL nicht in Whitelist → Domain pruefen
        parsed = urlparse(url)
        if parsed.hostname and not _ist_domain_erlaubt(parsed.hostname, config):
            return (f"Netzwerk: Domain '{parsed.hostname}' nicht in URL-Whitelist. "
                    f"Erlaubte Domains: siehe .claude/hooks/url-whitelist.json")

    # Alle Domains pruefen
    for domain in domains:
        if not _ist_domain_erlaubt(domain, config):
            return (f"Netzwerk: Domain '{domain}' nicht in URL-Whitelist. "
                    f"Erlaubte Domains: siehe .claude/hooks/url-whitelist.json")

    return None


def main() -> None:
    log = HookLog("dsgvo-network-guard")

    try:
        raw = sys.stdin.read().strip()
        if not raw:
            print(json.dumps({}))
            return
        data = json.loads(raw)
    except Exception:
        print(json.dumps({}))
        return

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    if tool_name != "Bash":
        print(json.dumps({}))
        return

    command = tool_input.get("command", "")
    reason = check_netzwerk(command)
    detail = f"Netzwerk: {command[:120]}"

    if reason:
        log.write("BLOCKED", f"{detail} -> {reason}")
        result = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
        print(json.dumps(result))
    else:
        log.write("ALLOWED", detail)
        print(json.dumps({}))


if __name__ == "__main__":
    main()
