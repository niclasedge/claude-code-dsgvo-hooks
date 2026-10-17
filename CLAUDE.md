# DSGVO-Hooks — Claude Code Sicherheitsschicht

## Projektbeschreibung

Dieses Projekt implementiert eine DSGVO-konforme Sicherheitsschicht fuer Claude Code. Hooks blockieren automatisch den Zugriff auf personenbezogene Daten (PII) und verhindern gefaehrliche Operationen. Ein Mock-Daten-Generator erstellt anonymisierte `.clean`-Versionen von PII-Dateien.

## Architektur

```
.claude/hooks/                       → 10 Python-Hooks (Pre/Post/Prompt/Session)
.claude/hooks/pii_scanner_engine.py  → Zentrale PII-Erkennung (3 Tiers)
.claude/hooks/dsgvo-network-guard.py → URL-Whitelist Network Guard
.claude/hooks/url-whitelist.json     → Konfigurierbare Domain-Whitelist
.claude/tools/generate_mock_data.py  → Mock-Daten-Generator (Presidio + GLiNER)
.claude/tools/pii_cleaner.py        → PII-Cleaner (Scan + Bereinigung, auch als Library)
tests/                               → TDD-Tests fuer alle Hooks
testfiles/                           → Testdaten (PII-Dateien + .clean-Versionen)
```

## Hook-Kette

| Phase | Hook | Schuetzt |
|-------|------|----------|
| **PreToolUse** (Read) | `dsgvo-pii-file-guard.py` | Blockiert Lesen von PII-Dateien (.csv, .xlsx, .json mit PII-Indikatoren, Zertifikate, Keys) |
| **PreToolUse** (Bash/Write/Edit) | `pre-tool-safety.py` | Blockiert gefaehrliche Bash-Befehle (rm -rf, git reset --hard, DROP TABLE, Zugriff auf .env/creds/) |
| **PreToolUse** (Bash) | `dsgvo-network-guard.py` | URL-Whitelist: Blockiert Netzwerkzugriffe auf nicht-whitegelistete Domains |
| **PostToolUse** (Read) | `dsgvo-content-guard.py` | Scannt gelesene Inhalte auf PII, entfernt sie aus dem Kontext |
| **PostToolUse** (Bash) | `dsgvo-output-guard.py` | Scannt Bash-Output auf PII, blockiert Ausgabe |
| **PostToolUse** (Write/Edit) | `post-write-validate.py` | Validiert Python (ruff) und JSON-Syntax |
| **UserPromptSubmit** | `dsgvo-prompt-guard.py` | Scannt Nutzereingaben auf PII (Namen, IBAN, Telefon) |
| **SessionStart** | `dsgvo-session-guard.py` | Prueft CLAUDE.md auf PII beim Sitzungsstart |

## PII-Erkennung (3 Tiers)

Der zentrale Scanner (`pii_scanner_engine.py`) arbeitet in drei Stufen:

- **Tier 1** — Regex (<1ms): IBAN, Telefon, Geburtsdatum, SVN, Email, IPv4
- **Tier 2** — Keyword-Kontext (<5ms): Credentials (password=X), Connection Strings, API Keys
- **Tier 3** — GLiNER NLP (~50-200ms): Personen, Organisationen, Adressen

## Arbeiten mit PII-Dateien

### Grundregel

PII-Dateien (`.csv`, `.xlsx`, `.json` mit Kundenbezeichnern, `.ldif`, `.sql`, etc.) werden automatisch blockiert. Arbeite immer mit `.clean`-Versionen.

### Mock-Daten erstellen

```bash
# Einzelne Datei anonymisieren → erstellt datei.csv.clean
uv run --extra mock-data .claude/tools/generate_mock_data.py testfiles/customers.csv

# PII-Fundstellen anzeigen (mit Ersetzungsvorschau)
uv run --extra mock-data .claude/tools/generate_mock_data.py --dry testfiles/customers.csv

# Interaktives Menu
uv run --extra mock-data .claude/tools/generate_mock_data.py

# Direkte Aktionen ohne Menu (--action / -a)
uv run --extra mock-data .claude/tools/generate_mock_data.py --action deep-scan        # Deep Scan aller PII
uv run --extra mock-data .claude/tools/generate_mock_data.py --action protect-data     # Datendateien → .clean
uv run --extra mock-data .claude/tools/generate_mock_data.py --action protect-source   # Source-Code → .clean
uv run --extra mock-data .claude/tools/generate_mock_data.py --action regenerate-all   # Alle .clean neu generieren

# Anderes Verzeichnis scannen
uv run --extra mock-data .claude/tools/generate_mock_data.py --action deep-scan -d testfiles/
```

### Sichere Dateimuster

Diese Dateien werden von Hooks **immer erlaubt**:

- `*.clean` — Anonymisierte Versionen (z.B. `customers.csv.clean`)
- `mock_*` — Mock-Dateien (z.B. `mock_customers.csv`)
- `fixture`, `example`, `sample`, `template` im Dateinamen
- Source-Code-Dateien (`.py`, `.js`, `.ts`, `.go`, etc.)

### PII-Cleaner — Dateien scannen und bereinigen

Der PII-Cleaner scannt beliebige Dateien (JSONL, JSON, Text, Logs, Source) auf PII
und ersetzt sie durch Mock-Daten. Nutzbar als CLI und als Python-Library.

```bash
# Verzeichnis scannen (z.B. .claude/ oder logs/)
uv run .claude/tools/pii_cleaner.py scan .claude/
uv run .claude/tools/pii_cleaner.py scan logs/ --muster "*.jsonl"

# Datei bereinigen (Vorschau)
uv run .claude/tools/pii_cleaner.py clean data.jsonl --dry

# Datei bereinigen (in-place mit Backup)
uv run .claude/tools/pii_cleaner.py clean data.jsonl --backup

# Verzeichnis bereinigen
uv run .claude/tools/pii_cleaner.py clean logs/ --dry

# Interaktives Menu
uv run .claude/tools/pii_cleaner.py
```

Als Library (fuer Skripting/Hooks):
```python
from pii_cleaner import PIICleaner
cleaner = PIICleaner(tier=3)
report = cleaner.scan_file("audit.jsonl")       # ScanReport
result = cleaner.clean_file("data.jsonl")        # CleanResult (in-place)
result = cleaner.clean_text("Max Mustermann")    # CleanResult
reports = cleaner.scan_directory("logs/")         # list[ScanReport]
```

### Wenn ein Hook blockiert

1. Lies die Fehlermeldung — sie enthaelt Alternativen
2. Pruefe ob eine `.clean`-Version existiert: `ls datei.csv.clean`
3. Erstelle eine: `uv run --extra mock-data .claude/tools/generate_mock_data.py datei.csv`
4. Nutze die `.clean`-Version fuer die Arbeit

## Tests ausfuehren

```bash
# Alle Tests
uv run pytest tests/ -v

# Einzelner Hook
uv run pytest tests/test_pii_file_guard.py -v

# NLP-Tests (benoetigen GLiNER-Modell, langsamer)
uv run pytest tests/test_pii_scanner_nlp.py -v
```

## URL-Whitelist (Netzwerk-Guard)

Der Network Guard blockiert alle Netzwerkzugriffe auf nicht-whitegelistete Domains. Konfiguration in `.claude/hooks/url-whitelist.json`.

### Domain hinzufuegen

Neue Domain in `erlaubte_domains` eintragen:
```json
{
  "erlaubte_domains": [
    "github.com",
    "*.github.com",
    "neue-domain.example.com"
  ]
}
```

### Was wird geprueft

- **curl, wget, ssh, scp, sftp, rsync** — Alle gaengigen Netzwerk-Tools
- **python -c "requests.get(...)"** — Interpreter-Netzwerk-Bypass
- **git clone/fetch/pull mit URLs** — Git-Remote-Zugriffe
- **pip/npm install mit URLs** — Package-Installationen von URLs
- **nc, ncat, socat** — Netzwerk-Utilities

### Was ist immer erlaubt

- **localhost, 127.0.0.1, 0.0.0.0** — Lokale Adressen
- **10.x.x.x, 172.16-31.x.x, 192.168.x.x** — Private Netzwerke
- **git push/pull origin** — Konfigurierte Git-Remotes (ohne explizite URL)
- **curl --help, wget --version** — Hilfe-Befehle

## Wichtige Regeln

- **Niemals PII in Code, Commits oder Logs** — Hooks blockieren das, aber bewusst vermeiden
- **Immer `.clean`-Versionen nutzen** — Nie Originaldaten lesen oder verarbeiten
- **Tests vor Aenderungen** — Hooks haben umfangreiche TDD-Tests, `uv run pytest` vor Commits
- **Fail-Closed-Prinzip** — Im Zweifel blockieren die Hooks (sicherer Default)
- **Sprache: Deutsch** — Kommentare, Commit-Messages, Variablennamen deutsch wo sinnvoll
