# claude-code-dsgvo-hooks

[![Tests](https://github.com/niclasedge/claude-code-dsgvo-hooks/actions/workflows/test.yml/badge.svg)](https://github.com/niclasedge/claude-code-dsgvo-hooks/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Claude Code hooks that try to keep personal data out of the model context, as a
technical building block for a DSGVO / GDPR-minded setup. They run locally, use
only the Python standard library, and need no network access.

> **Not legal advice.** The hooks reduce the chance that personal data (PII),
> credentials, or certificates reach the model. They do not make a deployment
> DSGVO/GDPR-compliant on their own. Whether and how you may process personal data
> with an AI service (legal basis, data processing agreement, data protection
> impact assessment) is a separate question for your data protection officer.

## The problem

Claude Code reads files, runs shell commands, and sends the results to the model.
Anything in a prompt, a file, or a command's output becomes part of the context that
is transmitted to the provider. In a typical project that includes customer
exports (`customers.csv`), employee files, `.env` files, private keys, and logs
with e-mail addresses or IBANs. A developer can paste such data into a prompt just as
easily as the agent can `cat` it.

## What the hooks do

Eight scripts in [`.claude/hooks/`](.claude/hooks) are registered in
[`.claude/settings.json`](.claude/settings.json) on these Claude Code hook events:

| Event | Matcher | Script | Behavior |
|---|---|---|---|
| `UserPromptSubmit` | all | `dsgvo-prompt-guard.py` | Blocks a prompt that contains an IBAN, phone number, date of birth, social insurance number, or a name from an optional name list. |
| `PreToolUse` | `Read` | `dsgvo-pii-file-guard.py` | Denies reading files by extension and file name: `.csv`, `.xlsx`, `.ldif`, `.sql`, `.sqlite`, certificates/keys (`.pem`, `.key`, `.p12`, ...), `.env*`, auth scripts (`auth.ps1`, `deploy_auth.sh`), `secrets.yaml`/`secrets.json`, and `.json`/`.xml` whose name suggests personal data (`customer`, `employee`, `kunden`, ...). Files ending in `.clean` or starting with `mock_` are allowed. |
| `PreToolUse` | `Bash`, `Write`, `Edit` | `pre-tool-safety.py` | Denies destructive commands (`rm -rf /`, `git reset --hard`, force-push to main, `DROP TABLE`, `curl ... \| sh`), risky PowerShell cmdlets, writes to `.env`/SSH keys/`.aws`, and Bash commands such as `cat`/`grep`/`head` on files the file guard would block. |
| `PreToolUse` | `Bash` | `dsgvo-network-guard.py` | Denies network commands (`curl`, `wget`, `ssh`, `scp`, `nc`, ...) to hosts that are not on [`url-whitelist.json`](.claude/hooks/url-whitelist.json). Unparsable input is denied (fail-closed). |
| `PostToolUse` | `Read` | `dsgvo-content-guard.py` | Scans the content of the file that was read; on a finding it exits with code 2 and a warning on stderr. |
| `PostToolUse` | `Bash` | `dsgvo-output-guard.py` | Scans stdout/stderr of a command; on a finding it exits with code 2 and a warning on stderr. |
| `PostToolUse` | `Write`, `Edit` | `post-write-validate.py` | Runs `ruff` on Python files and a syntax check on JSON files (not PII related; code hygiene). |
| `SessionStart` | all | `dsgvo-session-guard.py` | Scans `CLAUDE.md` and `.claude/CLAUDE.md` of the project and warns if they contain PII. |

`pii_scanner_engine.py` is the shared detector, and `hook_logger.py` writes one
log line per hook call. The hook messages are in German.

### Detection

The scanner has three tiers; the hooks use tiers 1 and 2.

- **Tier 1, regular expressions:** IBAN (DE-style layout, no checksum validation),
  German phone numbers (`+49`, `0049`, `0...`), dates `DD.MM.YYYY`, German social
  insurance number (`12A345678B901`), e-mail addresses, public IPv4 addresses.
  Known-safe values are filtered: `@example.*`, `@localhost`, `noreply@`,
  `testuser...`, all-zero IBANs, private IP ranges.
- **Tier 2, keyword context:** `password`/`passwort`/`secret`/`token`/`api key` followed by `:` or `=`
  and a value, connection strings (`postgres://`, `mysql://`, `mongodb://`, `redis://`, `amqp://`),
  and API key formats (`sk-...`, `AKIA...`, `ghp_...`, `gho_...`, `xoxb-...`).
- **Tier 3, NLP (names, organizations, addresses):** uses
  [GLiNER](https://github.com/urchade/GLiNER) if it is installed. The hooks do not
  enable it (it costs 50-200 ms per call and downloads a model); it is available to the
  optional tools below.

### Optional tools

- [`.claude/tools/pii_cleaner.py`](.claude/tools/pii_cleaner.py) (stdlib): scan files
  or directories for PII and replace findings with mock values.
  `uv run .claude/tools/pii_cleaner.py scan <path>`, `... clean <file> --dry`.
- [`.claude/tools/generate_mock_data.py`](.claude/tools/generate_mock_data.py): creates
  anonymized `<file>.clean` versions of CSV/JSON/text files with Presidio and GLiNER.
  Needs the extra: `uv run --extra mock-data .claude/tools/generate_mock_data.py --dry testfiles/customers.csv`.
  The extra is heavy (PyTorch, spaCy) and downloads models at first run.

## Installation

Requirements: [uv](https://docs.astral.sh/uv/), Python 3.10 or newer, Claude Code.

1. Copy the directory `.claude/hooks/` into your project's `.claude/` directory.
2. Merge the `hooks` section of [`.claude/settings.json`](.claude/settings.json)
   into your project's `.claude/settings.json` (or `.claude/settings.local.json`). Each
   entry runs `uv run .claude/hooks/<script>.py` from `$CLAUDE_PROJECT_DIR`.
3. Restart Claude Code. The `statusMessage` texts (`DSGVO Safety-Check...`) show
   up while the hooks run.

To try it in this repository, open it with Claude Code; the hooks in
`.claude/settings.json` are active immediately.

## Configuration

- **Network allow list:** edit `.claude/hooks/url-whitelist.json`
  (`erlaubte_domains` with `*.` wildcards, `erlaubte_urls`, `blockierte_domains`).
  Changes apply on the next call.
- **Name list (optional):** the prompt guard reads `.claude/hooks/pii-guard/config/names.txt`
  if the file exists, one `Firstname Lastname` per line, `#` for comments. The file is
  not part of this repository. Without it, names in prompts are not detected.
- **File rules:** the extension and file-name lists are constants at the top of
  `dsgvo-pii-file-guard.py` and `pre-tool-safety.py`.
- **Logs:** `logs/hooks-YYYY-MM-DD.log` (one line per call) and, for blocked prompts,
  `logs/dsgvo-audit/YYYY-MM/audit-YYYY-MM-DD.jsonl`. `logs/` is git-ignored.

## Example output

A prompt with an IBAN and a phone number (`UserPromptSubmit`):

```console
$ echo '{"prompt":"Check the customer with IBAN DE89 3704 0044 0532 0130 00, phone +49 170 1234567"}' \
    | uv run .claude/hooks/dsgvo-prompt-guard.py
{"decision": "block", "reason": "DSGVO: Prompt enthaelt personenbezogene Daten (Telefon, IBAN). Bitte PII aus dem Prompt entfernen."}
```

A read of a customer export (`PreToolUse`, abbreviated):

```console
$ echo '{"tool_name":"Read","tool_input":{"file_path":"/data/customers.csv"}}' \
    | uv run .claude/hooks/dsgvo-pii-file-guard.py
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
 "permissionDecisionReason": "DSGVO: Zugriff auf 'customers.csv' blockiert — Datei koennte personenbezogene Daten enthalten. Alternativen: ... /data/customers.csv.clean ..."}}
```

A network call to a host that is not on the allow list:

```console
$ echo '{"tool_name":"Bash","tool_input":{"command":"curl https://evil.example.org/x"}}' \
    | uv run .claude/hooks/dsgvo-network-guard.py
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
 "permissionDecisionReason": "Netzwerk: Domain 'evil.example.org' nicht in URL-Whitelist. Erlaubte Domains: siehe .claude/hooks/url-whitelist.json"}}
```

Command output that contains an e-mail address (`PostToolUse`, exit code 2):

```console
$ echo '{"tool_name":"Bash","tool_response":{"stdout":"contact: max.mustermann@acme-corp.de"}}' \
    | uv run .claude/hooks/dsgvo-output-guard.py
DSGVO-WARNUNG: Tool-Output enthaelt Personendaten (Email). Output wurde nicht in den Kontext uebernommen.
$ echo $?
2
```

## Limitations

- **Pattern matching, not understanding.** Tiers 1 and 2 are regular expressions.
  Expect false positives (a version number or an ID that looks like a phone number or
  date) and false negatives (an IBAN of another country layout, free-text names and
  addresses, personal data in an unusual format). The patterns are tuned for German data.
- **Names are only found through the optional name list.** NLP-based name detection is
  not enabled in the hooks.
- **`PostToolUse` runs after the tool has executed.** The content and output guards
  report a finding with exit code 2 and a message, and their messages say the content
  was not taken into the context. Whether Claude Code withholds the original tool
  output in that case is a property of Claude Code, not of this repository; treat the
  `PostToolUse` guards as a second line and rely on the `PreToolUse` file guard to
  prevent the read.
- **Only the matched tools are covered.** The hooks watch `Read`, `Bash`, `Write`,
  `Edit` and prompts. Other tools (for example `Grep`, `WebFetch`, MCP servers) are
  not hooked. The Bash checks are heuristics on the command text and can be
  bypassed by indirect commands (scripts that read a file themselves, encoded commands).
- **File rules work on names and extensions.** A personal-data file called `notes.txt`
  passes the file guard; the `PostToolUse` content scan is then the only check.
  Source code and Markdown files are not content-scanned.
- **Logs may contain fragments.** Hook log lines contain file paths and command
  excerpts (up to 150 characters), and the prompt audit log stores the first 40
  characters of a blocked prompt. Treat `logs/` as sensitive.
- **The prompt itself is sent before any later check.** `UserPromptSubmit` blocks
  prompts that match; anything the patterns miss is sent to the model.

## Development

```bash
uv run --no-project --with pytest pytest          # hook and scanner tests, stdlib only
uv run --extra mock-data --with pytest pytest     # also the Presidio/GLiNER generator tests
```

The three test modules for the Presidio-based generator are skipped unless the
`mock-data` extra and the spaCy model `de_core_news_lg` are installed. `testfiles/`
contains synthetic fixtures only (fictional names, `example.test` addresses,
placeholder certificates and keys). Secret scanning: `gitleaks git .` (reviewed
false positives are listed in `.gitleaksignore`).

## License

[Apache-2.0](LICENSE)
