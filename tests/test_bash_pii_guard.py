# /// script
# requires-python = ">=3.10"
# dependencies = ["pytest"]
# ///
"""
TDD-Tests: Bash-Kommandos die PII-Dateien lesen werden blockiert
=================================================================
Bash-Befehle wie cat, head, tail, less, grep auf PII-Dateien
muessen vom pre-tool-safety Hook blockiert werden.

Hook: pre-tool-safety.py (PreToolUse auf Bash)
"""
from __future__ import annotations

from tests.helpers import make_bash_input, run_hook, TESTFILES_DIR

HOOK = "pre-tool-safety.py"


# ─── BLOCKIEREN: cat/head/tail auf PII-Dateien ────────


class TestBlockBashReadPiiFiles:
    """Bash-Lesebefehle auf PII-Dateien muessen blockiert werden."""

    def test_block_cat_csv(self):
        result = run_hook(HOOK, make_bash_input("cat customers.csv"))
        assert "deny" in str(result)

    def test_block_cat_csv_full_path(self):
        result = run_hook(HOOK, make_bash_input(f"cat {TESTFILES_DIR}/customers.csv"))
        assert "deny" in str(result)

    def test_block_head_csv(self):
        result = run_hook(HOOK, make_bash_input("head -n 5 export.csv"))
        assert "deny" in str(result)

    def test_block_tail_csv(self):
        result = run_hook(HOOK, make_bash_input("tail -20 kunden.tsv"))
        assert "deny" in str(result)

    def test_block_less_csv(self):
        result = run_hook(HOOK, make_bash_input("less mitarbeiter.csv"))
        assert "deny" in str(result)

    def test_block_more_csv(self):
        result = run_hook(HOOK, make_bash_input("more users.xlsx"))
        assert "deny" in str(result)

    def test_block_cat_xlsx(self):
        result = run_hook(HOOK, make_bash_input("cat report.xlsx"))
        assert "deny" in str(result)

    def test_block_cat_xls(self):
        result = run_hook(HOOK, make_bash_input("cat legacy.xls"))
        assert "deny" in str(result)

    def test_block_cat_sql(self):
        result = run_hook(HOOK, make_bash_input("cat dump.sql"))
        assert "deny" in str(result)

    def test_block_cat_vcf(self):
        result = run_hook(HOOK, make_bash_input("cat contacts.vcf"))
        assert "deny" in str(result)

    def test_block_cat_ldif(self):
        result = run_hook(HOOK, make_bash_input("cat export.ldif"))
        assert "deny" in str(result)


# ─── BLOCKIEREN: grep/awk/sed auf PII-Dateien ─────────


class TestBlockBashSearchPiiFiles:
    """Bash-Suchbefehle auf PII-Dateien muessen blockiert werden."""

    def test_block_grep_csv(self):
        result = run_hook(HOOK, make_bash_input("grep 'Mueller' customers.csv"))
        assert "deny" in str(result)

    def test_block_grep_r_csv(self):
        result = run_hook(HOOK, make_bash_input("grep -r 'email' *.csv"))
        assert "deny" in str(result)

    def test_block_awk_csv(self):
        result = run_hook(HOOK, make_bash_input("awk -F, '{print $2}' employees.csv"))
        assert "deny" in str(result)

    def test_block_sed_csv(self):
        result = run_hook(HOOK, make_bash_input("sed -n '1,5p' data.tsv"))
        assert "deny" in str(result)

    def test_block_wc_csv(self):
        result = run_hook(HOOK, make_bash_input("wc -l personal.csv"))
        assert "deny" in str(result)

    def test_block_sort_csv(self):
        result = run_hook(HOOK, make_bash_input("sort kunden.csv"))
        assert "deny" in str(result)

    def test_block_cut_tsv(self):
        result = run_hook(HOOK, make_bash_input("cut -f1 access_log.tsv"))
        assert "deny" in str(result)


# ─── BLOCKIEREN: Bash auf Zertifikate/Keys ─────────────


class TestBlockBashReadCerts:
    """Bash-Lesebefehle auf Zertifikate/Keys muessen blockiert werden."""

    def test_block_cat_pem(self):
        result = run_hook(HOOK, make_bash_input("cat server.pem"))
        assert "deny" in str(result)

    def test_block_cat_key(self):
        result = run_hook(HOOK, make_bash_input("cat private.key"))
        assert "deny" in str(result)

    def test_block_cat_p12(self):
        result = run_hook(HOOK, make_bash_input("cat keystore.p12"))
        assert "deny" in str(result)

    def test_block_cat_pfx(self):
        result = run_hook(HOOK, make_bash_input("cat client.pfx"))
        assert "deny" in str(result)

    def test_block_cat_cer(self):
        result = run_hook(HOOK, make_bash_input("cat ca-cert.cer"))
        assert "deny" in str(result)

    def test_block_head_pem(self):
        result = run_hook(HOOK, make_bash_input("head -1 /etc/ssl/cert.pem"))
        assert "deny" in str(result)

    def test_block_openssl_read_key(self):
        result = run_hook(HOOK, make_bash_input("openssl rsa -in private.key -text"))
        assert "deny" in str(result)

    def test_block_base64_key(self):
        result = run_hook(HOOK, make_bash_input("base64 server.pem"))
        assert "deny" in str(result)

    def test_block_cat_jks(self):
        result = run_hook(HOOK, make_bash_input("cat truststore.jks"))
        assert "deny" in str(result)

    def test_block_cat_crt(self):
        result = run_hook(HOOK, make_bash_input("cat domain.crt"))
        assert "deny" in str(result)

    def test_block_cat_csr(self):
        result = run_hook(HOOK, make_bash_input("cat request.csr"))
        assert "deny" in str(result)


# ─── BLOCKIEREN: Bash auf Auth-Skripte ─────────────────


class TestBlockBashReadAuth:
    """Bash-Lesebefehle auf Auth-Dateien muessen blockiert werden."""

    def test_block_cat_env(self):
        result = run_hook(HOOK, make_bash_input("cat .env"))
        assert "deny" in str(result)

    def test_block_cat_env_local(self):
        result = run_hook(HOOK, make_bash_input("cat .env.local"))
        assert "deny" in str(result)

    def test_block_cat_env_production(self):
        result = run_hook(HOOK, make_bash_input("cat .env.production"))
        assert "deny" in str(result)

    def test_block_cat_auth_ps1(self):
        result = run_hook(HOOK, make_bash_input("cat auth.ps1"))
        assert "deny" in str(result)

    def test_block_cat_auth_sh(self):
        result = run_hook(HOOK, make_bash_input("cat deploy_auth.sh"))
        assert "deny" in str(result)

    def test_block_source_env(self):
        result = run_hook(HOOK, make_bash_input("source .env"))
        assert "deny" in str(result)

    def test_block_dot_env(self):
        """. .env (dot-sourcing)"""
        result = run_hook(HOOK, make_bash_input(". .env"))
        assert "deny" in str(result)

    def test_block_cat_secrets_yaml(self):
        result = run_hook(HOOK, make_bash_input("cat secrets.yaml"))
        assert "deny" in str(result)

    def test_block_cat_secrets_yml(self):
        result = run_hook(HOOK, make_bash_input("cat secrets.yml"))
        assert "deny" in str(result)


# ─── BLOCKIEREN: Bash auf SQLite ───────────────────────


class TestBlockBashReadDatabase:
    """Bash-Lesebefehle auf Datenbanken blockiert."""

    def test_block_cat_sqlite(self):
        result = run_hook(HOOK, make_bash_input("cat users.db"))
        assert "deny" in str(result)

    def test_block_cat_sqlite3(self):
        result = run_hook(HOOK, make_bash_input("cat app.sqlite3"))
        assert "deny" in str(result)

    def test_block_cat_sqlite_ext(self):
        result = run_hook(HOOK, make_bash_input("cat data.sqlite"))
        assert "deny" in str(result)

    def test_block_strings_db(self):
        """strings-Befehl auf DB blockiert (Daten-Extraktion)."""
        result = run_hook(HOOK, make_bash_input("strings users.db"))
        assert "deny" in str(result)

    def test_block_xxd_db(self):
        """Hex-Dump auf DB blockiert."""
        result = run_hook(HOOK, make_bash_input("xxd data.sqlite"))
        assert "deny" in str(result)


# ─── ERLAUBEN: .clean-Dateien via Bash ─────────────────


class TestAllowBashCleanFiles:
    """.clean-Dateien duerfen auch via Bash gelesen werden."""

    def test_allow_cat_csv_clean(self):
        result = run_hook(HOOK, make_bash_input("cat customers.csv.clean"))
        assert "deny" not in str(result)

    def test_allow_head_json_clean(self):
        result = run_hook(HOOK, make_bash_input("head -5 employees.json.clean"))
        assert "deny" not in str(result)

    def test_allow_grep_tsv_clean(self):
        result = run_hook(HOOK, make_bash_input("grep 'test' access_log.tsv.clean"))
        assert "deny" not in str(result)

    def test_allow_cat_mock_csv(self):
        result = run_hook(HOOK, make_bash_input("cat mock_customers.csv"))
        assert "deny" not in str(result)


# ─── ERLAUBEN: Normale Bash-Befehle ───────────────────


class TestAllowNormalBash:
    """Normale Bash-Befehle ohne PII-Dateien erlaubt."""

    def test_allow_cat_py(self):
        result = run_hook(HOOK, make_bash_input("cat test.py"))
        assert "deny" not in str(result)

    def test_allow_head_log(self):
        result = run_hook(HOOK, make_bash_input("head -20 server.log"))
        assert "deny" not in str(result)

    def test_allow_grep_md(self):
        result = run_hook(HOOK, make_bash_input("grep 'TODO' README.md"))
        assert "deny" not in str(result)

    def test_allow_cat_yaml(self):
        result = run_hook(HOOK, make_bash_input("cat docker-compose.yml"))
        assert "deny" not in str(result)

    def test_allow_ls_general(self):
        """ls ohne Dateizugriff erlaubt."""
        result = run_hook(HOOK, make_bash_input("ls -la"))
        assert "deny" not in str(result)

    def test_allow_git_status(self):
        result = run_hook(HOOK, make_bash_input("git status"))
        assert "deny" not in str(result)

    def test_allow_python_run(self):
        result = run_hook(HOOK, make_bash_input("python test.py"))
        assert "deny" not in str(result)

    def test_allow_cat_normal_json(self):
        """config.json ohne PII-Indikator erlaubt."""
        result = run_hook(HOOK, make_bash_input("cat config.json"))
        assert "deny" not in str(result)

    def test_allow_cat_normal_xml(self):
        """settings.xml ohne PII-Indikator erlaubt."""
        result = run_hook(HOOK, make_bash_input("cat settings.xml"))
        assert "deny" not in str(result)

    def test_allow_normal_sh(self):
        """cat build.sh ohne auth erlaubt."""
        result = run_hook(HOOK, make_bash_input("cat build.sh"))
        assert "deny" not in str(result)


# ─── EDGE CASES: Pipe-Chains, Quoting ─────────────────


class TestBashEdgeCases:
    """Grenzfaelle: Pipes, Redirects, Quoting."""

    def test_block_pipe_csv(self):
        """cat csv | grep blockiert."""
        result = run_hook(HOOK, make_bash_input("cat export.csv | grep 'name'"))
        assert "deny" in str(result)

    def test_block_redirect_csv(self):
        """Redirect von csv blockiert."""
        result = run_hook(HOOK, make_bash_input("cat kunden.csv > /tmp/out.txt"))
        assert "deny" in str(result)

    def test_block_quoted_csv(self):
        """Dateiname in Quotes blockiert."""
        result = run_hook(HOOK, make_bash_input('cat "customers.csv"'))
        assert "deny" in str(result)

    def test_block_single_quoted_csv(self):
        result = run_hook(HOOK, make_bash_input("cat 'employees.csv'"))
        assert "deny" in str(result)

    def test_block_subshell_csv(self):
        """Subshell mit csv blockiert."""
        result = run_hook(HOOK, make_bash_input("$(cat secret.csv)"))
        assert "deny" in str(result)

    def test_block_xargs_csv(self):
        result = run_hook(HOOK, make_bash_input("xargs cat < files.csv"))
        assert "deny" in str(result)

    def test_block_semicolon_csv(self):
        """Mehrere Befehle mit ; blockiert wenn csv dabei."""
        result = run_hook(HOOK, make_bash_input("echo test; cat personal.csv"))
        assert "deny" in str(result)

    def test_block_and_csv(self):
        """&& chain blockiert wenn csv dabei."""
        result = run_hook(HOOK, make_bash_input("cd /tmp && cat export.xlsx"))
        assert "deny" in str(result)

    def test_block_case_insensitive(self):
        result = run_hook(HOOK, make_bash_input("cat DATA.CSV"))
        assert "deny" in str(result)
