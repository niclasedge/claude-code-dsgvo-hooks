# /// script
# requires-python = ">=3.10"
# dependencies = ["pytest"]
# ///
"""
TDD-Tests fuer den DSGVO PII-Datei-Guard Hook
================================================
Testet ob der Hook PII-haltige Dateien, Zertifikate und Auth-Skripte
beim Lesen blockiert und .clean-Versionen durchlaesst.

Hook: dsgvo-pii-file-guard.py (PreToolUse auf Read)
"""
from __future__ import annotations

from tests.helpers import make_read_input, run_hook, TESTFILES_DIR

HOOK = "dsgvo-pii-file-guard.py"


# ─── BLOCKIEREN: PII-Dateien ───────────────────────────


class TestBlockPiiFiles:
    """Dateien mit potentiellen Personendaten muessen blockiert werden."""

    def test_block_csv_file(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "customers.csv"))
        assert result.get("decision") == "block"

    def test_block_tsv_file(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "access_log.tsv"))
        assert result.get("decision") == "block"

    def test_block_xlsx_file(self):
        result = run_hook(HOOK, make_read_input("/tmp/mitarbeiter.xlsx"))
        assert result.get("decision") == "block"

    def test_block_xls_file(self):
        result = run_hook(HOOK, make_read_input("/tmp/kunden.xls"))
        assert result.get("decision") == "block"

    def test_block_vcf_file(self):
        result = run_hook(HOOK, make_read_input("/tmp/kontakte.vcf"))
        assert result.get("decision") == "block"

    def test_block_ldif_file(self):
        result = run_hook(HOOK, make_read_input("/tmp/ad_export.ldif"))
        assert result.get("decision") == "block"

    def test_block_xml_with_pii_indicators(self):
        result = run_hook(HOOK, make_read_input("/tmp/mitarbeiter_export.xml"))
        assert result.get("decision") == "block"

    def test_block_json_with_pii_indicators(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "employees.json"))
        assert result.get("decision") == "block"

    def test_block_sql_dump(self):
        result = run_hook(HOOK, make_read_input("/tmp/users_backup.sql"))
        assert result.get("decision") == "block"

    def test_block_kunden_export_xml(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "kunden_export.xml"))
        assert result.get("decision") == "block"

    def test_block_ldif_real_file(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "ad_users.ldif"))
        assert result.get("decision") == "block"


# ─── BLOCKIEREN: Zertifikate und Keys ─────────────────


class TestBlockCertificatesAndKeys:
    """Zertifikate und private Keys duerfen nicht gelesen werden."""

    def test_block_pem_file(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "server.pem"))
        assert result.get("decision") == "block"

    def test_block_key_file(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "private.key"))
        assert result.get("decision") == "block"

    def test_block_p12_file(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "keystore.p12"))
        assert result.get("decision") == "block"

    def test_block_pfx_file(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "client.pfx"))
        assert result.get("decision") == "block"

    def test_block_cer_file(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "ca-cert.cer"))
        assert result.get("decision") == "block"

    def test_block_crt_file(self):
        result = run_hook(HOOK, make_read_input("/tmp/ssl/domain.crt"))
        assert result.get("decision") == "block"

    def test_block_csr_file(self):
        result = run_hook(HOOK, make_read_input("/tmp/ssl/request.csr"))
        assert result.get("decision") == "block"

    def test_block_jks_file(self):
        """Java Keystore blockiert."""
        result = run_hook(HOOK, make_read_input("/tmp/truststore.jks"))
        assert result.get("decision") == "block"

    def test_block_nested_cert(self):
        """Zertifikat in tiefem Pfad blockiert."""
        result = run_hook(HOOK, make_read_input("/opt/ssl/certs/2024/wildcard.pem"))
        assert result.get("decision") == "block"

    def test_block_reason_mentions_certificate(self):
        """Block-Grund erwaehnt Zertifikat."""
        result = run_hook(HOOK, make_read_input("/tmp/server.pem"))
        reason = result.get("reason", "")
        assert "ertifikat" in reason or "key" in reason.lower() or "DSGVO" in reason


# ─── BLOCKIEREN: Auth-Skripte ─────────────────────────


class TestBlockAuthScripts:
    """Auth-Skripte mit Credentials duerfen nicht gelesen werden."""

    def test_block_auth_ps1(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "auth.ps1"))
        assert result.get("decision") == "block"

    def test_block_auth_sh(self):
        result = run_hook(HOOK, make_read_input("/tmp/auth.sh"))
        assert result.get("decision") == "block"

    def test_block_auth_bat(self):
        result = run_hook(HOOK, make_read_input("/tmp/auth.bat"))
        assert result.get("decision") == "block"

    def test_block_auth_cmd(self):
        result = run_hook(HOOK, make_read_input("/tmp/auth.cmd"))
        assert result.get("decision") == "block"

    def test_block_deploy_auth_sh(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "deploy_auth.sh"))
        assert result.get("decision") == "block"

    def test_block_oauth_config(self):
        """JSON mit oauth/auth im Namen blockiert."""
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "oauth_config.json"))
        assert result.get("decision") == "block"

    def test_block_login_credentials_json(self):
        result = run_hook(HOOK, make_read_input("/tmp/login_credentials.json"))
        assert result.get("decision") == "block"

    def test_block_secrets_yaml(self):
        result = run_hook(HOOK, make_read_input("/tmp/secrets.yaml"))
        assert result.get("decision") == "block"

    def test_block_dot_env(self):
        result = run_hook(HOOK, make_read_input("/project/.env"))
        assert result.get("decision") == "block"

    def test_block_env_local(self):
        result = run_hook(HOOK, make_read_input("/project/.env.local"))
        assert result.get("decision") == "block"

    def test_block_env_production(self):
        result = run_hook(HOOK, make_read_input("/project/.env.production"))
        assert result.get("decision") == "block"


# ─── ERLAUBEN: .clean Dateien ──────────────────────────


class TestAllowCleanFiles:
    """.clean-Versionen mit Mock-Daten muessen erlaubt werden."""

    def test_allow_csv_clean(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "customers.csv.clean"))
        assert result.get("decision") != "block"

    def test_allow_json_clean(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "employees.json.clean"))
        assert result.get("decision") != "block"

    def test_allow_tsv_clean(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "access_log.tsv.clean"))
        assert result.get("decision") != "block"

    def test_allow_mock_prefix(self):
        result = run_hook(HOOK, make_read_input("/tmp/mock_customers.csv"))
        assert result.get("decision") != "block"

    def test_allow_test_prefix(self):
        result = run_hook(HOOK, make_read_input("/tmp/test_data.csv.clean"))
        assert result.get("decision") != "block"


# ─── ERLAUBEN: Nicht-PII-Dateien ──────────────────────


class TestAllowSafeFiles:
    """Technische Dateien ohne PII-Risiko muessen erlaubt werden."""

    def test_allow_python_file(self):
        result = run_hook(HOOK, make_read_input("/tmp/test_script.py"))
        assert result.get("decision") != "block"

    def test_allow_config_json(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "config.json"))
        assert result.get("decision") != "block"

    def test_allow_markdown(self):
        result = run_hook(HOOK, make_read_input("/tmp/README.md"))
        assert result.get("decision") != "block"

    def test_allow_yaml(self):
        result = run_hook(HOOK, make_read_input("/tmp/docker-compose.yml"))
        assert result.get("decision") != "block"

    def test_allow_toml(self):
        result = run_hook(HOOK, make_read_input("/tmp/pyproject.toml"))
        assert result.get("decision") != "block"

    def test_allow_gitignore(self):
        result = run_hook(HOOK, make_read_input("/tmp/.gitignore"))
        assert result.get("decision") != "block"

    def test_allow_package_json(self):
        result = run_hook(HOOK, make_read_input("/tmp/package.json"))
        assert result.get("decision") != "block"

    def test_allow_dockerfile(self):
        result = run_hook(HOOK, make_read_input("/tmp/Dockerfile"))
        assert result.get("decision") != "block"

    def test_allow_makefile(self):
        result = run_hook(HOOK, make_read_input("/tmp/Makefile"))
        assert result.get("decision") != "block"

    def test_allow_normal_sh_script(self):
        """Normales .sh-Skript ohne auth im Namen erlaubt."""
        result = run_hook(HOOK, make_read_input("/tmp/build.sh"))
        assert result.get("decision") != "block"

    def test_allow_normal_ps1_script(self):
        """Normales .ps1-Skript ohne auth im Namen erlaubt."""
        result = run_hook(HOOK, make_read_input("/tmp/setup.ps1"))
        assert result.get("decision") != "block"


# ─── HILFSMELDUNG: Vorschlag fuer Alternativen ────────


class TestBlockMessageQuality:
    """Block-Meldungen muessen hilfreiche Alternativen vorschlagen."""

    def test_block_reason_mentions_clean(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "customers.csv"))
        reason = result.get("reason", "")
        assert ".clean" in reason

    def test_block_reason_mentions_mock_generator(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "customers.csv"))
        reason = result.get("reason", "")
        assert "generate_mock_data" in reason or "mock" in reason.lower()

    def test_block_reason_mentions_dsgvo(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "customers.csv"))
        reason = result.get("reason", "")
        assert "DSGVO" in reason

    def test_block_suggests_clean_path(self):
        result = run_hook(HOOK, make_read_input(TESTFILES_DIR / "customers.csv"))
        reason = result.get("reason", "")
        assert "customers.csv.clean" in reason

    def test_cert_block_has_specific_reason(self):
        """Zertifikats-Block hat eigene spezifische Meldung."""
        result = run_hook(HOOK, make_read_input("/tmp/server.pem"))
        reason = result.get("reason", "")
        assert len(reason) > 10, "Block-Meldung fuer Zertifikate sollte informativ sein"

    def test_auth_block_has_specific_reason(self):
        """Auth-Block hat eigene spezifische Meldung."""
        result = run_hook(HOOK, make_read_input("/tmp/auth.ps1"))
        reason = result.get("reason", "")
        assert len(reason) > 10, "Block-Meldung fuer Auth-Dateien sollte informativ sein"


# ─── EDGE CASES ───────────────────────────────────────


class TestEdgeCases:
    """Grenzfaelle und Sonderfaelle."""

    def test_empty_input(self):
        result = run_hook(HOOK, {})
        assert result.get("decision") != "block"

    def test_no_file_path(self):
        result = run_hook(HOOK, {"tool_name": "Read", "tool_input": {}})
        assert result.get("decision") != "block"

    def test_non_read_tool(self):
        result = run_hook(HOOK, {"tool_name": "Bash", "tool_input": {"command": "ls"}})
        assert result.get("decision") != "block"

    def test_deeply_nested_csv(self):
        result = run_hook(HOOK, make_read_input("/a/b/c/d/kunden.csv"))
        assert result.get("decision") == "block"

    def test_case_insensitive_extension(self):
        result = run_hook(HOOK, make_read_input("/tmp/DATA.CSV"))
        assert result.get("decision") == "block"

    def test_case_insensitive_pem(self):
        result = run_hook(HOOK, make_read_input("/tmp/CERT.PEM"))
        assert result.get("decision") == "block"

    def test_case_insensitive_key(self):
        result = run_hook(HOOK, make_read_input("/tmp/SERVER.KEY"))
        assert result.get("decision") == "block"

    def test_windows_path_csv(self):
        """Windows-Pfade werden korrekt erkannt."""
        result = run_hook(HOOK, make_read_input("C:\\Users\\Data\\export.csv"))
        assert result.get("decision") == "block"

    def test_windows_path_pem(self):
        result = run_hook(HOOK, make_read_input("C:\\certs\\server.pem"))
        assert result.get("decision") == "block"

    def test_dot_env_hidden(self):
        """.env ohne Erweiterung wird blockiert."""
        result = run_hook(HOOK, make_read_input("/project/.env"))
        assert result.get("decision") == "block"

    def test_multiple_extensions_clean_last(self):
        """Datei mit .csv.clean: .clean-Suffix hat Vorrang."""
        result = run_hook(HOOK, make_read_input("/tmp/data.csv.clean"))
        assert result.get("decision") != "block"

    def test_sqlite_db_blocked(self):
        """SQLite-Datenbanken blockiert (koennen PII enthalten)."""
        result = run_hook(HOOK, make_read_input("/tmp/users.db"))
        assert result.get("decision") == "block"

    def test_sqlite3_extension_blocked(self):
        result = run_hook(HOOK, make_read_input("/tmp/app.sqlite3"))
        assert result.get("decision") == "block"

    def test_sqlite_extension_blocked(self):
        result = run_hook(HOOK, make_read_input("/tmp/data.sqlite"))
        assert result.get("decision") == "block"
