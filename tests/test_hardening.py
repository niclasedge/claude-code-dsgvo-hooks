"""
Tests fuer Hook-Haertung (Vektoren 5, 6, 8, 12)
=================================================
Symlink-Aufloesung, Fail-Closed, Interpreter-Bypass, Env-Dump.
"""
from __future__ import annotations

from tests.helpers import run_hook, make_read_input, make_bash_input


# ─── Vektor 5: Symlink-Aufloesung ────────────────────────

class TestSymlinkResolution:
    """Symlinks muessen aufgeloest werden bevor Extension geprueft wird."""

    def test_symlink_to_csv_is_blocked(self, tmp_path):
        """Symlink safe.py -> customers.csv muss blockiert werden."""
        csv_file = tmp_path / "customers.csv"
        csv_file.write_text("Name,Email\n")
        symlink = tmp_path / "safe.py"
        symlink.symlink_to(csv_file)
        result = run_hook("dsgvo-pii-file-guard.py", make_read_input(str(symlink)))
        assert result.get("decision") == "block"

    def test_symlink_to_pem_is_blocked(self, tmp_path):
        """Symlink config.txt -> server.pem muss blockiert werden."""
        pem_file = tmp_path / "server.pem"
        pem_file.write_text("cert\n")
        symlink = tmp_path / "config.txt"
        symlink.symlink_to(pem_file)
        result = run_hook("dsgvo-pii-file-guard.py", make_read_input(str(symlink)))
        assert result.get("decision") == "block"

    def test_symlink_to_env_is_blocked(self, tmp_path):
        """Symlink notes.md -> .env muss blockiert werden."""
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=abc\n")
        symlink = tmp_path / "notes.md"
        symlink.symlink_to(env_file)
        result = run_hook("dsgvo-pii-file-guard.py", make_read_input(str(symlink)))
        assert result.get("decision") == "block"

    def test_symlink_to_safe_file_allowed(self, tmp_path):
        """Symlink link.py -> real.py muss erlaubt werden."""
        py_file = tmp_path / "real.py"
        py_file.write_text("print('hello')\n")
        symlink = tmp_path / "link.py"
        symlink.symlink_to(py_file)
        result = run_hook("dsgvo-pii-file-guard.py", make_read_input(str(symlink)))
        assert result.get("decision") == "allow"


# ─── Vektor 6: Fail-Closed ───────────────────────────────

class TestFailClosed:
    """Hooks muessen bei Fehler blockieren statt erlauben."""

    def test_file_guard_malformed_tool_input(self):
        """File-Guard mit tool_input=None muss blockieren."""
        result = run_hook("dsgvo-pii-file-guard.py", {
            "tool_name": "Read",
            "tool_input": "not_a_dict",
        })
        assert result.get("decision") == "block"

    def test_prompt_guard_non_string_prompt(self):
        """Prompt-Guard mit prompt=123 muss blockieren."""
        result = run_hook("dsgvo-prompt-guard.py", {"prompt": 12345})
        assert result.get("decision") == "block"


# ─── Vektor 8: Interpreter-Bypass ────────────────────────

class TestInterpreterBypass:
    """Interpreter-Wrapping mit Dateizugriff muss erkannt werden."""

    def test_python_c_open_csv(self):
        result = run_hook("pre-tool-safety.py",
            make_bash_input('python3 -c "open(\'secret.csv\').read()"'))
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_python_c_import_csv(self):
        result = run_hook("pre-tool-safety.py",
            make_bash_input('python3 -c "import csv; r=csv.reader(open(\'d.csv\'))"'))
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_node_e_readfile(self):
        result = run_hook("pre-tool-safety.py",
            make_bash_input("node -e \"require('fs').readFileSync('data.csv')\""))
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_bash_c_cat_csv(self):
        result = run_hook("pre-tool-safety.py",
            make_bash_input("bash -c 'cat customers.csv'"))
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_safe_python_c_allowed(self):
        """python3 -c ohne Dateizugriff muss erlaubt sein."""
        result = run_hook("pre-tool-safety.py",
            make_bash_input('python3 -c "print(1+1)"'))
        assert result == {} or "hookSpecificOutput" not in result

    def test_safe_node_e_allowed(self):
        """node -e ohne Dateizugriff muss erlaubt sein."""
        result = run_hook("pre-tool-safety.py",
            make_bash_input('node -e "console.log(42)"'))
        assert result == {} or "hookSpecificOutput" not in result


# ─── Vektor 12: Env-Dump blockieren ──────────────────────

class TestEnvDumpBlocked:
    """env/printenv/set muessen blockiert werden."""

    def test_env_alone(self):
        result = run_hook("pre-tool-safety.py", make_bash_input("env"))
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_printenv_alone(self):
        result = run_hook("pre-tool-safety.py", make_bash_input("printenv"))
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_env_pipe_grep(self):
        result = run_hook("pre-tool-safety.py", make_bash_input("env | grep KEY"))
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_export_p(self):
        result = run_hook("pre-tool-safety.py", make_bash_input("export -p"))
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_set_without_args(self):
        result = run_hook("pre-tool-safety.py", make_bash_input("set"))
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_set_e_allowed(self):
        """set -e ist Shell-Option, kein Env-Dump."""
        result = run_hook("pre-tool-safety.py", make_bash_input("set -e"))
        assert result == {} or "hookSpecificOutput" not in result

    def test_printenv_specific_var_allowed(self):
        """printenv HOME ist spezifisch, kein Dump."""
        result = run_hook("pre-tool-safety.py", make_bash_input("printenv HOME"))
        assert result == {} or "hookSpecificOutput" not in result

    def test_cat_bashrc_blocked(self):
        result = run_hook("pre-tool-safety.py", make_bash_input("cat ~/.bashrc"))
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_cat_zshrc_blocked(self):
        result = run_hook("pre-tool-safety.py", make_bash_input("cat ~/.zshrc"))
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
