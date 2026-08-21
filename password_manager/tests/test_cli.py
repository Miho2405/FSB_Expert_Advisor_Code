"""End-to-end command line behaviour, driven through ``cli.main``."""

from __future__ import annotations

import io
import json
import os
import stat
import sys

import pytest
from conftest import TEST_MASTER

from pwman import cli
from pwman.session import default_vault_path

MASTER = TEST_MASTER.decode()
NEW_MASTER = "ocean-candle-forest-marble-eight"


@pytest.fixture
def run(vault_path, monkeypatch, capsys):
    """Run pwman with a temp vault; extra stdin lines feed prompts."""

    def _run(*argv: str, stdin: list[str] | None = None, master: str = MASTER, vault: str | None = None):
        lines = ([master] if master is not None else []) + list(stdin or [])
        monkeypatch.setattr(sys, "stdin", io.StringIO("".join(line + "\n" for line in lines)))
        base = ["--vault", vault or vault_path, "--no-color"]
        if master is not None:
            base.append("--password-stdin")
        code = cli.main(base + list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return _run


@pytest.fixture
def vault(run, vault_path):
    """An initialised vault with one generated and one known entry."""
    assert run("init")[0] == cli.OK
    assert run("add", "github", "-u", "me@example.com", "--url", "https://github.com",
               "--tags", "dev", "--generate", "--show")[0] == cli.OK
    assert run("add", "bank", "-u", "12345", "--secret-stdin", stdin=["hunter2"])[0] == cli.OK
    return vault_path


# --------------------------------------------------------------------------- #
# init / info
# --------------------------------------------------------------------------- #

def test_init_creates_a_private_vault(run, vault_path):
    code, out, _ = run("init")
    assert code == cli.OK
    assert os.path.exists(vault_path)
    assert stat.S_IMODE(os.stat(vault_path).st_mode) == 0o600
    assert "AES-256-GCM" in out


def test_init_refuses_to_overwrite(run, vault_path):
    run("init")
    code, _, err = run("init")
    assert code == cli.ERROR
    assert "already exists" in err


def test_init_warns_about_a_weak_master_password(run):
    code, _, err = run("init", master="hunter2")
    assert code == cli.OK  # non-interactive: warn, do not block
    assert "very weak" in err


def test_info_reports_the_real_parameters(run, vault):
    code, out, _ = run("info", "--json")
    assert code == cli.OK
    info = json.loads(out)
    assert info["entries"] == 2
    assert info["cipher"] == "AES-256-GCM"
    assert info["mode"] == "0600"


# --------------------------------------------------------------------------- #
# entries
# --------------------------------------------------------------------------- #

def test_add_and_read_back_a_password(run, vault):
    code, out, _ = run("get", "bank", "--show")
    assert code == cli.OK
    assert out.strip() == "hunter2"


def test_stored_password_is_not_in_the_file(run, vault, vault_path):
    with open(vault_path, "rb") as handle:
        blob = handle.read()
    assert b"hunter2" not in blob
    assert b"me@example.com" not in blob
    assert b"github" not in blob.lower().replace(b"pwmanvlt", b"")


def test_add_does_not_print_the_password_unless_asked(run, vault):
    code, out, _ = run("add", "quiet-entry", "--secret-stdin", stdin=["s3cr3t-not-printed"])
    assert code == cli.OK
    assert "s3cr3t-not-printed" not in out


def test_add_rejects_a_duplicate_name(run, vault):
    code, _, err = run("add", "GitHub", "--generate")
    assert code == cli.ERROR
    assert "already exists" in err


def test_list_and_search(run, vault):
    code, out, _ = run("list")
    assert code == cli.OK
    assert "github" in out and "bank" in out

    code, out, _ = run("search", "12345")
    assert "bank" in out and "github" not in out

    code, out, _ = run("list", "--tag", "dev")
    assert "github" in out and "bank" not in out


def test_list_json_redacts_secrets(run, vault):
    code, out, _ = run("list", "--json")
    assert code == cli.OK
    entries = json.loads(out)
    assert {e["name"] for e in entries} == {"github", "bank"}
    assert all(e["password"] == "***" for e in entries)
    assert "hunter2" not in out


def test_edit_replaces_the_password_and_keeps_history(run, vault):
    before, _, _ = run("get", "bank", "--show")
    code, out, _ = run("edit", "bank", "--generate", "--show")
    assert code == cli.OK
    after = out.strip().splitlines()[-1]
    assert after != "hunter2"

    code, out, _ = run("get", "bank", "--show")
    assert out.strip() == after

    code, out, _ = run("list", "--json")
    entry = next(e for e in json.loads(out) if e["name"] == "bank")
    assert len(entry["history"]) == 1


def test_edit_without_changes_is_a_usage_error(run, vault):
    code, _, err = run("edit", "bank")
    assert code == cli.USAGE
    assert "nothing to change" in err


def test_rename_and_delete(run, vault):
    assert run("edit", "bank", "--rename", "savings")[0] == cli.OK
    assert run("rm", "savings", "--force")[0] == cli.OK
    code, out, _ = run("list")
    assert "savings" not in out


def test_unknown_and_ambiguous_lookups_fail_cleanly(run, vault):
    assert run("get", "nope", "--show")[0] == cli.ERROR

    run("add", "github-work", "--generate", "--show")
    code, _, err = run("get", "git", "--show")   # matches github and github-work
    assert code == cli.ERROR
    assert "matches 2 entries" in err
    assert run("get", "github", "--show")[0] == cli.OK  # an exact name still wins


def test_totp_round_trip(run, vault):
    assert run("edit", "github", "--totp", "otpauth://totp/gh?secret=JBSWY3DPEHPK3PXP")[0] == cli.OK
    code, out, _ = run("get", "github", "-f", "totp", "--show")
    assert code == cli.OK
    assert out.strip().splitlines()[0].isdigit()
    assert len(out.strip().splitlines()[0]) == 6


# --------------------------------------------------------------------------- #
# authentication
# --------------------------------------------------------------------------- #

def test_wrong_master_password_is_its_own_exit_code(run, vault):
    code, _, err = run("list", master="definitely-not-the-master")
    assert code == cli.AUTH
    assert "wrong master password" in err


def test_master_password_rotation(run, vault):
    code, _, _ = run("passwd", stdin=[NEW_MASTER])
    assert code == cli.OK
    assert run("list", master=MASTER)[0] == cli.AUTH
    assert run("list", master=NEW_MASTER)[0] == cli.OK


def test_a_missing_vault_is_reported_not_created(run, tmp_path):
    missing = str(tmp_path / "nothing.pmv")
    code, _, err = run("list", vault=missing)
    assert code == cli.ERROR
    assert "no vault" in err
    assert not os.path.exists(missing)


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #

def test_audit_reports_problems_with_a_distinct_exit_code(run, vault):
    code, out, _ = run("audit")
    assert code == cli.FINDINGS
    assert "bank" in out and "weak" in out


def test_audit_is_clean_after_fixing_the_entries(run, vault):
    run("edit", "bank", "--generate", "-l", "24")
    code, out, _ = run("audit")
    assert code == cli.OK
    assert "no issues" in out


def test_audit_json_lists_findings(run, vault):
    code, out, _ = run("audit", "--json")
    assert code == cli.FINDINGS
    findings = json.loads(out)
    assert {f["kind"] for f in findings} >= {"weak"}


# --------------------------------------------------------------------------- #
# generate / export / import
# --------------------------------------------------------------------------- #

def test_gen_needs_no_vault_and_no_master_password(run, tmp_path):
    code, out, _ = run("gen", "-n", "3", "-l", "16", master=None, vault=str(tmp_path / "absent.pmv"))
    assert code == cli.OK
    values = [line for line in out.splitlines() if line and "entropy" not in line]
    assert len(values) == 3
    assert all(len(v) == 16 for v in values)
    assert len(set(values)) == 3


def test_gen_passphrase_mode(run):
    code, out, _ = run("gen", "--passphrase", "-w", "5", master=None)
    assert code == cli.OK
    assert len(out.splitlines()[0].split("-")) == 5
    assert "50 bits" in out


def test_export_requires_an_explicit_confirmation(run, vault, tmp_path):
    target = str(tmp_path / "export.json")
    code, _, err = run("export", target)
    assert code == cli.USAGE
    assert not os.path.exists(target)
    assert "clear text" in err


def test_export_then_import_round_trip(run, vault, tmp_path, vault_path):
    target = str(tmp_path / "export.json")
    assert run("export", target, "--insecure-plaintext")[0] == cli.OK
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert "hunter2" in open(target).read()

    second = str(tmp_path / "second.pmv")
    assert run("init", vault=second)[0] == cli.OK
    assert run("import", target, vault=second)[0] == cli.OK
    code, out, _ = run("get", "bank", "--show", vault=second)
    assert out.strip() == "hunter2"


def test_import_csv_and_dry_run(run, vault, tmp_path):
    csv_path = tmp_path / "browser.csv"
    csv_path.write_text("name,url,username,password\nmail,https://mail.example,me,pw-from-csv\n")

    code, out, _ = run("import", str(csv_path), "--dry-run")
    assert "would import 1" in out
    assert run("get", "mail", "--show")[0] == cli.ERROR  # dry run changed nothing

    assert run("import", str(csv_path))[0] == cli.OK
    code, out, _ = run("get", "mail", "--show")
    assert out.strip() == "pw-from-csv"


def test_import_skips_duplicates_unless_replacing(run, vault, tmp_path):
    csv_path = tmp_path / "dup.csv"
    csv_path.write_text("name,username,password\nbank,other,replaced-password\n")
    code, out, _ = run("import", str(csv_path))
    assert "0 entries (1 skipped)" in out
    assert run("get", "bank", "--show")[1].strip() == "hunter2"

    assert run("import", str(csv_path), "--replace")[0] == cli.OK
    assert run("get", "bank", "--show")[1].strip() == "replaced-password"


# --------------------------------------------------------------------------- #
# interface invariants
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("argv", [
    ["add", "x", "--password", "secret-on-the-command-line"],
    ["add", "x", "-p", "secret-on-the-command-line"],
    ["get", "x", "--master-password", "secret"],
    ["init", "--password", "secret"],
])
def test_no_command_accepts_a_secret_as_an_argument(argv):
    """argv is world-readable on Linux and ends up in the shell history."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(argv)


def test_default_vault_path_follows_xdg(monkeypatch):
    monkeypatch.delenv("PWMAN_VAULT", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", "/tmp/xdg")
    assert default_vault_path() == "/tmp/xdg/pwman/vault.pmv"
    monkeypatch.setenv("PWMAN_VAULT", "~/custom.pmv")
    assert default_vault_path().endswith("custom.pmv")


def test_version_flag_exits_cleanly():
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0


def test_import_rejects_a_file_that_is_not_an_export(run, vault, tmp_path):
    junk = tmp_path / "junk.json"
    junk.write_text('{"not": "an export"}')
    code, _, err = run("import", str(junk))
    assert code == cli.ERROR
    assert "not a JSON export" in err
