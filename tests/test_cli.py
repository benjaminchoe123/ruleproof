"""The command line: exit codes first.

This tool's job is to fail a build. Everything else it prints is secondary to
returning non-zero at the right moments, so that is what these tests pin — an
exit code that is wrong in the lenient direction turns the whole project into
decoration.
"""

from ruleproof.cli import main
from tests.test_harness import RULE_YAML, SUITE_YAML


def build(tmp_path, suite=SUITE_YAML, rule=RULE_YAML, stem="net_user_add"):
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    (rules / f"{stem}.yml").write_text(rule, encoding="utf-8")
    if suite is not None:
        (rules / f"{stem}.test.yml").write_text(suite, encoding="utf-8")
    return rules


def test_exit_zero_when_all_rules_pass(tmp_path, capsys):
    assert main(["test", str(build(tmp_path))]) == 0
    assert "1 rule" in capsys.readouterr().out


def test_exit_nonzero_on_a_failing_rule(tmp_path, capsys):
    rules = build(tmp_path, rule=RULE_YAML.replace("' /add'", "' /addx'"))
    assert main(["test", str(rules)]) == 1
    assert "missed detection" in capsys.readouterr().out


def test_exit_nonzero_on_an_untested_rule(tmp_path, capsys):
    assert main(["test", str(build(tmp_path, suite=None))]) == 1
    assert "untested" in capsys.readouterr().out.lower()


def test_untested_rules_can_be_tolerated_explicitly(tmp_path):
    """Adopting Sigma's public rule set means thousands of untested rules on day
    one. The flag exists so the gate can be turned on before the backlog is
    cleared — but it has to be asked for, in writing, in the command."""
    rules = build(tmp_path, suite=None)
    assert main(["test", str(rules), "--allow-untested"]) == 0


def test_exit_nonzero_on_a_broken_rule_file(tmp_path, capsys):
    rules = build(tmp_path)
    (rules / "broken.yml").write_text("title: x\n", encoding="utf-8")
    assert main(["test", str(rules)]) == 1
    assert "broken.yml" in capsys.readouterr().out


def test_coverage_command_reports_the_gap(tmp_path, capsys):
    rules = build(tmp_path, suite=None)
    assert main(["coverage", str(rules)]) == 0
    out = capsys.readouterr().out
    assert "T1136.001" in out
    assert "0/1" in out or "0 of 1" in out


def test_missing_directory_is_an_error_not_a_pass(tmp_path, capsys):
    """An empty or mistyped path returning 0 would make the CI gate a no-op."""
    assert main(["test", str(tmp_path / "nope")]) == 2
    assert "not found" in capsys.readouterr().err.lower()


def test_empty_directory_is_an_error_not_a_pass(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["test", str(empty)]) == 2
    assert "no rules" in capsys.readouterr().err.lower()


def test_exit_nonzero_on_an_orphaned_test_file(tmp_path, capsys):
    """A test file whose rule no longer exists must not pass silently. It is the
    mirror of an untested rule, and arguably worse: the file sitting in the
    directory implies coverage that is not there."""
    rules = build(tmp_path)
    (rules / "deleted_rule.test.yml").write_text(
        (rules / "net_user_add.test.yml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    assert main(["test", str(rules)]) == 1
    assert "orphan" in capsys.readouterr().out.lower()


def test_allow_untested_does_not_also_tolerate_orphans(tmp_path):
    """Adopting a rule set explains untested rules. It does not explain a test
    file with no rule, which is always a mistake someone made."""
    rules = build(tmp_path)
    (rules / "deleted_rule.test.yml").write_text(
        (rules / "net_user_add.test.yml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    assert main(["test", str(rules), "--allow-untested"]) == 1
