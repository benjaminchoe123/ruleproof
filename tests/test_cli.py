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


def test_fail_under_message_never_reads_as_equal_to_the_threshold(tmp_path, capsys):
    """The headline percentage is rounded; the gate compares the real value. At
    32.5% against a floor of 33 that printed "FAIL: 33% ... below the required
    33%", which reads as a bug in the tool and gets the gate ignored rather than
    the coverage fixed."""
    rules = build(tmp_path)          # one rule, demonstrating T1136.001
    observed = tmp_path / "observed.txt"
    #: 1 of 3 detected = 33.3%, which rounds to 33 and must still fail a 34 floor.
    observed.write_text("T1136.001\nT1190\nT1071\n", encoding="utf-8")

    assert main(["gap", str(rules), str(observed), "--fail-under", "34"]) == 1
    fail_line = [ln for ln in capsys.readouterr().out.splitlines() if "FAIL" in ln][0]
    assert "34%" in fail_line
    assert "33.3%" in fail_line


# --- ruleproof negatives ---------------------------------------------------

def test_negatives_command_reports_an_unguarded_constraint(tmp_path, capsys):
    """A rule whose suite passes while leaving a condition unpinned. `test` says
    green because nothing fails; this says which constraint nothing is watching."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yml").write_text(
        "title: R\nlogsource: {product: windows}\ndetection:\n"
        "  sel_a:\n    A: '1'\n  sel_b:\n    B: '2'\n"
        "  condition: sel_a and sel_b\n", encoding="utf-8")
    # The only negative breaks sel_b, so nothing guards sel_a.
    (rules / "r.test.yml").write_text(
        "true_positives:\n  - name: fires\n    event: {A: '1', B: '2'}\n"
        "true_negatives:\n  - name: no b\n    event: {A: '1', B: 'x'}\n", encoding="utf-8")

    assert main(["negatives", str(rules)]) == 0      # a report, not a gate
    out = capsys.readouterr().out
    assert "sel_a" in out
    assert "sel_b" not in out.split("unguarded")[-1]


def test_negatives_strict_turns_the_report_into_a_gate(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yml").write_text(
        "title: R\nlogsource: {product: windows}\ndetection:\n"
        "  sel_a:\n    A: '1'\n  sel_b:\n    B: '2'\n"
        "  condition: sel_a and sel_b\n", encoding="utf-8")
    (rules / "r.test.yml").write_text(
        "true_positives:\n  - name: fires\n    event: {A: '1', B: '2'}\n"
        "true_negatives:\n  - name: no b\n    event: {A: '1', B: 'x'}\n", encoding="utf-8")
    assert main(["negatives", str(rules), "--strict"]) == 1


def test_negatives_is_clean_when_every_constraint_is_guarded(tmp_path, capsys):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yml").write_text(
        "title: R\nlogsource: {product: windows}\ndetection:\n"
        "  sel_a:\n    A: '1'\n  sel_b:\n    B: '2'\n"
        "  condition: sel_a and sel_b\n", encoding="utf-8")
    (rules / "r.test.yml").write_text(
        "true_positives:\n  - name: fires\n    event: {A: '1', B: '2'}\n"
        "true_negatives:\n"
        "  - name: no b\n    event: {A: '1', B: 'x'}\n"
        "  - name: no a\n    event: {A: 'x', B: '2'}\n", encoding="utf-8")
    assert main(["negatives", str(rules), "--strict"]) == 0
    assert "every constraint" in capsys.readouterr().out


def test_negatives_on_a_missing_directory_is_a_usage_error(tmp_path):
    assert main(["negatives", str(tmp_path / "nope")]) == 2


def test_two_rules_sharing_a_sigma_id_fail_the_build(tmp_path, capsys):
    """Both rules are individually valid and both pass their tests. The defect is
    only visible across the set: a SIEM keys on the id, so one silently replaces
    the other and never fires."""
    rules = build(tmp_path)
    original = (rules / "net_user_add.yml").read_text(encoding="utf-8")
    (rules / "copy_of_rule.yml").write_text(original, encoding="utf-8")
    (rules / "copy_of_rule.test.yml").write_text(
        (rules / "net_user_add.test.yml").read_text(encoding="utf-8"), encoding="utf-8")

    assert main(["test", str(rules)]) == 1
    out = capsys.readouterr().out
    assert "DUPLICATE ID" in out
    assert "never fires" in out


def test_allow_untested_does_not_excuse_a_duplicate_id(tmp_path):
    """Adopting somebody else's rule set explains rules without tests. It does
    not explain two rules claiming the same identity."""
    rules = build(tmp_path)
    original = (rules / "net_user_add.yml").read_text(encoding="utf-8")
    (rules / "copy_of_rule.yml").write_text(original, encoding="utf-8")
    (rules / "copy_of_rule.test.yml").write_text(
        (rules / "net_user_add.test.yml").read_text(encoding="utf-8"), encoding="utf-8")
    assert main(["test", str(rules), "--allow-untested"]) == 1
