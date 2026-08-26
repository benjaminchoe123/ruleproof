"""The harness: run a rule against its test cases and report what broke.

The two failure modes are not symmetric and the report must never blur them:

  * a `true_positives` case that does NOT match is a **missed detection** — the
    rule would not have fired on the thing it was written for.
  * a `true_negatives` case that DOES match is a **false positive** — the rule
    fires on benign activity, which is how a rule gets disabled in production
    and stops protecting anything at all.

A third state matters just as much and is the reason this tool exists: a rule
with no test file at all is **untested**, and untested is reported as its own
category rather than being quietly counted as passing.
"""

import pytest

from ruleproof.harness import HarnessError, TestSuite, discover, run_all, run_suite
from ruleproof.rule import Rule

RULE_YAML = """
title: Local Account Created via net.exe
id: 8f1a2b3c-0000-4000-8000-000000000001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
    Image|endswith: '\\net.exe'
    CommandLine|contains|all: [' user ', ' /add']
  condition: selection
level: medium
tags: [attack.persistence, attack.t1136.001]
"""

SUITE_YAML = """
true_positives:
  - name: backdoor account added
    event:
      EventID: 4688
      Image: 'C:\\Windows\\System32\\net.exe'
      CommandLine: 'net user backdoor P@ssw0rd /add'
true_negatives:
  - name: listing accounts only
    event:
      EventID: 4688
      Image: 'C:\\Windows\\System32\\net.exe'
      CommandLine: 'net user'
"""


def write_pair(tmp_path, rule_yaml=RULE_YAML, suite_yaml=SUITE_YAML, stem="net_user_add"):
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    (rules / f"{stem}.yml").write_text(rule_yaml, encoding="utf-8")
    if suite_yaml is not None:
        (rules / f"{stem}.test.yml").write_text(suite_yaml, encoding="utf-8")
    return rules


# --- suite loading ---------------------------------------------------------


def test_loads_positive_and_negative_cases():
    suite = TestSuite.from_yaml(SUITE_YAML)
    assert [c.name for c in suite.true_positives] == ["backdoor account added"]
    assert [c.name for c in suite.true_negatives] == ["listing accounts only"]


def test_a_suite_with_no_cases_is_refused():
    """An empty test file is indistinguishable from forgetting to write one,
    except that it looks deliberate. Refuse it."""
    with pytest.raises(HarnessError, match="no test cases"):
        TestSuite.from_yaml("true_positives: []\ntrue_negatives: []\n")


def test_case_without_an_event_is_refused():
    with pytest.raises(HarnessError, match="event"):
        TestSuite.from_yaml("true_positives:\n  - name: x\n")


# --- running ---------------------------------------------------------------


def test_all_cases_passing():
    result = run_suite(Rule.from_yaml(RULE_YAML), TestSuite.from_yaml(SUITE_YAML))
    assert result.passed
    assert result.total == 2
    assert result.failures == []


def test_missed_detection_is_reported_as_such():
    """Rule tightened to require an /add that the positive case does not have."""
    weakened = RULE_YAML.replace("' /add'", "' /addx'")
    result = run_suite(Rule.from_yaml(weakened), TestSuite.from_yaml(SUITE_YAML))
    assert not result.passed
    assert len(result.failures) == 1
    failure = result.failures[0]
    assert failure.kind == "missed detection"
    assert failure.case.name == "backdoor account added"


def test_false_positive_is_reported_as_such():
    """Rule loosened until the benign 'net user' case also fires."""
    loosened = RULE_YAML.replace("CommandLine|contains|all: [' user ', ' /add']", "")
    result = run_suite(Rule.from_yaml(loosened), TestSuite.from_yaml(SUITE_YAML))
    assert not result.passed
    assert [f.kind for f in result.failures] == ["false positive"]
    assert result.failures[0].case.name == "listing accounts only"


def test_both_failure_kinds_can_appear_together():
    inverted = RULE_YAML.replace("EventID: 4688", "EventID: 9999")
    result = run_suite(Rule.from_yaml(inverted), TestSuite.from_yaml(SUITE_YAML))
    # positive no longer fires (missed), negative still does not fire (fine)
    assert [f.kind for f in result.failures] == ["missed detection"]


# --- discovery -------------------------------------------------------------


def test_discovers_rule_and_its_test_file(tmp_path):
    rules = write_pair(tmp_path)
    found = discover(rules)
    assert len(found) == 1
    assert found[0].rule_path.name == "net_user_add.yml"
    assert found[0].test_path.name == "net_user_add.test.yml"


def test_test_files_are_not_themselves_loaded_as_rules(tmp_path):
    """`*.test.yml` sits alongside `*.yml`; a naive glob loads it as a rule and
    then reports it as broken."""
    rules = write_pair(tmp_path)
    assert [p.rule_path.name for p in discover(rules)] == ["net_user_add.yml"]


def test_a_rule_without_tests_is_discovered_with_no_test_path(tmp_path):
    rules = write_pair(tmp_path, suite_yaml=None)
    assert discover(rules)[0].test_path is None


def test_discovery_recurses_into_subdirectories(tmp_path):
    rules = write_pair(tmp_path)
    nested = rules / "windows" / "deep"
    nested.mkdir(parents=True)
    (nested / "other.yml").write_text(RULE_YAML, encoding="utf-8")
    assert len(discover(rules)) == 2


# --- whole-directory report ------------------------------------------------


def test_report_counts_untested_rules_separately(tmp_path):
    rules = write_pair(tmp_path)
    (rules / "untested.yml").write_text(RULE_YAML, encoding="utf-8")
    report = run_all(rules)
    assert report.tested == 1
    assert len(report.untested) == 1
    assert report.untested[0].name == "untested.yml"


def test_report_is_not_ok_when_rules_are_untested(tmp_path):
    """Untested rules must not report a green run. That silence is the exact
    thing this tool is built to remove."""
    rules = write_pair(tmp_path, suite_yaml=None)
    assert not run_all(rules).ok


def test_report_is_ok_when_everything_is_tested_and_passing(tmp_path):
    assert run_all(write_pair(tmp_path)).ok


def test_a_broken_rule_file_is_reported_not_raised(tmp_path):
    """One unparseable rule must not abort the run for every other rule."""
    rules = write_pair(tmp_path)
    (rules / "broken.yml").write_text("title: x\n", encoding="utf-8")
    report = run_all(rules)
    assert len(report.load_errors) == 1
    assert "broken.yml" in str(report.load_errors[0])
    assert not report.ok


def test_attack_coverage_lists_techniques_with_passing_tests(tmp_path):
    report = run_all(write_pair(tmp_path))
    assert report.covered_techniques == {"T1136.001"}


def test_a_technique_is_not_covered_if_its_only_rule_is_untested(tmp_path):
    """Coverage means 'a rule that is demonstrated to work', not 'a file exists'."""
    report = run_all(write_pair(tmp_path, suite_yaml=None))
    assert report.covered_techniques == set()
    assert report.claimed_techniques == {"T1136.001"}
