"""Loading a Sigma rule file.

Validation here is deliberately strict and happens at load time. A rule
directory is the kind of place where a file with a typo'd key sits for months
looking like coverage, so anything this tool cannot fully evaluate is refused
loudly rather than loaded partially.
"""

import pytest

from ruleproof.rule import Rule, RuleError

MINIMAL = """
title: Local Account Created via net.exe
id: 8f1a2b3c-0000-4000-8000-000000000001
status: experimental
description: Detects local account creation using net.exe.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
    Image|endswith: '\\net.exe'
    CommandLine|contains|all:
      - ' user '
      - ' /add'
  condition: selection
level: medium
tags:
  - attack.persistence
  - attack.t1136.001
falsepositives:
  - Legitimate administrator activity
"""

EVENT = {
    "EventID": 4688,
    "Image": r"C:\Windows\System32\net.exe",
    "CommandLine": "net user backdoor P@ssw0rd /add",
}


def test_loads_metadata():
    r = Rule.from_yaml(MINIMAL)
    assert r.title == "Local Account Created via net.exe"
    assert r.id == "8f1a2b3c-0000-4000-8000-000000000001"
    assert r.level == "medium"
    assert r.status == "experimental"


def test_rule_matches_a_true_positive():
    assert Rule.from_yaml(MINIMAL).matches(EVENT)


def test_rule_rejects_a_near_miss():
    """Same binary, no /add — the discriminating token is the point of the rule."""
    assert not Rule.from_yaml(MINIMAL).matches({**EVENT, "CommandLine": "net user"})


def test_attack_techniques_are_extracted_from_tags():
    assert Rule.from_yaml(MINIMAL).techniques == ["T1136.001"]


def test_attack_tactics_are_extracted_separately_from_techniques():
    r = Rule.from_yaml(MINIMAL)
    assert r.tactics == ["persistence"]
    assert "persistence" not in r.techniques


def test_technique_ids_are_uppercased_for_attack_matching():
    """Sigma writes `attack.t1059.001`; ATT&CK and every navigator layer use
    `T1059.001`. Comparing the two without normalising silently reports zero
    coverage for every rule."""
    r = Rule.from_yaml(MINIMAL.replace("attack.t1136.001", "attack.t1059.001"))
    assert r.techniques == ["T1059.001"]


def test_logsource_is_available_for_routing():
    r = Rule.from_yaml(MINIMAL)
    assert r.logsource == {"product": "windows", "category": "process_creation"}


# --- validation ------------------------------------------------------------


def test_missing_title_is_refused():
    with pytest.raises(RuleError, match="title"):
        Rule.from_yaml(MINIMAL.replace("title: Local Account Created via net.exe", ""))


def test_missing_detection_is_refused():
    with pytest.raises(RuleError, match="detection"):
        Rule.from_yaml("title: x\nlogsource:\n  product: windows\n")


def test_unsupported_modifier_is_refused_at_load_time():
    """Not at match time. A rule using a modifier this tool cannot evaluate must
    never be loadable, or it will sit in the directory reporting clean."""
    with pytest.raises(RuleError, match="modifier"):
        Rule.from_yaml(MINIMAL.replace("CommandLine|contains|all", "CommandLine|base64offset"))


def test_broken_condition_is_refused_at_load_time():
    with pytest.raises(RuleError):
        Rule.from_yaml(MINIMAL.replace("condition: selection", "condition: selection and"))


def test_invalid_yaml_is_refused():
    with pytest.raises(RuleError, match="YAML"):
        Rule.from_yaml("title: [unclosed\n")


def test_file_path_is_reported_in_errors(tmp_path):
    """A stack trace that does not name the offending file is useless when the
    rule directory has hundreds of them."""
    bad = tmp_path / "broken.yml"
    bad.write_text("title: x\n", encoding="utf-8")
    with pytest.raises(RuleError, match="broken.yml"):
        Rule.from_file(bad)


def test_multi_document_yaml_is_refused_with_a_clear_message():
    """Sigma allows multi-document rule collections. This tool does not yet, and
    says so rather than silently evaluating only the first document."""
    with pytest.raises(RuleError, match="multi-document"):
        Rule.from_yaml(MINIMAL + "\n---\ntitle: second\n")
