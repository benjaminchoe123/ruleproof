"""How much work is a true_negative actually doing?

`ruleproof test` proves a rule stays silent on its negatives. It cannot tell a
negative that nearly fired from one that shares nothing with the rule at all. A
suite of unrelated negatives passes exactly as green as a suite of sharp ones,
which is the same shape as the untested-rule problem this project was built on:
the result looks identical whether the check is doing work or not.

The measure here is **distance to firing** -- how many of the rule's search
identifiers would have to flip before it fires. Distance 1 means the negative
breaks exactly one condition, so it is the case that would catch that condition
being loosened. A larger distance means the negative is not guarding anything in
particular.

Distance is computed over the parsed condition, not over a count of matched
identifiers, because a filter inverts the arithmetic: an event caught only by
`not filter_x` matches *every* identifier and still does not fire. Counting
matches would score that strong negative as the weakest kind.
"""

import pytest

from ruleproof.discrimination import (
    distance_to_firing,
    unguarded_constraints,
    weakest_negatives,
)
from ruleproof.harness import TestSuite
from ruleproof.rule import Rule

TWO_CONDITION = r"""
title: Two conditions
logsource: {product: windows}
detection:
  selection_tool:
    Image|endswith: '\certutil.exe'
  selection_url:
    CommandLine|contains: 'http://'
  condition: selection_tool and selection_url
"""

FILTERED = r"""
title: Filtered
logsource: {product: windows}
detection:
  selection:
    Image|endswith: '\wscript.exe'
  filter_signed:
    CommandLine|contains: 'NETLOGON'
  condition: selection and not filter_signed
"""


def rule(text):
    return Rule.from_yaml(text)


def test_a_negative_breaking_one_condition_is_distance_one():
    r = rule(TWO_CONDITION)
    event = {"Image": r"C:\W\certutil.exe", "CommandLine": "certutil -dump local.cer"}
    assert distance_to_firing(r.detection, event) == 1


def test_a_negative_sharing_nothing_with_the_rule_is_further_away():
    r = rule(TWO_CONDITION)
    event = {"Image": r"C:\W\notepad.exe", "CommandLine": "notepad budget.txt"}
    assert distance_to_firing(r.detection, event) == 2


def test_an_event_that_fires_is_distance_zero():
    r = rule(TWO_CONDITION)
    event = {"Image": r"C:\W\certutil.exe", "CommandLine": "certutil -f http://x/a"}
    assert distance_to_firing(r.detection, event) == 0


def test_a_negative_excluded_only_by_a_filter_is_distance_one():
    """The case counting matched identifiers gets backwards. This event matches
    every identifier in the rule and is stopped solely by the filter, which makes
    it the sharpest possible negative -- not the bluntest."""
    r = rule(FILTERED)
    event = {"Image": r"C:\W\wscript.exe", "CommandLine": "wscript //NETLOGON/map.vbs"}
    assert distance_to_firing(r.detection, event) == 1


def test_distance_is_capped_rather_than_searched_exhaustively():
    """A rule with many identifiers would otherwise cost 2^n to score."""
    r = rule(TWO_CONDITION)
    event = {}
    assert distance_to_firing(r.detection, event, max_distance=1) == 2


def test_weakest_negatives_names_the_cases_that_guard_nothing():
    r = rule(TWO_CONDITION)
    suite = TestSuite(
        true_positives=[],
        true_negatives=[
            type("C", (), {"name": "sharp", "event": {
                "Image": r"C:\W\certutil.exe", "CommandLine": "certutil -dump x.cer"}})(),
            type("C", (), {"name": "unrelated", "event": {
                "Image": r"C:\W\notepad.exe", "CommandLine": "notepad x"}})(),
        ],
    )
    weak = weakest_negatives(r.detection, suite.true_negatives)
    assert [name for name, _ in weak] == ["unrelated"]


def test_a_rule_whose_every_negative_is_sharp_reports_none_weak():
    r = rule(TWO_CONDITION)
    cases = [type("C", (), {"name": "a", "event": {
        "Image": r"C:\W\certutil.exe", "CommandLine": "certutil -dump x.cer"}})()]
    assert weakest_negatives(r.detection, cases) == []


@pytest.mark.parametrize("condition", ["selection_tool or selection_url",
                                       "1 of selection_*",
                                       "all of them"])
def test_every_condition_shape_can_be_scored(condition):
    text = TWO_CONDITION.replace("condition: selection_tool and selection_url",
                                 f"condition: {condition}")
    r = rule(text)
    assert distance_to_firing(r.detection, {}) >= 1


# --- which constraints does the suite actually guard? ----------------------
# The sharper question than "is this negative weak". A rule can have five sharp
# negatives that all guard the same condition, leaving another completely
# unpinned -- which is precisely how a mutation survived on 2026-08-26.

def _case(name, event):
    return type("C", (), {"name": name, "event": event})()


def test_a_constraint_with_a_distance_one_negative_is_guarded():
    r = rule(TWO_CONDITION)
    cases = [_case("no url", {"Image": r"C:\W\certutil.exe",
                              "CommandLine": "certutil -dump x.cer"})]
    assert "selection_url" not in unguarded_constraints(r.detection, cases)


def test_a_constraint_no_negative_pins_is_reported():
    """Only selection_url is guarded here; loosening selection_tool would fail
    nothing, which is the bug this catches."""
    r = rule(TWO_CONDITION)
    cases = [_case("no url", {"Image": r"C:\W\certutil.exe",
                              "CommandLine": "certutil -dump x.cer"})]
    assert unguarded_constraints(r.detection, cases) == ["selection_tool"]


def test_both_constraints_guarded_reports_nothing():
    r = rule(TWO_CONDITION)
    cases = [
        _case("no url", {"Image": r"C:\W\certutil.exe",
                         "CommandLine": "certutil -dump x.cer"}),
        _case("not the tool", {"Image": r"C:\W\curl.exe",
                               "CommandLine": "curl http://x/a"}),
    ]
    assert unguarded_constraints(r.detection, cases) == []


def test_a_filter_counts_as_a_constraint_needing_a_guard():
    """An exclusion nothing tests is an exclusion that exists only in the
    author's intention."""
    r = rule(FILTERED)
    assert "filter_signed" in unguarded_constraints(r.detection, [])


def test_no_negatives_at_all_leaves_everything_unguarded():
    r = rule(TWO_CONDITION)
    assert sorted(unguarded_constraints(r.detection, [])) == [
        "selection_tool", "selection_url"]
