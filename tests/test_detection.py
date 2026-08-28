"""Search identifiers and the `condition` expression.

Two layers sit above field matching:

  * a search identifier (`selection:`) is a map whose keys must ALL match, or a
    list of such maps of which ANY may match. The map-is-AND / list-is-OR
    asymmetry is the single most common source of an accidentally-wide rule.
  * `condition:` is a small boolean language over those identifiers, including
    the aggregate forms `1 of them`, `all of them`, and `1 of selection*`.

The `not filter` idiom is what makes a rule survive contact with production, so
it gets the most attention here.
"""

import pytest

from ruleproof.detection import ConditionError, Detection

PROC = {
    "EventID": 4688,
    "Image": r"C:\Windows\System32\net.exe",
    "CommandLine": "net user backdoor P@ssw0rd /add",
    "User": "CORP\\alice",
}


def det(**kw):
    return Detection.from_dict(kw)


# --- search identifiers ----------------------------------------------------


def test_map_keys_are_anded():
    d = det(selection={"EventID": 4688, "Image|endswith": r"\net.exe"}, condition="selection")
    assert d.matches(PROC)


def test_map_fails_when_any_key_fails():
    d = det(selection={"EventID": 4688, "Image|endswith": r"\nope.exe"}, condition="selection")
    assert not d.matches(PROC)


def test_list_of_maps_is_ored():
    d = det(
        selection=[{"Image|endswith": r"\nope.exe"}, {"Image|endswith": r"\net.exe"}],
        condition="selection",
    )
    assert d.matches(PROC)


def test_absent_field_does_not_match():
    d = det(selection={"NoSuchField": "x"}, condition="selection")
    assert not d.matches(PROC)


def test_null_matches_an_absent_field():
    d = det(selection={"NoSuchField": None}, condition="selection")
    assert d.matches(PROC)


# --- condition -------------------------------------------------------------


def test_and():
    d = det(a={"EventID": 4688}, b={"User|startswith": "CORP"}, condition="a and b")
    assert d.matches(PROC)


def test_or():
    d = det(a={"EventID": 9999}, b={"User|startswith": "CORP"}, condition="a or b")
    assert d.matches(PROC)


def test_not_excludes():
    """The filter idiom: match the behaviour, then subtract the known-good."""
    d = det(
        selection={"CommandLine|contains": "/add"},
        filter={"User|startswith": "CORP"},
        condition="selection and not filter",
    )
    assert not d.matches(PROC)


def test_not_leaves_non_matching_filter_alone():
    d = det(
        selection={"CommandLine|contains": "/add"},
        filter={"User|startswith": "SYSTEM"},
        condition="selection and not filter",
    )
    assert d.matches(PROC)


def test_parentheses_override_precedence():
    d = det(
        a={"EventID": 4688},
        b={"EventID": 9999},
        c={"EventID": 9998},
        condition="a and (b or c)",
    )
    assert not d.matches(PROC)


def test_and_binds_tighter_than_or():
    """`a or b and c` is `a or (b and c)`. If this were left-to-right the rule
    would mean something else entirely."""
    d = det(
        a={"EventID": 4688},
        b={"EventID": 9999},
        c={"EventID": 9998},
        condition="a or b and c",
    )
    assert d.matches(PROC)


# --- aggregates ------------------------------------------------------------


def test_one_of_them():
    d = det(a={"EventID": 9999}, b={"EventID": 4688}, condition="1 of them")
    assert d.matches(PROC)


def test_all_of_them():
    d = det(a={"EventID": 9999}, b={"EventID": 4688}, condition="all of them")
    assert not d.matches(PROC)


def test_one_of_prefix_wildcard():
    d = det(
        selection_net={"Image|endswith": r"\net.exe"},
        selection_ps={"Image|endswith": r"\powershell.exe"},
        other={"EventID": 9999},
        condition="1 of selection_*",
    )
    assert d.matches(PROC)


def test_all_of_prefix_wildcard_respects_the_prefix():
    """`other` must not be swept into `all of selection_*`."""
    d = det(
        selection_net={"Image|endswith": r"\net.exe"},
        selection_id={"EventID": 4688},
        other={"EventID": 9999},
        condition="all of selection_*",
    )
    assert d.matches(PROC)


def test_them_excludes_nothing_and_includes_every_identifier():
    d = det(a={"EventID": 4688}, b={"Image|endswith": r"\net.exe"}, condition="all of them")
    assert d.matches(PROC)


# --- errors ----------------------------------------------------------------


def test_unknown_identifier_is_an_error():
    with pytest.raises(ConditionError, match="unknown search identifier"):
        det(selection={"EventID": 4688}, condition="selection and nosuch").matches(PROC)


def test_malformed_condition_is_an_error():
    with pytest.raises(ConditionError):
        det(selection={"EventID": 4688}, condition="selection and").matches(PROC)


def test_missing_condition_is_an_error():
    with pytest.raises(ConditionError, match="condition"):
        Detection.from_dict({"selection": {"EventID": 4688}})


def test_unsupported_aggregate_is_an_error_not_a_silent_false():
    with pytest.raises(ConditionError):
        det(a={"EventID": 4688}, condition="2 of them").matches(PROC)


# --- defined but never referenced -------------------------------------------
# The condition language already refuses an identifier that is *used* without
# being defined. The reverse -- defined and never used -- was silently fine, and
# it is the more dangerous of the two: a `filter_` block that the condition
# forgets to mention reads exactly like protection and does nothing at all. This
# repo has already shipped two dead conditions by other mechanisms.

def test_a_search_identifier_never_used_by_the_condition_is_reported():
    detection = Detection.from_dict({
        "selection": {"A": "1"},
        "filter_forgotten": {"B": "2"},
        "condition": "selection",
    })
    assert detection.unused_identifiers() == ["filter_forgotten"]


def test_every_unused_identifier_is_named_not_just_the_first():
    detection = Detection.from_dict({
        "selection": {"A": "1"},
        "filter_a": {"B": "2"},
        "filter_b": {"C": "3"},
        "condition": "selection",
    })
    assert detection.unused_identifiers() == ["filter_a", "filter_b"]


def test_a_rule_using_everything_it_defines_reports_nothing():
    detection = Detection.from_dict({
        "selection": {"A": "1"},
        "filter_x": {"B": "2"},
        "condition": "selection and not filter_x",
    })
    assert detection.unused_identifiers() == []


def test_an_unused_block_still_loads_and_still_matches():
    """Reported, not raised. The rule works; it just carries dead weight, and
    refusing to load somebody else's working rule set is heavier than the defect
    warrants."""
    detection = Detection.from_dict({
        "selection": {"A": "1"},
        "filter_forgotten": {"B": "2"},
        "condition": "selection",
    })
    assert detection.matches({"A": "1"}) is True


def test_an_identifier_reached_only_through_a_wildcard_counts_as_used():
    """`1 of selection_*` uses them, even though no name appears literally."""
    detection = Detection.from_dict({
        "selection_a": {"A": "1"},
        "selection_b": {"B": "2"},
        "condition": "1 of selection_*",
    })
    assert detection.unused_identifiers() == []


def test_all_of_them_uses_everything():
    detection = Detection.from_dict({
        "selection": {"A": "1"},
        "other": {"B": "2"},
        "condition": "all of them",
    })
    assert detection.unused_identifiers() == []


def test_an_identifier_used_only_under_a_negation_counts_as_used():
    detection = Detection.from_dict({
        "selection": {"A": "1"},
        "filter_x": {"B": "2"},
        "condition": "selection and not filter_x",
    })
    assert detection.unused_identifiers() == []
