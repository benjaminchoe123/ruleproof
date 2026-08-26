"""Field matching: the layer that decides whether one event field satisfies one
Sigma condition.

Sigma's value semantics are deceptively fiddly and every one of these rules is a
place a hand-rolled matcher usually gets wrong:

  * a bare string compares case-insensitively, but `|re` does not unless told to
  * `*` is a wildcard in plain values, and NOT a wildcard inside `|re`
  * a list of values is an OR, unless `|all` flips it to an AND
  * `null` matches a field that is absent *or* explicitly null
  * a missing field never matches anything except `null`

Each test below pins one of those.
"""

import pytest

from ruleproof.matching import MISSING, field_matches

# --- plain equality --------------------------------------------------------


def test_exact_string_match():
    assert field_matches("whoami.exe", "whoami.exe", [])


def test_string_match_is_case_insensitive():
    """Sigma compares strings case-insensitively by default; Windows paths and
    process names arrive in whatever case the source logged them."""
    assert field_matches("WhoAmI.EXE", "whoami.exe", [])


def test_non_matching_string():
    assert not field_matches("cmd.exe", "whoami.exe", [])


def test_integer_match():
    assert field_matches(4688, 4688, [])


def test_integer_matches_its_string_form():
    """EventID arrives as an int from EVTX and a string from JSON exports."""
    assert field_matches("4688", 4688, [])


# --- wildcards -------------------------------------------------------------


def test_star_matches_any_run_of_characters():
    assert field_matches(r"C:\Windows\System32\whoami.exe", r"*\whoami.exe", [])


def test_question_mark_matches_exactly_one_character():
    assert field_matches("a1c", "a?c", [])
    assert not field_matches("ac", "a?c", [])


def test_wildcard_does_not_leak_regex_metacharacters():
    """A '.' in a Sigma value is a literal dot, not 'any character'."""
    assert not field_matches("axexe", "a.exe", [])
    assert field_matches("a.exe", "a.exe", [])


def test_backslash_escaped_star_is_a_literal_star():
    assert field_matches("a*b", r"a\*b", [])
    assert not field_matches("axb", r"a\*b", [])


# --- modifiers -------------------------------------------------------------


def test_contains():
    assert field_matches("net user /add bob", "user /add", ["contains"])


def test_contains_is_case_insensitive():
    assert field_matches("NET USER /ADD", "user /add", ["contains"])


def test_startswith():
    assert field_matches(r"C:\Temp\x.exe", r"C:\Temp", ["startswith"])
    assert not field_matches(r"D:\Temp\x.exe", r"C:\Temp", ["startswith"])


def test_endswith():
    assert field_matches(r"C:\Windows\whoami.exe", r"\whoami.exe", ["endswith"])


def test_regex_modifier_is_case_sensitive_by_default():
    """Unlike plain values. Getting this backwards silently widens every rule."""
    assert field_matches("Invoke-Mimikatz", "Invoke-Mimi.*", ["re"])
    assert not field_matches("invoke-mimikatz", "Invoke-Mimi.*", ["re"])


def test_regex_modifier_treats_star_as_a_quantifier_not_a_wildcard():
    assert field_matches("aaa", "a*", ["re"])
    assert field_matches("", "a*", ["re"])


def test_unknown_modifier_is_an_error_not_a_silent_pass():
    """A typo'd modifier that quietly matched everything would be the worst
    possible failure: a rule that looks deployed and detects nothing."""
    with pytest.raises(ValueError, match="unsupported modifier"):
        field_matches("x", "x", ["startswtih"])


# --- lists -----------------------------------------------------------------


def test_list_of_values_is_an_or():
    assert field_matches("cmd.exe", ["powershell.exe", "cmd.exe"], [])
    assert not field_matches("bash", ["powershell.exe", "cmd.exe"], [])


def test_all_modifier_turns_a_list_into_an_and():
    assert field_matches("net user /add bob", ["net", "/add"], ["all", "contains"])
    assert not field_matches("net user bob", ["net", "/add"], ["all", "contains"])


# --- absence ---------------------------------------------------------------


def test_null_matches_an_absent_field():
    assert field_matches(MISSING, None, [])


def test_null_matches_an_explicitly_null_field():
    assert field_matches(None, None, [])


def test_absent_field_matches_nothing_else():
    assert not field_matches(MISSING, "anything", [])
    assert not field_matches(MISSING, "", ["contains"])
