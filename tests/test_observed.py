"""Coverage measured against reality, not against the rule set's own claims.

`coverage` answers "of the techniques my rules claim, how many are proven?" That
is a question the rule set asks about itself, and a rule set can score 100% on it
while detecting nothing anyone is actually being attacked with.

`gap` asks the question from outside: of the techniques seen in real threat data,
how many would we catch? The two numbers disagree, and the disagreement is the
point. When this was first measured by hand, three of six rules covered techniques
the source data had never once observed — chosen from general knowledge rather
than from the evidence already on disk.
"""

import pytest

from ruleproof.cli import main
from ruleproof.observed import ObservedError, coverage_gap, load_observed
from tests.test_cli import build

NOTE_A = """---
title: CVE-2026-1111
---
Exploitation uses T1059.001 to run an encoded command, then T1071.001 for C2.
"""

NOTE_B = """---
title: CVE-2026-2222
---
Initial access via T1190 against a public-facing app; C2 over T1071.001.
"""

NOTE_C = """---
title: CVE-2026-3333
---
Another T1190 case.
"""


def observed_dir(tmp_path):
    d = tmp_path / "techniques"
    d.mkdir()
    (d / "a.md").write_text(NOTE_A, encoding="utf-8")
    (d / "b.md").write_text(NOTE_B, encoding="utf-8")
    (d / "c.md").write_text(NOTE_C, encoding="utf-8")
    return d


# --------------------------------------------------------------- loading


def test_load_observed_counts_files_citing_each_technique(tmp_path):
    """Counted per file, not per mention. Three mentions in one note is one
    sighting; the same technique across three notes is three."""
    counts = load_observed(observed_dir(tmp_path))
    assert counts["T1190"] == 2
    assert counts["T1071.001"] == 2
    assert counts["T1059.001"] == 1


def test_load_observed_reads_a_plain_list_file(tmp_path):
    listing = tmp_path / "observed.txt"
    listing.write_text("T1190\nT1059.001\nT1190\n", encoding="utf-8")
    counts = load_observed(listing)
    assert counts["T1190"] == 2
    assert counts["T1059.001"] == 1


def test_load_observed_ignores_things_that_only_look_like_technique_ids(tmp_path):
    """Wrong length, or glued to letters or digits, means it is not a technique.

    A *hyphen* deliberately does not disqualify: `MITRE-T1059` and `T1059-based`
    are both ordinary ways an analyst writes a technique reference in prose, and
    dropping them to avoid miscounting the occasional ticket number would lose far
    more real signal than it saves.
    """
    noise = tmp_path / "noise.txt"
    noise.write_text("T123 T12345 XT1190 T1190x T1059x1 T1071.001\n", encoding="utf-8")
    # the one real identifier survives; nothing else does
    assert load_observed(noise) == {"T1071.001": 1}


def test_hyphenated_references_still_count(tmp_path):
    prose = tmp_path / "prose.txt"
    prose.write_text("A MITRE-T1059 chain, i.e. T1190-based initial access.\n", encoding="utf-8")
    assert load_observed(prose) == {"T1059": 1, "T1190": 1}


def test_load_observed_rejects_a_missing_path(tmp_path):
    with pytest.raises(ObservedError):
        load_observed(tmp_path / "nope")


def test_load_observed_rejects_a_source_with_no_techniques_in_it(tmp_path):
    """An empty result must not read as 'perfect coverage of nothing'. A mistyped
    path that happens to exist is the dangerous case."""
    empty = tmp_path / "empty.txt"
    empty.write_text("no identifiers here\n", encoding="utf-8")
    with pytest.raises(ObservedError):
        load_observed(empty)


# --------------------------------------------------------------- the gap


def test_exact_match_counts_as_covered():
    covered, gap = coverage_gap({"T1190": 3}, {"T1190"})
    assert covered == ["T1190"]
    assert gap == []


def test_a_sub_technique_is_covered_by_a_demonstrated_parent():
    covered, gap = coverage_gap({"T1071.001": 1}, {"T1071"})
    assert covered == ["T1071.001"]
    assert gap == []


def test_a_parent_is_covered_by_a_demonstrated_sub_technique():
    """Being strict about the dot in either direction overstates the gap, and a
    number that overstates the problem gets ignored just as fast as one that
    flatters."""
    covered, gap = coverage_gap({"T1071": 1}, {"T1071.001"})
    assert covered == ["T1071"]
    assert gap == []


def test_gap_is_ordered_by_how_often_the_technique_was_actually_seen():
    """The ranking is the actionable part: it says which rule to write next."""
    _, gap = coverage_gap({"T1190": 24, "T1571": 9, "T1219": 7}, set())
    assert gap == ["T1190", "T1571", "T1219"]


def test_demonstrated_but_never_observed_is_not_counted_as_coverage():
    covered, gap = coverage_gap({"T1190": 1}, {"T1053.005"})
    assert covered == []
    assert gap == ["T1190"]


# --------------------------------------------------------------- the command


def test_gap_reports_observed_and_covered_counts(tmp_path, capsys):
    rules = build(tmp_path)
    assert main(["gap", str(rules), str(observed_dir(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "3" in out  # three techniques observed
    assert "T1190" in out


def test_gap_names_rules_covering_techniques_never_observed(tmp_path, capsys):
    """The finding that motivated this command."""
    rules = build(tmp_path)
    main(["gap", str(rules), str(observed_dir(tmp_path))])
    out = capsys.readouterr().out
    assert "never observed" in out.lower()


def test_gap_exits_two_on_an_unusable_observed_path(tmp_path, capsys):
    rules = build(tmp_path)
    assert main(["gap", str(rules), str(tmp_path / "nope")]) == 2


def test_gap_exits_one_when_below_the_required_percentage(tmp_path, capsys):
    """So CI can stop coverage regressing, the same way `test` stops rules rotting."""
    rules = build(tmp_path)
    code = main(["gap", str(rules), str(observed_dir(tmp_path)), "--fail-under", "99"])
    assert code == 1
    assert "below" in capsys.readouterr().out.lower()


def test_gap_exits_zero_when_the_requirement_is_met(tmp_path):
    rules = build(tmp_path)
    assert main(["gap", str(rules), str(observed_dir(tmp_path)), "--fail-under", "0"]) == 0
