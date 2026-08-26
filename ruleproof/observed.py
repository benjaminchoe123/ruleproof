"""Coverage measured against reality instead of against the rule set's own claims.

`coverage` asks the rule set a question about itself: of the techniques my rules
*claim*, how many are proven? A library can score 100% on that and still detect
nothing anyone is actually being attacked with, because it chose what to claim.

This module supplies the other half — a set of techniques observed in real threat
data, produced by something that is not the rule set. The gap between the two is
the honest number, and it is the one that says which rule to write next.

The dependency runs one way on purpose. This reads a *directory or file
containing ATT&CK identifiers*, nothing more: no schema, no import, no knowledge
of where the data came from. A threat-intel pipeline, a SIEM export, or a text
file typed by hand all work, and none of them become something ruleproof has to
keep up with.
"""

import re
from collections import Counter
from pathlib import Path

#: Word-bounded so `T12345`, `XT1190` and `ticket-T1059` do not read as sightings.
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


class ObservedError(RuntimeError):
    """The observed-technique source could not be used.

    Raised rather than returning an empty set, because "no techniques found" and
    "path was wrong" would otherwise be indistinguishable — and the second one,
    silently treated as the first, reports perfect coverage of nothing.
    """


def _ids_in(text):
    return set(TECHNIQUE_RE.findall(text))


def load_observed(path):
    """Return {technique_id: number of sources citing it}.

    A directory is counted per *file*: three mentions inside one note is one
    sighting, while the same technique across three notes is three. That keeps
    the ranking meaningful — it measures how widely a technique appears, not how
    verbose any single writeup was.
    """
    path = Path(path)
    counts = Counter()

    if path.is_dir():
        files = [p for p in sorted(path.rglob("*")) if p.is_file()]
        if not files:
            raise ObservedError(f"no files found in {path}")
        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue  # an unreadable file is not evidence of anything
            counts.update(_ids_in(text))
    elif path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace")
        # A plain list is the common case, so count repeats line by line rather
        # than deduplicating the whole file.
        for line in text.splitlines():
            counts.update(_ids_in(line))
    else:
        raise ObservedError(f"observed-technique source not found: {path}")

    if not counts:
        raise ObservedError(
            f"no ATT&CK technique identifiers found in {path} — "
            "an empty result is not the same as full coverage"
        )
    return dict(counts)


def _family(technique):
    return technique.split(".")[0]


def coverage_gap(observed, demonstrated):
    """Split observed techniques into (covered, gap).

    Covered means the rule set demonstrates a detection for the technique or for
    something in its family: a proven sub-technique covers its parent and vice
    versa. Being strict about the dot in either direction overstates the gap, and
    a number that overstates the problem gets ignored exactly as fast as one that
    flatters it.

    `gap` comes back ordered by how often the technique was actually seen, because
    that ordering is the actionable part — it names the next rule to write.
    """
    families = {_family(t) for t in demonstrated}

    def is_covered(technique):
        return technique in demonstrated or _family(technique) in families

    covered = sorted((t for t in observed if is_covered(t)),
                     key=lambda t: (-observed[t], t))
    gap = sorted((t for t in observed if not is_covered(t)),
                 key=lambda t: (-observed[t], t))
    return covered, gap


def unobserved(observed, demonstrated):
    """Techniques the rules detect that the data has never actually shown.

    Not a defect on its own — defending against something you have not been hit
    with yet is legitimate. It becomes a finding when it is most of the rule set,
    which means the rules were chosen from general knowledge rather than from the
    evidence already in hand.
    """
    families = {_family(t) for t in observed}
    return sorted(t for t in demonstrated
                  if t not in observed and _family(t) not in families)
