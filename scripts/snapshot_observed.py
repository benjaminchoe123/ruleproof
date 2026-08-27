"""Regenerate samples/observed-techniques.txt from a directory of threat data.

The snapshot is what `ruleproof gap` measures coverage against, and CI gates on
the number it produces. A figure that can only be refreshed by hand goes stale
the moment the data moves, which is the failure this project exists to argue
against -- so the capture is a command, not an afternoon.

The one-way dependency is preserved: this reads *text containing ATT&CK
identifiers*, nothing more. No schema, no import, no knowledge of what wrote the
files. Technique names are lifted opportunistically from a `T1234 - Some Name`
rendering if the source happens to carry one, and left off when it does not --
an unnamed technique is unnamed, not guessed at.

Run: python scripts/snapshot_observed.py <source-dir> [-o samples/observed-techniques.txt]
"""

import argparse
import re
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ruleproof.observed import load_observed  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "samples" / "observed-techniques.txt"

#: `T1189 - Drive-by Compromise`, with any dash and optional wiki-link brackets
#: around the id. Loose about the surroundings, strict about the shape. The
#: optional second segment is what makes sub-technique names come out right --
#: ATT&CK renders them `Phishing: Spearphishing Link`, and stopping at the first
#: colon silently labels the child with its parent's name. Prose following the
#: name is rejected by length, not by punctuation, because a sentence can begin
#: with a capital letter as easily as a technique name can.
_NAMED_RE = re.compile(
    r"\b(T\d{4}(?:\.\d{3})?)\]{0,2}\s*[-–—:]\s*"
    r"([A-Z][^\n:;.]{2,48}?(?::\s*[A-Z][^\n:;.]{2,40}?)?)\s*[:.\n]"
)

HEADER = """\
# ATT&CK techniques observed in live threat data.
#
# {techniques} techniques across {sources} sightings, captured {captured} from
# {origin}.
#
# One line per sighting, so a technique seen in five separate sources appears
# five times -- that repetition is what ranks the gap.
#
# These are public ATT&CK identifiers, nothing more. No indicators, no customer
# data. Regenerate against your own data and `ruleproof gap` reports your
# coverage instead of this one:
#
#   python scripts/snapshot_observed.py /path/to/your/threat/notes
#   ruleproof gap rules samples/observed-techniques.txt
"""


def collect_names(source_dir):
    """{technique_id: name} for whatever the source text happens to name.

    First rendering wins. A source that names the same technique two different
    ways is telling you something about itself, not about ATT&CK, and picking a
    winner by majority would hide that.
    """
    names = {}
    for path in sorted(Path(source_dir).rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for tid, name in _NAMED_RE.findall(text):
            names.setdefault(tid, name.strip())
    return names


def render(counts, names, origin, captured=None):
    captured = captured or date.today().isoformat()
    out = [HEADER.format(
        captured=captured,
        origin=origin,
        techniques=len(counts),
        sources=sum(counts.values()),
    )]
    # Most-seen first, so the file reads in the order the gap report ranks.
    for tid, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        label = names.get(tid)
        out.append(f"{tid}  # x{count}" + (f"  {label}" if label else ""))
        out.extend([tid] * (count - 1))
    return "\n".join(out) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("source", help="directory (or file) of text citing ATT&CK ids")
    parser.add_argument("-o", "--out", default=str(DEFAULT_OUT))
    parser.add_argument("--origin", default=None,
                        help="how to describe the source in the file header")
    args = parser.parse_args(argv)

    counts = load_observed(args.source)
    names = collect_names(args.source) if Path(args.source).is_dir() else {}
    origin = args.origin or Path(args.source).as_posix()
    Path(args.out).write_text(render(counts, names, origin), encoding="utf-8", newline="\n")
    print(f"wrote {len(counts)} technique(s), {sum(counts.values())} sighting(s) to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
