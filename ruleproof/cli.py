"""`ruleproof test`, `ruleproof coverage` and `ruleproof gap`.

Exit codes are the product. This is meant to run in CI, so the important
question is not what it prints but when it returns non-zero:

    0  every rule loaded, every rule has tests, every test passed
    1  something failed, or a rule has no tests at all
    2  the command could not do its job (bad path, empty directory)

The distinction between 1 and 2 matters: an empty or mistyped rules directory
must never look like success, or the gate silently stops gating and nobody finds
out until an incident.
"""

import argparse
import sys
from pathlib import Path

from .harness import discover, run_all
from .observed import ObservedError, coverage_gap, load_observed, unobserved


def _utf8_stdout():
    """Windows stdout is cp1252 even when redirected, and this output contains
    box-drawing and check characters."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        pass  # not a real tty (pytest capture); the default is fine


def _check_dir(path):
    """Return (Path, error_message). An unusable directory is exit 2, not 0."""
    directory = Path(path)
    if not directory.is_dir():
        return None, f"rules directory not found: {directory}"
    if not discover(directory):
        return None, f"no rules found in {directory}"
    return directory, None


def _cmd_test(args):
    directory, error = _check_dir(args.rules_dir)
    if error:
        print(error, file=sys.stderr)
        return 2

    report = run_all(directory)

    for err in report.load_errors:
        print(f"  ERROR  {err}")

    for result in report.results:
        for failure in result.failures:
            print(f"  FAIL   {result.rule_title}")
            print(f"         {failure.kind}: {failure.case.name}")

    for path in report.untested:
        print(f"  UNTESTED  {path}")

    cases = sum(r.total for r in report.results)
    print(
        f"\n{report.tested} rule(s) tested, {cases} case(s), "
        f"{len(report.failures)} failure(s), {len(report.untested)} untested, "
        f"{len(report.load_errors)} error(s)"
    )

    if report.failures or report.load_errors:
        return 1
    if report.untested and not args.allow_untested:
        print("\nuntested rules are failures by default; pass --allow-untested to tolerate them")
        return 1
    return 0


def _cmd_coverage(args):
    directory, error = _check_dir(args.rules_dir)
    if error:
        print(error, file=sys.stderr)
        return 2

    report = run_all(directory)
    claimed = sorted(report.claimed_techniques)
    covered = report.covered_techniques

    print(f"ATT&CK coverage: {len(covered)}/{len(claimed)} claimed technique(s) demonstrated\n")
    for technique in claimed:
        mark = "yes" if technique in covered else "NO "
        print(f"  [{mark}] {technique}")

    gap = [t for t in claimed if t not in covered]
    if gap:
        print(
            f"\n{len(gap)} technique(s) are claimed by a rule tag but have no passing test: "
            + ", ".join(gap)
        )
    return 0


def _cmd_gap(args):
    """Coverage against observed reality rather than against the rules' own claims.

    `coverage` lets a rule set grade its own homework: it reports the techniques
    the rules claim versus the ones they prove. This asks the question from
    outside — of the techniques actually seen in threat data, how many would we
    catch — and the two answers disagree.
    """
    directory, error = _check_dir(args.rules_dir)
    if error:
        print(error, file=sys.stderr)
        return 2

    try:
        observed = load_observed(args.observed)
    except ObservedError as e:
        print(str(e), file=sys.stderr)
        return 2

    demonstrated = run_all(directory).covered_techniques
    covered, gap = coverage_gap(observed, demonstrated)
    total = len(observed)
    pct = (len(covered) / total * 100) if total else 0.0

    print(f"Observed techniques      : {total}")
    print(f"Demonstrated by rules    : {len(demonstrated)}")
    print(f"Observed AND detected    : {len(covered)}  ({pct:.0f}%)")
    print(f"Observed, NOT detected   : {len(gap)}\n")

    if covered:
        print("COVERED - seen in the data and provably detected")
        for t in covered:
            print(f"  {t:<12} {observed[t]:>4} source(s)")
        print()

    if gap:
        print("GAP - most-observed techniques with no demonstrated detection")
        for t in gap[: args.limit]:
            print(f"  {t:<12} {observed[t]:>4} source(s)")
        if len(gap) > args.limit:
            print(f"  ... and {len(gap) - args.limit} more (--limit to show)")
        print()

    stranded = unobserved(observed, demonstrated)
    if stranded:
        print(
            f"{len(stranded)} of {len(demonstrated)} demonstrated technique(s) were "
            "never observed in this data: " + ", ".join(stranded)
        )
        print(
            "  Not wrong on its own, but if it is most of the rule set the rules were "
            "chosen from general knowledge rather than from the evidence in hand."
        )

    if args.fail_under is not None and pct < args.fail_under:
        print(
            f"\nFAIL: {pct:.0f}% of observed techniques are detected, "
            f"below the required {args.fail_under:.0f}%"
        )
        return 1
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ruleproof", description="Unit tests for Sigma detection rules."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_test = sub.add_parser("test", help="run every rule against its test cases")
    p_test.add_argument("rules_dir")
    p_test.add_argument(
        "--allow-untested",
        action="store_true",
        help="do not fail when a rule has no test file (for adopting an existing rule set)",
    )
    p_test.set_defaults(func=_cmd_test)

    p_cov = sub.add_parser("coverage", help="ATT&CK techniques claimed vs. demonstrated")
    p_cov.add_argument("rules_dir")
    p_cov.set_defaults(func=_cmd_coverage)

    p_gap = sub.add_parser(
        "gap",
        help="coverage against techniques actually observed in threat data",
    )
    p_gap.add_argument("rules_dir")
    p_gap.add_argument(
        "observed",
        help="file or directory containing ATT&CK identifiers seen in real data "
             "(threat-intel notes, a SIEM export, or a plain list)",
    )
    p_gap.add_argument(
        "--fail-under", type=float, default=None, metavar="PCT",
        help="exit 1 when fewer than PCT%% of observed techniques are detected",
    )
    p_gap.add_argument(
        "--limit", type=int, default=15, metavar="N",
        help="how many gap techniques to list (default 15)",
    )
    p_gap.set_defaults(func=_cmd_gap)
    return parser


def main(argv=None):
    _utf8_stdout()
    args = build_parser().parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover - thin shell
    sys.exit(main())
