"""`ruleproof test` and `ruleproof coverage`.

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
    return parser


def main(argv=None):
    _utf8_stdout()
    args = build_parser().parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover - thin shell
    sys.exit(main())
