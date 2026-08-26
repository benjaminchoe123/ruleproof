"""Do the test suites actually discriminate?

A rule set where every test passes on the first run is indistinguishable from a
rule set whose tests assert nothing. This script breaks each rule on purpose and
checks that its suite notices. A mutation that survives means the suite has a
hole — usually a missing near-miss negative.

Run: python scripts/mutation_check.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ruleproof.harness import TestSuite, run_suite  # noqa: E402
from ruleproof.rule import Rule, RuleError  # noqa: E402

RULES = Path(__file__).resolve().parent.parent / "rules"

# (rule file, description, find, replace). Each mutation should make at least
# one test case fail — either by widening the rule (false positive) or by
# narrowing it past its own true positives (missed detection).
MUTATIONS = [
    (
        "windows/local_account_created_net.yml",
        "drop the /add discriminator (widens to any 'net user')",
        "      - ' /add'\n",
        "",
    ),
    (
        "windows/local_account_created_net.yml",
        "forget the net1.exe alias (attacker evades by name)",
        "      - '\\net1.exe'\n",
        "",
    ),
    (
        "windows/powershell_encoded_command.yml",
        "forget the spelled-out -EncodedCommand variant",
        "      - ' -encodedcommand '\n",
        "",
    ),
    (
        "windows/powershell_encoded_command.yml",
        "match 'enc' loosely instead of as a flag",
        "      - ' -enc '",
        "      - 'enc'",
    ),
    (
        "windows/clickfix_run_dialog_execution.yml",
        "drop the explorer.exe parent constraint",
        "    ParentImage|endswith: '\\explorer.exe'\n",
        "",
    ),
    (
        "windows/scheduled_task_persistence.yml",
        "drop the user-writable path constraint",
        "  condition: selection and suspicious_path",
        "  condition: selection",
    ),
    (
        "linux/webserver_spawns_shell.yml",
        "drop the parent-process constraint",
        "  condition: selection and not filter_healthcheck",
        "  condition: selection_any",
    ),
    (
        "network/c2_beacon_known_infrastructure.yml",
        "match the indicator as a prefix instead of exactly",
        "    DestinationIp:\n      - '38.147.185.54'",
        "    DestinationIp|startswith:\n      - '38.147.185.5'",
    ),
]


def main():
    survived, killed, skipped = [], 0, []
    for relative, description, find, replace in MUTATIONS:
        rule_path = RULES / relative
        original = rule_path.read_text(encoding="utf-8")
        if find not in original:
            skipped.append(f"{relative}: pattern not found for {description!r}")
            continue

        mutated_text = original.replace(find, replace, 1)
        suite_path = rule_path.with_name(rule_path.stem + ".test.yml")
        suite = TestSuite.from_file(suite_path)

        try:
            rule = Rule.from_yaml(mutated_text, source=rule_path)
        except RuleError:
            # A mutation that makes the rule unloadable is also caught — that is
            # the load-time validation doing its job.
            killed += 1
            print(f"  killed (refused to load)  {relative}: {description}")
            continue

        result = run_suite(rule, suite)
        if result.passed:
            survived.append(f"{relative}: {description}")
            print(f"  SURVIVED                  {relative}: {description}")
        else:
            killed += 1
            kinds = ", ".join(sorted({f.kind for f in result.failures}))
            print(f"  killed ({kinds})".ljust(28) + f"  {relative}: {description}")

    print(f"\n{killed} killed, {len(survived)} survived, {len(skipped)} skipped")
    for note in skipped:
        print(f"  skipped: {note}")
    if survived:
        print("\nSurviving mutations mean a test suite is not discriminating:")
        for s in survived:
            print(f"  - {s}")
    return 1 if survived or skipped else 0


if __name__ == "__main__":
    sys.exit(main())
