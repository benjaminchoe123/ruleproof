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
        "network/c2_commodity_rat_nonstandard_port.yml",
        "include 8080, which the same data carried C2 on but is ordinary HTTP-alt",
        "      - 1604    # DarkComet default",
        "      - 8080\n      - 1604    # DarkComet default",
    ),
    (
        "network/c2_commodity_rat_nonstandard_port.yml",
        "include TrueConf's own service port 4307 (legitimate by design)",
        "      - 7777    # DCRat",
        "      - 4307\n      - 7777    # DCRat",
    ),
    (
        "network/c2_commodity_rat_nonstandard_port.yml",
        "drop the internal-address filter (fires on RFC1918 and loopback)",
        "  condition: selection and not filter_internal",
        "  condition: selection",
    ),
    (
        "windows/remote_access_tool_from_user_path.yml",
        "drop the user-writable path constraint (flags every legitimate install)",
        "  condition: selection and user_writable_path",
        "  condition: selection",
    ),
    (
        "windows/remote_access_tool_from_user_path.yml",
        "match tool names loosely instead of as a full filename",
        "    Image|endswith:",
        "    Image|contains:",
    ),
    (
        "windows/remote_access_tool_from_user_path.yml",
        "forget the process-creation constraint (matches any event type)",
        "    EventID: 4688\n",
        "",
    ),
    (
        "windows/lolbin_download_to_user_path.yml",
        "drop the URL requirement (fires on ordinary certificate work)",
        "  condition: selection_lolbin and selection_url and selection_user_path",
        "  condition: selection_lolbin and selection_user_path",
    ),
    (
        "windows/lolbin_download_to_user_path.yml",
        "drop the user-writable destination (fires on legitimate corporate updates)",
        "  condition: selection_lolbin and selection_url and selection_user_path",
        "  condition: selection_lolbin and selection_url",
    ),
    (
        "windows/lolbin_download_to_user_path.yml",
        "drop the LOLBin constraint (fires on any process mentioning a URL)",
        "  condition: selection_lolbin and selection_url and selection_user_path",
        "  condition: selection_url and selection_user_path",
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
    (
        "windows/script_host_runs_browser_download.yml",
        "drop the download-location constraint (fires on every logon script)",
        "  condition: selection_host and selection_downloaded and not filter_mail_attachment",
        "  condition: selection_host and not filter_mail_attachment",
    ),
    (
        "windows/script_host_runs_browser_download.yml",
        "look for the script host anywhere in the event, not as the executing image",
        "    Image|endswith:\n      - '\\wscript.exe'\n      - '\\cscript.exe'\n      - '\\mshta.exe'",
        "    CommandLine|contains:\n      - 'wscript'\n      - 'cscript'\n      - 'mshta'",
    ),
    (
        "windows/script_host_runs_browser_download.yml",
        "stop excluding the Outlook attachment cache (claims T1189 for mail delivery)",
        "    CommandLine|contains: '\\Content.Outlook\\'",
        "    CommandLine|contains: '\\NeverAppearsInAnyPath\\'",
    ),
    (
        "windows/script_host_runs_browser_download.yml",
        "forget the process-creation constraint (matches any event type)",
        "    EventID: 4688\n",
        "",
    ),
    (
        "windows/browser_credential_store_copied.yml",
        "drop the credential-store constraint (fires on any copy)",
        "  condition: selection_tool and selection_store",
        "  condition: selection_tool",
    ),
    (
        "windows/browser_credential_store_copied.yml",
        "match the store loosely as 'Login' instead of the filename",
        "      - '\\Login Data'",
        "      - 'Login'",
    ),
    (
        "windows/browser_credential_store_copied.yml",
        "look for the copy tool anywhere in the event, not as the executing image",
        "    Image|endswith:\n      - '\\esentutl.exe'\n      - '\\cmd.exe'\n      - '\\powershell.exe'\n      - '\\pwsh.exe'\n      - '\\robocopy.exe'\n      - '\\xcopy.exe'",
        "    CommandLine|contains:\n      - 'esentutl'\n      - 'cmd'\n      - 'powershell'\n      - 'pwsh'\n      - 'robocopy'\n      - 'xcopy'",
    ),
    (
        "windows/browser_credential_store_copied.yml",
        "forget the process-creation constraint (matches any event type)",
        "    EventID: 4688\n",
        "",
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
