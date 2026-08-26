# ruleproof

Unit tests for [Sigma](https://github.com/SigmaHQ/sigma) detection rules.

A detection rule that matches nothing looks exactly like a detection rule for a threat
that never fired. Both produce silence. `ruleproof` makes a rule prove it fires on the
thing it was written for, and stays quiet on the things it wasn't.

```console
$ ruleproof test rules
7 rule(s) tested, 54 case(s), 0 failure(s), 0 untested, 0 orphaned, 0 error(s)
$ echo $?
0
```

When something is wrong it says which kind of wrong, and returns non-zero:

```console
$ ruleproof test rules      # after someone loosens a rule
  FAIL   Local Account Created via net.exe
         false positive: querying one account - contains ' user ' but no /add
  UNTESTED  rules/windows/lsass_dump.yml
  ORPHANED  rules/windows/renamed_rule.test.yml  (test file with no rule beside it)

6 rule(s) tested, 49 case(s), 1 failure(s), 1 untested, 1 orphaned, 0 error(s)

untested rules are failures by default; pass --allow-untested to tolerate them
$ echo $?
1
```

## The idea it's built around

**Untested is a result, not an absence.**

A rule directory reports green very easily. Every rule that loads, loads. Every rule with
no tests has no failing tests. That is how a detection library rots — not by failing, but
by never being asked. So:

- a rule with no test file is a **failure**, not a blank (`--allow-untested` exists for
  adopting an existing rule set, but you have to ask for it in writing);
- `coverage` reports **claimed** ATT&CK techniques separately from **demonstrated** ones.
  The gap between those two numbers is the honest measure of a detection library.

The two failure kinds are never blurred, because they mean opposite things to whoever has
to act on them:

| kind | meaning | why it matters |
|---|---|---|
| **missed detection** | a `true_positives` case did not fire | the rule was silent during the thing it exists to catch |
| **false positive** | a `true_negatives` case fired | this is how a rule gets muted in production, after which it protects nothing |

A third kind was added after the tool caught it happening here: an **orphaned** test file,
one with no rule beside it. It is the mirror of an untested rule and the same failure in the
other direction — a rule with no tests scores nothing, a test with no rule tests nothing, and
both report green. This one is arguably worse, because the file sitting in the directory
implies coverage that is not there. It happens when a rule is renamed or deleted and its tests
are left behind, and unlike untested rules it is **not** covered by `--allow-untested`:
adopting somebody else's rule set explains rules without tests, but nothing explains a test
file whose rule does not exist.

## Coverage against reality, not against your own claims

`coverage` lets a rule set grade its own homework. It reports the techniques your rules
**claim** against the ones they **prove** — useful, but a library can score 100% on that and
still detect nothing anyone is actually being attacked with, because it chose what to claim in
the first place.

`gap` asks the question from outside. Point it at any source of ATT&CK identifiers observed in
real data — threat-intel notes, a SIEM export, a text file — and it reports what fraction of
what you are *actually seeing* you would catch.

```console
$ ruleproof gap rules ../threat-intel-pipeline/vault/threats
Observed techniques      : 43
Demonstrated by rules    : 6
Observed AND detected    : 11  (26%)
Observed, NOT detected   : 32

GAP - most-observed techniques with no demonstrated detection
  T1190          24 source(s)
  T1571           9 source(s)
  T1219           7 source(s)
  ...

2 of 6 demonstrated technique(s) were never observed in this data: T1053.005, T1136.001
  Not wrong on its own, but if it is most of the rule set the rules were chosen from
  general knowledge rather than from the evidence in hand.
```

Two things that output is designed to make unavoidable:

- **The gap is ranked by how often each technique was actually seen**, so it names the next rule
  to write instead of leaving you with a percentage. Above, `T1190` is both the most-observed
  technique in the data and completely undetected.
- **Rules aimed at things you have never seen are reported separately.** Defending against
  something that has not hit you yet is legitimate; discovering that it describes most of your
  rule set means the rules came from general knowledge rather than from evidence you already
  had. That is what the author found on the first real run of this command.

`--fail-under PCT` exits 1 below a threshold, so CI can stop coverage regressing the same way
`test` stops rules rotting. `--limit N` controls how much of the gap is listed.

The dependency runs one way on purpose: this reads *a file or directory containing ATT&CK
identifiers*, with no schema and no import. It knows nothing about where the data came from,
and so has nothing to keep up with.

## Quickstart

```bash
pip install pyyaml
python -m ruleproof.cli test rules        # exit 1 on failures or untested rules
python -m ruleproof.cli coverage rules    # ATT&CK claimed vs. demonstrated
python -m ruleproof.cli gap rules NOTES   # ...vs. what is actually being seen
```

A rule and its tests sit side by side:

```
rules/windows/local_account_created_net.yml
rules/windows/local_account_created_net.test.yml
```

```yaml
# local_account_created_net.test.yml
true_positives:
  - name: net1.exe variant used to evade a name-only rule
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\net1.exe'
      CommandLine: 'net1 user attacker Passw0rd! /add'

true_negatives:
  - name: querying one account - contains ' user ' but no /add
    event:
      EventID: 4688
      Image: 'C:\Windows\System32\net.exe'
      CommandLine: 'net user alice /domain'
```

That negative is doing real work. See below.

## Do the tests actually test anything?

Every rule passing on the first run is indistinguishable from a rule set whose tests assert
nothing. `scripts/mutation_check.py` breaks each rule on purpose and checks its suite
notices:

```console
$ python scripts/mutation_check.py
  killed (false positive)     drop the /add discriminator (widens to any 'net user')
  killed (missed detection)   forget the net1.exe alias (attacker evades by name)
  killed (refused to load)    drop the parent-process constraint
  ...
8 killed, 0 survived, 0 skipped
```

This found two genuine holes the first time it ran, both in rules that were passing:

1. The negative for `net user` never contained `' user '` (no trailing space), so widening
   the rule went unnoticed. Fixed by adding `net user alice /domain` — which *does* contain
   `' user '` and no `/add`, so it fails the moment the discriminator is dropped.
2. A `-Encoding` exclusion filter turned out to be **dead code**: no `-Encoding` command can
   match `' -enc '` with its trailing space, so the filter was guarding against nothing. It
   was deleted rather than left in looking protective.

Mutation checking runs in CI.

## How it works

```mermaid
flowchart TD
    A[rules/*.yml] --> B[Rule.from_file]
    B -->|strict validation| C{loads?}
    C -->|no| E[load_errors]
    C -->|yes| D[Detection.from_dict]
    D --> F[condition parsed to a tuple AST]
    A2["rules/*.test.yml"] --> G[TestSuite]
    F --> H[run_suite]
    G --> H
    H --> I[missed detection / false positive]
    B -.->|no test file| J[untested]
    I --> K[Report.ok]
    J --> K
    E --> K
```

Four layers, each with its own tests:

| module | job |
|---|---|
| `matching.py` | does one event field satisfy one Sigma condition |
| `detection.py` | search identifiers (map = AND, list = OR) + the `condition` language |
| `rule.py` | load and validate a rule file; extract ATT&CK tags |
| `harness.py` | run suites, classify failures, report coverage |

### Two decisions worth stating

**The condition is parsed, never `eval()`-ed.** Rules are data that arrives from outside the
tool — that is the whole point of Sigma being portable. `condition: selection and not filter`
is tokenised and parsed by recursive descent into a tuple AST. It never becomes executable
Python.

**Everything that can be validated at load time is.** An unsupported modifier, an unknown
search identifier, an unparseable condition, a multi-document file — all refused when the
rule is read, by filename, with the reason. A rule this tool cannot fully evaluate must
never be able to sit in a directory looking healthy. That is why `|base64offset` raises
instead of quietly falling back to equality: a rule that is deployed, green, and blind is
worse than a rule that failed to load.

## Sigma support

Implemented and tested: `contains`, `startswith`, `endswith`, `re`, `all`; wildcards `*`
and `?` with backslash escaping; case-insensitive plain values and case-sensitive `|re`;
map/list AND/OR semantics; `null` matching absent-or-null; `and` / `or` / `not` /
parentheses with correct precedence; `1 of them`, `all of them`, `1 of prefix_*`.

**Not implemented:** `|base64offset`, `|utf16`, `|cidr`, `|expand`, correlation rules,
multi-document rule collections, and field mapping to specific SIEM backends. All of these
raise at load time rather than being approximated.

This is an evaluator for testing rules against sample events, not a backend that converts
Sigma into SIEM queries — use [pySigma](https://github.com/SigmaHQ/pySigma) for that.

## The rules in this repo

Seven rules across Windows, Linux, and network telemetry, each with true positives and
near-miss negatives:

| rule | ATT&CK | why this one |
|---|---|---|
| Local account created via `net.exe` | T1136.001 | |
| PowerShell encoded command | T1059.001 | |
| ClickFix paste-and-run via the Run dialog | T1204.004 | |
| Scheduled task from a user-writable path | T1053.005 | |
| Web server process spawns a shell | T1505.003 | |
| Outbound connection to known C2 infrastructure | T1071.001 | |
| Commodity RAT C2 on a non-standard port | T1571 | **chosen by `gap`** |

They are drawn from activity in the [threat-intel-pipeline][pipeline] weekly reports —
the ClickFix rule covers the SmartApeSG/ClearFake/FAKEUPDATES delivery chain, the web-shell
rule covers the class of unauthenticated command injection that Zimbra CVE-2026-73570
belongs to, and the C2 rule uses indicators from
[2026-W35][w35].

That pairing is the point of building this one second: **the pipeline says what is being
exploited; ruleproof says whether I would catch it.**

The last rule in that table was not chosen by intuition. `ruleproof gap` reported T1571 as the
second most-observed technique in the pipeline's data — 9 sources — with no detection at all,
so it was the obvious next one to write. Adding it moved observed coverage from **26% to 28%**.

Writing it also produced the most useful decision in the rule set. The same week's data carried
C2 on ports **8080** and **4307**, and both are deliberately excluded: 8080 is ordinary
HTTP-alt, and 4307 is TrueConf's own service port — those entries were vulnerabilities in a
legitimate server, not C2. Including them would have made the rule fire on normal traffic, and
a rule that fires on normal traffic gets muted. Two of the mutation checks exist specifically
to prove that exclusion is tested rather than merely intended.

[pipeline]: https://github.com/benjaminchoe123/threat-intel-pipeline
[w35]: https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/reports/2026-W35.md

## Development

```bash
python -m venv .venv && .venv/Scripts/activate   # or source .venv/bin/activate
pip install pyyaml pytest ruff
python -m pytest -q          # 80 tests
python -m ruff check ruleproof/ tests/ scripts/
```

Built test-first: every test in this repo was watched failing before the code that satisfies
it was written. `pytest` runs with `filterwarnings = ["error"]`, which is how the unclosed
file handle in `Rule.from_file` was found.

## Limitations

- Events are plain dicts. Nothing here parses EVTX, JSON lines, or a SIEM export — bring
  your own decoder.
- Field names are compared literally. There is no taxonomy mapping between, say,
  `process.command_line` and `CommandLine`.
- `true_negatives` prove a rule does not fire on the benign cases *you thought of*. That is
  strictly better than nothing and strictly worse than production telemetry.
- `gap` counts a technique as covered when the rule set demonstrates it **or something in its
  family** — a proven sub-technique covers its parent and vice versa. That is a deliberate
  choice: being strict about the dot overstates the gap, and a number that overstates the
  problem gets ignored exactly as fast as one that flatters. It does mean a rule for one
  sub-technique reads as covering a sibling it may not really catch.
- `gap` measures against whatever you point it at. Coverage of a narrow data set is not
  coverage of your environment, and the command cannot tell the difference.

## License

MIT — see [LICENSE](LICENSE).
