# ruleproof

Unit tests for [Sigma](https://github.com/SigmaHQ/sigma) detection rules.

A detection rule that matches nothing looks exactly like a detection rule for a threat
that never fired. Both produce silence. `ruleproof` makes a rule prove it fires on the
thing it was written for, and stays quiet on the things it wasn't.

```console
$ ruleproof test rules
11 rule(s) tested, 105 case(s), 0 failure(s), 0 untested, 0 orphaned, 0 duplicate id(s), 0 error(s)
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
  DUPLICATE ID  6b1e0a54-2c9e-4b7a-9a1f-0f2b1c4d5e01

6 rule(s) tested, 49 case(s), 1 failure(s), 1 untested, 1 orphaned, 1 duplicate id(s), 0 error(s)

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

A third failure is visible only across the whole set: two rules claiming the same Sigma **id**.
Each rule is individually valid and both pass their own tests, so per-file validation cannot see
it — but a SIEM keys on that UUID, so importing both silently keeps one. The survivor looks
healthy and the loser is simply absent: a rule that never fires while appearing to exist, which is
the thing this repo exists to make visible. It fails the build, and like orphans it is **not**
covered by `--allow-untested`, because adopting somebody else's rule set explains rules without
tests but not two rules claiming one identity. Rules with no id are ignored — absent is not
duplicated.

It found nothing on this rule set, which is worth stating plainly. It was added because six of the
eleven ids differ only in their last two hex digits, which is what hand-incremented ids look like
just before someone copies a file and forgets.

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

A snapshot of real observed activity ships with the repo, so this runs with nothing else
cloned:

```console
$ ruleproof gap rules samples/observed-techniques.txt --limit 3
Observed techniques      : 43
Demonstrated by rules    : 11
Observed AND detected    : 17  (40%)
Observed, NOT detected   : 26

COVERED - seen in the data and provably detected
  ...

GAP - most-observed techniques with no demonstrated detection
  T1190          25 source(s)
  T1056.001       4 source(s)
  T1068           4 source(s)
  ... and 23 more (--limit to show)

2 of 11 demonstrated technique(s) were never observed in this data: T1053.005, T1136.001
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
`test` stops rules rotting — **this repo's own CI gates on it**, which is the difference between
a number in a README and a number that stays true. `--limit N` controls how much of the gap is
listed.

`samples/observed-techniques.txt` is a snapshot of what the [threat-intel-pipeline][pipeline]
observed: 43 techniques across 127 sightings, one line per sighting, since the repetition is
what ranks the gap. `samples/observed-techniques-confirmed.txt` is the same data restricted to
sightings the source did not flag as inference — see below for why that second file exists. Both
are public ATT&CK identifiers and nothing else — no indicators, no customer data. Point the
command at your own data and it reports your coverage instead.

The snapshot is regenerated by command, not maintained by hand. A figure that can only be
refreshed by editing a file goes stale the moment the data moves — which is the failure this
whole command exists to catch, one level up. `scripts/snapshot_observed.py <dir>` builds one
from any directory of text; the two committed samples come from the pipeline's own
`python -m pipeline.techniques`, which can additionally tell its confirmed sightings from its
inferred ones. That distinction turned out to matter more than the coverage number.

### How much of "observed" is actually observed

`gap` ranks by observed frequency, and that ranking decides which rule gets written next. So it
is worth asking what the word *observed* is carrying. In the source vault, **53% of technique
sightings (67 of 127) come from notes whose own author flagged them** as going beyond their
source. For several techniques the ATT&CK mapping is exactly what went beyond it — the notes
say so in as many words:

> keystroke logging is core, well-documented Agent Tesla behavior *(family knowledge, not shown
> in this source data)*

A ThreatFox IOC dump cannot show keylogging. The technique was inferred from the family name,
which is fair enrichment and unfair evidence, and a frequency ranking cannot tell them apart.

So the same rules are measured against both standards, and both are gated in CI:

| | observed | detected | coverage |
|---|---|---|---|
| every sighting | 43 | 17 | **40%** |
| only sightings the source did not flag | 24 | 12 | **50%** |

Coverage goes **up** under the stricter standard, which is the opposite of convenient: the
inferred mappings are mostly obscure recon and infrastructure techniques that nothing detects,
so including them made the number look worse than the rule set deserves. The headline was
pessimistic.

The ranking is where it bites, because the ranking is the part that changes behaviour. The
clearest case is a rule in this repo. **T1189 was written because it ranked highest — and only
one of its five sightings comes from an unflagged note.** The rule is sound and its tests hold, but the
argument for writing it *next* was thinner than the number made it look. On confirmed evidence
the queue reads T1068 (4), T1056.001 (3), T1555.003 (2) instead.

`flagged` is a property of the note, not of the individual mapping, so the confirmed subset is a
conservative floor that discards some sound mappings too — which is why both numbers are always
reported and neither is presented as *the* coverage figure. A single number here would be the
thing this project exists to argue against.

The dependency runs one way on purpose: this reads *a file or directory containing ATT&CK
identifiers*, with no schema and no import. It knows nothing about where the data came from,
and so has nothing to keep up with.

## Quickstart

```bash
pip install pyyaml
python -m ruleproof.cli test rules        # exit 1 on failures or untested rules
python -m ruleproof.cli coverage rules    # ATT&CK claimed vs. demonstrated
python -m ruleproof.cli gap rules samples/observed-techniques.txt   # ...vs. what is being seen
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
  killed (false positive)     windows/local_account_created_net.yml: drop the /add discriminator (widens to any 'net user')
  killed (missed detection)   windows/local_account_created_net.yml: forget the net1.exe alias (attacker evades by name)
  killed (refused to load)    linux/webserver_spawns_shell.yml: drop the parent-process constraint
  ...
26 killed, 0 survived, 0 skipped
```

### Are the negatives guarding anything?

`test` proves a rule stays silent on its negatives. It cannot tell a negative that nearly fired
from one that shares nothing with the rule at all — and a suite of unrelated negatives reports
exactly as green as a suite of sharp ones. That is the same shape as the untested-rule problem
this project was built on: the result looks identical whether the check is doing work or not.

`ruleproof negatives` measures **distance to firing** — how many of a rule's conditions would
have to flip before it fires. A negative at distance 1 breaks exactly one thing, so it is the
case that fails when that one thing is loosened. That is what makes it a guard.

```console
$ ruleproof negatives rules --strict

scheduled_task_persistence.yml
  weak (distance 2): querying tasks rather than creating one

every constraint has a negative that fails when it is loosened.
```

Two findings, weighted differently on purpose:

- an **unguarded constraint** is a defect — no negative fails when that condition is loosened, so
  the condition is intended rather than tested. `--strict` exits 1 on these, and **this repo's CI
  gates on it**;
- a **weak negative** is a smell. It passes for no particular reason, but it is often a legitimate
  realistic-benign case, so it is reported and does not fail the build.

Distance is computed over the parsed condition, not by counting matched conditions, because a
filter inverts the arithmetic: an event stopped *only* by `not filter_x` matches every condition
in the rule and still does not fire. Counting matches would score the sharpest possible negative
as the bluntest, which is how a well-meant metric ends up recommending that good tests be deleted.

**It found two real defects on its first run, in rules whose suites were passing:**

1. A **dead filter**. The C2 rule excluded RFC1918 destinations — but its indicator list is five
   public addresses, so no event could ever satisfy both. The filter was unreachable, and the
   negative that appeared to test it (`10.38.147.185`) matched no indicator either, so it tested
   nothing. Deleted, because a condition that cannot fire is decoration implying protection. This
   is the second time this repo has shipped a dead filter; the first was found by hand.
2. A **negative that guarded nothing**, in the scheduled-task rule. The case named "deleting a
   task that lives in AppData" was meant to pin the `/create` discriminator, but its command line
   said `AppDataTask` — no `\AppData\` — so it broke both conditions instead of one and pinned
   neither. Exactly the shape of the mutation that survived on 2026-08-26. Replaced with a case
   that satisfies the path condition and fails only on the verb, and a matching mutation now
   proves it.

This is the mutation check's argument approached from the other side: mutation testing breaks the
rule and asks whether the suite notices, while this reads the suite and asks whether it *could*.
The second is much cheaper, so it can gate every push.

This found two genuine holes the first time it ran, both in rules that were passing:

1. The negative for `net user` never contained `' user '` (no trailing space), so widening
   the rule went unnoticed. Fixed by adding `net user alice /domain` — which *does* contain
   `' user '` and no `/add`, so it fails the moment the discriminator is dropped.
2. A `-Encoding` exclusion filter turned out to be **dead code**: no `-Encoding` command can
   match `' -enc '` with its trailing space, so the filter was guarding against nothing. It
   was deleted rather than left in looking protective.

Mutation checking runs in CI.

### The mutation check earned its keep

While writing the T1219 rule, one mutation **survived**: loosening the tool-name match from
`endswith` to `contains` failed no test at all. The near-miss negative meant to guard that —
`anydesk-support-notes.exe` — never contained the string `\AnyDesk.exe` in the first place, so
it had never tested the distinction. It only looked like it did.

The fix was a case that does contain it: `client32.exe.tmp`, a partial download whose name runs
past the executable. `contains` fires on it; `endswith` does not.

That is the argument for mutation testing in three lines. The suite was green, the rule was
correct, and one of its constraints was guarded by a test that asserted nothing. Nothing else in
the toolchain would have said so.

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

Nine rules across Windows, Linux, and network telemetry, each with true positives and
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
| Remote access tool from a user-writable path | T1219 | **chosen by `gap`** |
| LOLBin downloading to a user-writable path | T1105 | **chosen by `gap`** |
| Script host executing a browser download | T1189 | **chosen by `gap`** |
| Browser credential store copied by another process | T1555.003 | **chosen by `gap`** |

They are drawn from activity in the [threat-intel-pipeline][pipeline] weekly reports —
the ClickFix rule covers the SmartApeSG/ClearFake/FAKEUPDATES delivery chain, the web-shell
rule covers the class of unauthenticated command injection that Zimbra CVE-2026-73570
belongs to, and the C2 rule uses indicators from
[2026-W35][w35].

That pairing is the point of building this one second: **the pipeline says what is being
exploited; ruleproof says whether I would catch it.**

The last rule in that table was not chosen by intuition. `ruleproof gap` reported T1571 as the
second most-observed technique in the pipeline's data — 9 sources — with no detection at all,
so it was the obvious next one to write. Adding it moved observed coverage from **26% to 28%**,
then T1219 (Remote Access Tools), T1105 (Ingress Tool Transfer) and T1189 (Drive-by Compromise)
took it to **35%**. All four rules were picked by the measurement rather than by taste.

One technique on that list is deliberately **not** attempted: **T1190, Exploit Public-Facing
Application** — the most-observed technique in the data at 25 sightings, and completely
undetected. (This previously read "the most-observed technique by a factor of three", which was
never true of the data as a whole: T1071.001 sits at 13. The factor described the lead over the
next-largest *undetected* technique, and that lead is now above six, because the rules written
since have cleared everything between. Overstating a headline gap in a project about honest
coverage numbers is worth correcting even where the error argues in the project's favour.) It cannot be caught by one generic rule, because exploiting a public-facing
application looks different for every product, and writing something that pattern-matches
invented exploit strings would be worse than leaving the gap visible. T1190 is where generic
detection stops and product-specific detection has to start. Saying so is more useful than a
rule that would never fire.

**T1189, Drive-by Compromise** — the next entry on that same list — is the contrast that keeps
the T1190 decision honest rather than convenient. It is also delivery-side, and it also varies
by site and by lure, but it ends somewhere fixed: a Windows script host interpreting a file the
browser put on disk. That endpoint is the same whether the lure is ClearFake or FAKEUPDATES, so
it can be written behaviourally, and it was. The distinction is not "web things are hard" — it
is whether the technique converges on an observable that does not depend on the product being
attacked.

That rule's exclusion is the part worth reading: a script run from the **Outlook attachment
cache** is filtered out, even though it sits under the same `INetCache` path a browser download
does. Mail-delivered scripts are user execution of an attachment, not a drive-by; letting them
fire would let this rule claim T1189 coverage using detections of something else. The exclusion
has its own near-miss test case and its own mutation.

### Three reasons a gap stays open, and why naming them matters

Working down the ranked gap produced something more useful than the next rule: the undetected
techniques are not undetected for one reason, and lumping them together is what lets a coverage
number hide behind "detection is hard". Three of the top four are left alone deliberately, each
for a different and stateable reason.

| technique | why it is open | could a rule close it? |
|---|---|---|
| **T1190** Exploit Public-Facing Application | **Product-shaped.** The observable is a request to a specific application, and it differs per product. | Yes, one product at a time — never generically. |
| **T1068** Exploitation for Privilege Escalation | **Outcome-shaped.** It names a *result*, not a behaviour. Detecting it means detecting the specific exploit (product-shaped again) or the post-conditions, which are other techniques with their own IDs. | No. A rule tagged T1068 here would be a token-manipulation or UAC-bypass detection wearing the wrong label. |
| **T1056.001** Keylogging | **Telemetry-shaped.** The behaviour is real and uniform, and invisible in the log sources these rules read. Keystroke capture happens through API hooks, not process creation. | Yes, given ETW or API-level telemetry. Not from a 4688 stream, whatever the rule says. |
| **T1555.003** Credentials from Web Browsers | Nothing — it is none of the three. | **Written.** See the table above. |

The outcome-shaped case is the one worth dwelling on, because it is the easiest to fake. It
would be trivial to write a plausible-looking T1068 rule, watch coverage rise, and never notice
that the rule detects something else with a different ATT&CK ID stapled to it. That is the same
move this repo already refuses in a smaller place — the T1189 rule excludes the Outlook
attachment cache for exactly that reason — and refusing it consistently is what stops the
coverage number becoming decoration.

A technique left open for a *named* reason is a different object from one nobody got to.
Both show as gaps in the number; only one of them is an answer.

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
