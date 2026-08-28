"""Run rules against their test cases and report what broke.

The design turns on one idea: **untested is a result, not an absence.**

A rule directory reports green very easily. Every rule that loads, loads; every
rule with no tests has no failing tests. That is how a detection library rots —
not by failing, but by never being asked. So `Report.ok` is false while any rule
is untested, and `covered_techniques` counts only techniques whose rules are
demonstrated to work, separately from `claimed_techniques`, which counts what
the tags assert. The gap between those two numbers is the honest measure of a
detection library, and it is the number this tool exists to print.

The two failure kinds are kept distinct everywhere, because they mean opposite
things to whoever has to act on them:

  * *missed detection* — a `true_positives` case did not fire. The rule would
    have been silent during the thing it was written for.
  * *false positive* — a `true_negatives` case fired. This is the one that gets
    a rule muted in production, after which it protects nothing.
"""

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .rule import Rule, RuleError


class HarnessError(ValueError):
    """A test file that cannot be used."""


@dataclass(frozen=True)
class Case:
    name: str
    event: dict


@dataclass(frozen=True)
class Failure:
    kind: str  # "missed detection" | "false positive"
    case: Case
    rule_title: str = ""

    def describe(self):
        return f"{self.kind}: {self.case.name}"


class TestSuite:
    # Name starts with "Test", so pytest tries to collect it as a test class and
    # warns that it cannot. It is a domain object, not a test.
    __test__ = False

    def __init__(self, true_positives, true_negatives, source=None):
        self.true_positives = true_positives
        self.true_negatives = true_negatives
        self.source = source

    @classmethod
    def from_yaml(cls, text, source=None):
        where = str(source) if source else "<test suite>"
        try:
            raw = yaml.safe_load(text) or {}
        except yaml.YAMLError as e:
            raise HarnessError(f"{where}: invalid YAML: {e}") from e
        if not isinstance(raw, dict):
            raise HarnessError(f"{where}: test file must be a YAML map")

        def cases(key):
            out = []
            for i, entry in enumerate(raw.get(key) or []):
                if not isinstance(entry, dict):
                    raise HarnessError(f"{where}: {key}[{i}] must be a map")
                if "event" not in entry or not isinstance(entry["event"], dict):
                    raise HarnessError(f"{where}: {key}[{i}] has no 'event' map")
                out.append(Case(name=str(entry.get("name") or f"{key}[{i}]"), event=entry["event"]))
            return out

        tps, tns = cases("true_positives"), cases("true_negatives")
        if not tps and not tns:
            raise HarnessError(f"{where}: no test cases (an empty test file is not coverage)")
        return cls(tps, tns, source=source)

    @classmethod
    def from_file(cls, path):
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as e:
            raise HarnessError(f"{path}: cannot read: {e}") from e
        return cls.from_yaml(text, source=path)


@dataclass
class SuiteResult:
    rule_title: str
    total: int
    failures: list

    @property
    def passed(self):
        return not self.failures


def run_suite(rule, suite):
    failures = []
    for case in suite.true_positives:
        if not rule.matches(case.event):
            failures.append(Failure("missed detection", case, rule.title))
    for case in suite.true_negatives:
        if rule.matches(case.event):
            failures.append(Failure("false positive", case, rule.title))
    return SuiteResult(
        rule_title=rule.title,
        total=len(suite.true_positives) + len(suite.true_negatives),
        failures=failures,
    )


@dataclass(frozen=True)
class Discovered:
    rule_path: Path
    test_path: Path | None


TEST_SUFFIX = ".test.yml"


def discover(rules_dir):
    """Every rule under `rules_dir`, paired with its `<stem>.test.yml` if present.

    `*.test.yml` files live beside the rules they test, so they must be excluded
    from the rule glob — otherwise each one loads as a rule and is reported
    broken, burying the real findings.
    """
    rules_dir = Path(rules_dir)
    found = []
    for path in sorted(rules_dir.rglob("*.yml")) + sorted(rules_dir.rglob("*.yaml")):
        if path.name.endswith(TEST_SUFFIX) or path.name.endswith(".test.yaml"):
            continue
        candidate = path.with_name(path.stem + TEST_SUFFIX)
        found.append(Discovered(path, candidate if candidate.exists() else None))
    return sorted(found, key=lambda d: str(d.rule_path))


def orphaned_tests(rules_dir):
    """Test files with no rule beside them.

    The mirror of an untested rule, and the same failure in the other direction:
    a rule with no tests scores nothing, and a test with no rule tests nothing.
    Both report green. This one is arguably worse, because the file sitting in
    the directory implies coverage that does not exist — which is exactly what
    happens when a rule is renamed or deleted and its tests are left behind.

    A rule may be `.yml` or `.yaml`, so both have to be checked before calling a
    test file orphaned.
    """
    rules_dir = Path(rules_dir)
    suffixes = (TEST_SUFFIX, ".test.yaml")
    orphans = []
    for path in sorted(rules_dir.rglob("*")):
        if not path.is_file():
            continue
        matched = next((suf for suf in suffixes if path.name.endswith(suf)), None)
        if matched is None:
            continue
        stem = path.name[: -len(matched)]
        if not any((path.with_name(stem + ext)).exists() for ext in (".yml", ".yaml")):
            orphans.append(path)
    return orphans


@dataclass
class Report:
    results: list = field(default_factory=list)
    untested: list = field(default_factory=list)
    load_errors: list = field(default_factory=list)
    orphaned: list = field(default_factory=list)
    covered_techniques: set = field(default_factory=set)
    claimed_techniques: set = field(default_factory=set)

    @property
    def tested(self):
        return len(self.results)

    @property
    def failures(self):
        return [f for r in self.results for f in r.failures]

    @property
    def ok(self):
        """Green requires every rule to load, pass, AND have tests at all."""
        return (not self.failures and not self.untested
                and not self.load_errors and not self.orphaned)


def run_all(rules_dir):
    report = Report()
    report.orphaned = orphaned_tests(rules_dir)
    for found in discover(rules_dir):
        try:
            rule = Rule.from_file(found.rule_path)
        except RuleError as e:
            # One unparseable file must not abort the run for every other rule.
            report.load_errors.append(e)
            continue

        report.claimed_techniques.update(rule.techniques)

        if found.test_path is None:
            report.untested.append(found.rule_path)
            continue

        try:
            suite = TestSuite.from_file(found.test_path)
        except HarnessError as e:
            report.load_errors.append(e)
            continue

        result = run_suite(rule, suite)
        report.results.append(result)
        if result.passed:
            # Coverage means "demonstrated to work", not "a file exists".
            report.covered_techniques.update(rule.techniques)
    return report


def duplicate_ids(rules_dir):
    """[(id, [paths])] for any Sigma id claimed by more than one rule.

    A Sigma `id` is a UUID that SIEMs and rule managers key on. Two rules sharing
    one means an import silently keeps a single rule: the survivor looks healthy
    and the loser is simply absent. That is a rule which never fires while
    appearing to exist, which is the failure this whole project is built to make
    visible — and per-file validation cannot see it, because each rule is
    individually valid.

    Rules with no id are ignored. Absent is not duplicated: they cannot replace
    each other on a key that does not exist, and inventing a policy about missing
    ids is a different decision from catching a collision.

    A rule that will not parse is skipped rather than raised on. `test` already
    reports it as broken, and one unreadable file must not blind the scan to a
    real collision elsewhere.
    """
    seen = {}
    for found in discover(rules_dir):
        try:
            rule = Rule.from_file(found.rule_path)
        except RuleError:
            continue
        rule_id = rule.id
        if not rule_id:
            continue
        seen.setdefault(str(rule_id), []).append(found.rule_path)
    return [(rule_id, paths) for rule_id, paths in sorted(seen.items()) if len(paths) > 1]


def dead_conditions(rules_dir):
    """[(path, [identifiers])] for rules defining a search block nothing uses.

    The condition parser already refuses an identifier that is *used* without
    being defined. This is the reverse, and the more dangerous of the two because
    it is the silent one: a `filter_` block the condition forgets to mention
    reads exactly like protection and does nothing at all.

    Reported here rather than refused at load time. Such a rule still loads and
    still matches correctly, so refusing to read somebody else's working rule set
    over it is heavier than the defect warrants -- `test` fails the build instead,
    which is where a policy decision belongs.
    """
    dead = []
    for found in discover(rules_dir):
        try:
            rule = Rule.from_file(found.rule_path)
        except RuleError:
            continue  # `test` already reports this one as broken
        unused = rule.detection.unused_identifiers()
        if unused:
            dead.append((found.rule_path, unused))
    return dead
