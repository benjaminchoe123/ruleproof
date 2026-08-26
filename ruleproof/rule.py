"""Loading and validating a Sigma rule file.

Everything this module can detect about a broken rule, it detects at load time.
That is a deliberate stance rather than a stylistic one: a rule directory is
exactly the kind of place where a file with a typo'd modifier or an unparseable
condition sits for months while a dashboard counts it as coverage. A rule this
tool cannot fully evaluate is refused, by name, with the reason — it never loads
half-understood.

The scope is honest about itself. Sigma has modifiers this evaluator does not
implement (`|base64offset`, `|cidr`, `|utf16`, ...); rules using them raise
rather than silently falling back to equality, because a rule that is deployed,
green, and blind is worse than a rule that failed to load.
"""

import re
from pathlib import Path

import yaml

from .detection import ConditionError, Detection
from .matching import SUPPORTED_MODIFIERS

# `attack.t1136.001` -> T1136.001. Sigma writes the tag lowercase; ATT&CK, the
# Navigator, and every layer file use the uppercase form. Comparing the two
# without normalising reports zero coverage for every rule in the directory.
_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TACTIC_TAG = re.compile(r"^attack\.([a-z_]+)$", re.IGNORECASE)


class RuleError(ValueError):
    """A rule file that cannot be loaded. Always names the file when there is one."""


def _check_modifiers(detection_block, where):
    """Reject unsupported field modifiers before the rule can be used."""
    for name, definition in detection_block.items():
        if name in Detection.RESERVED:
            continue
        maps = definition if isinstance(definition, list) else [definition]
        for mapping in maps:
            if not isinstance(mapping, dict):
                continue
            for key in mapping:
                for modifier in str(key).split("|")[1:]:
                    if modifier not in SUPPORTED_MODIFIERS:
                        raise RuleError(
                            f"{where}: unsupported modifier {modifier!r} on field {key!r} "
                            f"(supported: {', '.join(sorted(SUPPORTED_MODIFIERS))})"
                        )


class Rule:
    def __init__(self, raw, detection, source=None):
        self.raw = raw
        self.detection = detection
        self.source = source

    # --- construction ------------------------------------------------------

    @classmethod
    def from_yaml(cls, text, source=None):
        where = str(source) if source else "<rule>"
        try:
            documents = list(yaml.safe_load_all(text))
        except yaml.YAMLError as e:
            raise RuleError(f"{where}: invalid YAML: {e}") from e

        documents = [d for d in documents if d is not None]
        if not documents:
            raise RuleError(f"{where}: file is empty")
        if len(documents) > 1:
            raise RuleError(
                f"{where}: multi-document rule collections are not supported yet "
                f"({len(documents)} documents found)"
            )

        raw = documents[0]
        if not isinstance(raw, dict):
            raise RuleError(f"{where}: rule must be a YAML map, got {type(raw).__name__}")
        if not raw.get("title"):
            raise RuleError(f"{where}: rule has no 'title'")
        detection_block = raw.get("detection")
        if not detection_block:
            raise RuleError(f"{where}: rule has no 'detection' block")

        _check_modifiers(detection_block, where)
        try:
            detection = Detection.from_dict(detection_block)
        except ConditionError as e:
            raise RuleError(f"{where}: {e}") from e

        return cls(raw, detection, source=source)

    @classmethod
    def from_file(cls, path):
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as e:
            raise RuleError(f"{path}: cannot read: {e}") from e
        return cls.from_yaml(text, source=path)

    # --- metadata ----------------------------------------------------------

    @property
    def title(self):
        return self.raw.get("title")

    @property
    def id(self):
        return self.raw.get("id")

    @property
    def level(self):
        return self.raw.get("level")

    @property
    def status(self):
        return self.raw.get("status")

    @property
    def description(self):
        return self.raw.get("description")

    @property
    def logsource(self):
        return self.raw.get("logsource") or {}

    @property
    def falsepositives(self):
        fp = self.raw.get("falsepositives") or []
        return fp if isinstance(fp, list) else [fp]

    @property
    def tags(self):
        tags = self.raw.get("tags") or []
        return [str(t) for t in tags]

    @property
    def techniques(self):
        """ATT&CK technique IDs, normalised to the uppercase `T####[.###]` form."""
        found = []
        for tag in self.tags:
            m = _TECHNIQUE_TAG.match(tag)
            if m:
                found.append(m.group(1).upper())
        return found

    @property
    def tactics(self):
        """ATT&CK tactic names — `attack.` tags that are not technique IDs."""
        return [
            m.group(1).lower()
            for tag in self.tags
            if (m := _TACTIC_TAG.match(tag)) and not _TECHNIQUE_TAG.match(tag)
        ]

    # --- evaluation --------------------------------------------------------

    def matches(self, event):
        return self.detection.matches(event)

    def __repr__(self):
        return f"<Rule {self.title!r} from {self.source or '<string>'}>"
