"""Does one event field satisfy one Sigma condition?

This is the bottom of the stack and the place correctness actually lives. A
detection rule that silently matches nothing looks identical, in a dashboard, to
a detection rule for a threat that never fired — which is the whole reason this
project exists. So the rules below are implemented literally rather than
approximated, and every one of them is pinned by a test:

  * Plain string comparison is case-insensitive. `|re` is case-sensitive.
    Approximating that in either direction changes what a deployed rule catches.
  * `*` and `?` are wildcards in a plain value. Inside `|re` they are ordinary
    regex quantifiers. Everything else in a plain value is a literal — a `.` in
    a Sigma value means a dot, not "any character".
  * A list is an OR, unless `|all` makes it an AND.
  * `null` matches a field that is absent *or* present-and-null. Nothing else
    matches an absent field.

An unrecognised modifier raises rather than degrading to a plain comparison. A
typo like `startswtih` that quietly fell through to equality would produce a rule
that is deployed, green, and blind.
"""

import re


class _Missing:
    """Sentinel for "this event has no such field", distinct from None.

    `None` is a value a log field can legitimately hold, and Sigma's `null`
    matches both cases — but only this one makes every other comparison false.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self):
        return "MISSING"

    def __bool__(self):
        return False


MISSING = _Missing()

# Deliberately closed. Sigma defines more (|base64, |utf16, |cidr, ...); this
# tool reports an unsupported modifier as an error at load time rather than
# pretending to evaluate a rule it does not fully understand.
SUPPORTED_MODIFIERS = frozenset({"contains", "startswith", "endswith", "re", "all"})


def _wildcard_to_regex(value):
    """Translate a Sigma plain value into a regex, escaping everything but
    the two wildcards. `\\*` and `\\?` are literal; a lone backslash is literal
    (Windows paths are full of them and must not be read as escapes)."""
    out = []
    s = str(value)
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in ("*", "?", "\\"):
            out.append(re.escape(s[i + 1]))
            i += 2
        elif c == "*":
            out.append(".*")
            i += 1
        elif c == "?":
            out.append(".")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def _match_one(event_value, expected, modifiers):
    if expected is None:
        return event_value is MISSING or event_value is None
    if event_value is MISSING or event_value is None:
        return False

    haystack = str(event_value)
    needle = str(expected)

    if "re" in modifiers:
        # Case-sensitive on purpose: Sigma's `|re` does not imply the
        # case-insensitivity that plain values get.
        return re.search(needle, haystack, re.DOTALL) is not None

    body = _wildcard_to_regex(needle)
    if "contains" in modifiers:
        pattern = f".*{body}.*"
    elif "startswith" in modifiers:
        pattern = f"{body}.*"
    elif "endswith" in modifiers:
        pattern = f".*{body}"
    else:
        pattern = body
    return re.fullmatch(pattern, haystack, re.IGNORECASE | re.DOTALL) is not None


def field_matches(event_value, expected, modifiers):
    """True if `event_value` satisfies `expected` under `modifiers`.

    event_value: the value from the event, or MISSING if the field is absent.
    expected:    a scalar, a list (OR, or AND under `all`), or None for `null`.
    modifiers:   the `|`-separated parts of the Sigma field name, e.g.
                 `CommandLine|contains|all` -> ["contains", "all"].
    """
    modifiers = list(modifiers or [])
    for m in modifiers:
        if m not in SUPPORTED_MODIFIERS:
            raise ValueError(
                f"unsupported modifier: {m!r} "
                f"(supported: {', '.join(sorted(SUPPORTED_MODIFIERS))})"
            )

    if isinstance(expected, list | tuple):
        results = [_match_one(event_value, e, modifiers) for e in expected]
        return all(results) if "all" in modifiers else any(results)
    return _match_one(event_value, expected, modifiers)
