"""The `detection:` block: search identifiers plus the `condition` expression.

Two layers sit on top of field matching.

A **search identifier** is a map (every key must match — AND) or a list of maps
(any map may match — OR). That asymmetry is worth stating loudly because getting
it backwards produces a rule that still loads, still runs, and quietly matches
far more or far less than its author intended.

A **condition** is a small boolean language over those identifiers:

    condition := or_expr
    or_expr   := and_expr ("or" and_expr)*
    and_expr  := not_expr ("and" not_expr)*
    not_expr  := "not" not_expr | primary
    primary   := "(" or_expr ")" | aggregate | identifier
    aggregate := ("1" | "all") "of" ("them" | <prefix>*)

It is parsed once, at load time, into a tuple AST — not evaluated by string
manipulation and not handed to `eval()`. Rules are data that arrives from
outside the tool (that is the entire point of Sigma being portable), so the
condition never becomes executable Python. Parsing at load time also means a
malformed condition or an unknown identifier is an error when the rule is read,
not a silent `False` at match time on some event nobody was watching.
"""

import fnmatch
import re

from .matching import MISSING, field_matches


class ConditionError(ValueError):
    """A detection block that cannot be understood.

    Always raised, never degraded into a non-match: a rule that cannot be parsed
    is a rule that is not protecting anything, and it must not be able to sit in
    a rule directory looking healthy.
    """


_TOKENS = re.compile(r"\(|\)|[^\s()]+")
_INTEGER = re.compile(r"\d+")


def _split_field(key):
    """`CommandLine|contains|all` -> ("CommandLine", ["contains", "all"])."""
    field, *modifiers = str(key).split("|")
    return field, modifiers


def _map_matches(event, mapping):
    for key, expected in mapping.items():
        field, modifiers = _split_field(key)
        if not field_matches(event.get(field, MISSING), expected, modifiers):
            return False
    return True


def search_matches(event, definition):
    """A search identifier against one event. Map = AND, list of maps = OR."""
    if isinstance(definition, list):
        return any(_map_matches(event, m) for m in definition)
    if isinstance(definition, dict):
        return _map_matches(event, definition)
    raise ConditionError(
        f"search identifier must be a map or a list of maps, got {type(definition).__name__}"
    )


class _Parser:
    def __init__(self, tokens, names, text):
        self.tokens = tokens
        self.names = names
        self.text = text
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self):
        token = self.peek()
        if token is None:
            raise ConditionError(f"condition ended unexpectedly: {self.text!r}")
        self.pos += 1
        return token

    def parse_or(self):
        node = self.parse_and()
        while (self.peek() or "").lower() == "or":
            self.take()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while (self.peek() or "").lower() == "and":
            self.take()
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self):
        if (self.peek() or "").lower() == "not":
            self.take()
            return ("not", self.parse_not())
        return self.parse_primary()

    def parse_primary(self):
        token = self.take()
        if token == "(":
            node = self.parse_or()
            closing = self.take()
            if closing != ")":
                raise ConditionError(f"expected ')' but found {closing!r} in {self.text!r}")
            return node
        if token == ")":
            raise ConditionError(f"unbalanced ')' in condition: {self.text!r}")

        lowered = token.lower()
        if lowered in ("1", "all") and (self.peek() or "").lower() == "of":
            self.take()
            return ("agg", lowered, self._resolve(self.take()))
        if _INTEGER.fullmatch(token):
            raise ConditionError(
                f"unsupported aggregate {token!r} in {self.text!r}: "
                "only '1 of ...' and 'all of ...' are supported"
            )
        if token not in self.names:
            raise ConditionError(
                f"unknown search identifier: {token!r} "
                f"(defined: {', '.join(sorted(self.names)) or 'none'})"
            )
        return ("id", token)

    def _resolve(self, target):
        """Expand `them` or a `prefix*` pattern to concrete identifier names."""
        if target.lower() == "them":
            names = sorted(self.names)
        elif "*" in target:
            names = sorted(n for n in self.names if fnmatch.fnmatchcase(n, target))
        elif target in self.names:
            names = [target]
        else:
            raise ConditionError(f"unknown search identifier: {target!r}")
        if not names:
            raise ConditionError(f"{target!r} matched no search identifiers in {self.text!r}")
        return tuple(names)


def _referenced(node, found):
    """Every search identifier the parsed condition actually reaches."""
    kind = node[0]
    if kind == "id":
        found.add(node[1])
    elif kind == "not":
        _referenced(node[1], found)
    elif kind in ("and", "or"):
        _referenced(node[1], found)
        _referenced(node[2], found)
    elif kind == "agg":
        found.update(node[2])
    return found


def _parse(text, names):
    tokens = _TOKENS.findall(text)
    if not tokens:
        raise ConditionError("condition is empty")
    parser = _Parser(tokens, names, text)
    node = parser.parse_or()
    if parser.pos != len(tokens):
        raise ConditionError(f"unexpected trailing {tokens[parser.pos]!r} in {text!r}")
    return node


class Detection:
    """A parsed `detection:` block, ready to be applied to events."""

    # Keys inside `detection:` that are not search identifiers.
    RESERVED = frozenset({"condition", "timeframe"})

    def __init__(self, searches, condition_text, ast):
        self.searches = searches
        self.condition_text = condition_text
        self.ast = ast

    @classmethod
    def from_dict(cls, block):
        if not isinstance(block, dict):
            raise ConditionError(f"detection block must be a map, got {type(block).__name__}")
        condition = block.get("condition")
        if condition is None:
            raise ConditionError("detection block has no 'condition'")
        searches = {k: v for k, v in block.items() if k not in cls.RESERVED}
        if not searches:
            raise ConditionError("detection block defines no search identifiers")
        return cls(searches, str(condition), _parse(str(condition), set(searches)))

    def unused_identifiers(self):
        """Search identifiers the condition never reaches.

        A `filter_` block the condition forgets to mention reads exactly like
        protection and does nothing whatsoever, which is the failure this project
        exists to name. The parser already refuses the reverse -- an identifier
        used without being defined -- so this closes an asymmetry where the more
        dangerous half was the silent one.

        Reported rather than raised. An unused block still leaves a rule that
        loads and matches correctly, and refusing to load somebody else's
        working rule set is a heavier response than the defect warrants; `test`
        fails the build on it instead.
        """
        return sorted(set(self.searches) - _referenced(self.ast, set()))

    def matches(self, event):
        return self._eval(self.ast, event)

    def _eval(self, node, event):
        kind = node[0]
        if kind == "id":
            return search_matches(event, self.searches[node[1]])
        if kind == "not":
            return not self._eval(node[1], event)
        if kind == "and":
            return self._eval(node[1], event) and self._eval(node[2], event)
        if kind == "or":
            return self._eval(node[1], event) or self._eval(node[2], event)
        if kind == "agg":
            _, quantifier, names = node
            results = [search_matches(event, self.searches[n]) for n in names]
            return all(results) if quantifier == "all" else any(results)
        raise ConditionError(f"unhandled condition node: {node!r}")  # pragma: no cover
