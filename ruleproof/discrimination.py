"""How much work is a `true_negative` actually doing?

`test` proves a rule stays silent on its negatives. It cannot tell a negative
that nearly fired from one that shares nothing with the rule at all, and a suite
of unrelated negatives reports exactly as green as a suite of sharp ones. That is
the same shape as the untested-rule problem this project was built on: the result
looks identical whether the check is doing work or not.

The measure is **distance to firing** — the smallest number of search identifiers
whose outcome would have to flip before the condition evaluates true. Distance 1
means the negative breaks exactly one thing, so it is the case that fails when
that one thing is loosened. That is what makes it a guard. A negative at distance
2 or more is not protecting any particular constraint; it is scenery.

Distance is computed over the parsed condition rather than by counting matched
identifiers, because a filter inverts the arithmetic. An event caught only by
`not filter_x` matches *every* identifier in the rule and still does not fire.
Counting matches would score the sharpest possible negative as the bluntest one,
which is how a well-meant metric ends up recommending that good tests be deleted.

This is the same argument as `scripts/mutation_check.py`, approached from the
other side. Mutation testing breaks the rule and asks whether the suite notices;
this reads the suite and asks whether it *could*.
"""

from itertools import combinations

from .detection import search_matches


def _eval(node, values):
    """Evaluate a parsed condition against a map of identifier -> bool.

    Deliberately separate from `Detection._eval`, which reads the event on every
    identifier. Here the identifier outcomes are supplied so that they can be
    flipped, which is the entire point.
    """
    kind = node[0]
    if kind == "id":
        return values[node[1]]
    if kind == "not":
        return not _eval(node[1], values)
    if kind == "and":
        return _eval(node[1], values) and _eval(node[2], values)
    if kind == "or":
        return _eval(node[1], values) or _eval(node[2], values)
    if kind == "agg":
        _, quantifier, names = node
        results = [values[n] for n in names]
        return all(results) if quantifier == "all" else any(results)
    raise ValueError(f"unhandled condition node: {node!r}")  # pragma: no cover


def identifier_outcomes(detection, event):
    """{identifier: whether this event satisfies it}."""
    return {name: search_matches(event, definition)
            for name, definition in detection.searches.items()}


def distance_to_firing(detection, event, max_distance=2):
    """Fewest identifier flips that would make this rule fire on this event.

    0 means it already fires. `max_distance + 1` is returned as a ceiling rather
    than searching every subset — scoring is 2^n in the worst case and the only
    distinction that matters is "one flip away" versus "further than that".
    """
    values = identifier_outcomes(detection, event)
    if _eval(detection.ast, values):
        return 0
    names = list(values)
    for size in range(1, max_distance + 1):
        for flipped in combinations(names, size):
            probe = dict(values)
            for name in flipped:
                probe[name] = not probe[name]
            if _eval(detection.ast, probe):
                return size
    return max_distance + 1


def weakest_negatives(detection, cases, max_distance=2):
    """[(case name, distance)] for negatives that guard no single constraint.

    A negative at distance 0 is not returned here — that is a false positive, and
    `test` already reports it as a failure. This is only about negatives that pass
    for the wrong reason.
    """
    weak = []
    for case in cases:
        distance = distance_to_firing(detection, case.event, max_distance)
        if distance > 1:
            weak.append((case.name, distance))
    return weak


def guarding_identifier(detection, event):
    """The single identifier whose flip would make this event fire, or None.

    None means the event is not one flip from firing — either it already fires,
    or more than one thing is keeping it out. Only a single-flip negative pins a
    constraint, because only that case fails when that constraint is loosened.
    """
    values = identifier_outcomes(detection, event)
    if _eval(detection.ast, values):
        return None
    found = None
    for name in values:
        probe = dict(values)
        probe[name] = not probe[name]
        if _eval(detection.ast, probe):
            if found is not None:
                return None  # ambiguous: two different single flips fire it
            found = name
    return found


def unguarded_constraints(detection, cases):
    """Search identifiers no negative pins, in the rule's own order.

    The sharper question than "is this negative weak". A rule can have five sharp
    negatives that all guard the same condition and leave another completely
    unpinned — which is exactly how a mutation survived here on 2026-08-26: the
    suite was green, the rule was correct, and one constraint was protected by a
    test that asserted nothing about it.

    Filters count. An exclusion nothing tests is an exclusion that exists only in
    the author's intention.
    """
    guarded = {guarding_identifier(detection, case.event) for case in cases}
    return [name for name in detection.searches if name not in guarded]
