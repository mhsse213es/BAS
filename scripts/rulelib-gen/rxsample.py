"""Sample strings that match a regex, by walking Python's own parse tree (no third-party generator)."""
import random
import re
try:
    import re._parser as sp
    from re import _constants as C
except ImportError:  # Python < 3.11
    import sre_parse as sp
    import sre_constants as C

_PRINT = "abcxyzABCXYZ019 -_./:\\"


def _cat(code, rng):
    return {C.CATEGORY_DIGIT: "5", C.CATEGORY_SPACE: " ", C.CATEGORY_WORD: "w",
            C.CATEGORY_NOT_DIGIT: "x", C.CATEGORY_NOT_SPACE: "x", C.CATEGORY_NOT_WORD: "-"}.get(code, "a")


def _in(items, rng):
    neg = any(op == C.NEGATE for op, _ in items)
    pool = []
    for op, av in items:
        if op == C.LITERAL:
            pool.append(chr(av))
        elif op == C.RANGE:
            pool.extend(chr(c) for c in range(av[0], min(av[1], av[0] + 30) + 1))
        elif op == C.CATEGORY:
            pool.append(_cat(av, rng))
    if neg:
        cand = [c for c in _PRINT if c not in pool]
        return rng.choice(cand or ["#"])
    return rng.choice(pool or ["a"])


def _gen(parsed, rng, groups):
    out = []
    for op, av in parsed:
        if op == C.LITERAL:
            out.append(chr(av))
        elif op == C.NOT_LITERAL:
            out.append(rng.choice([c for c in _PRINT if c != chr(av)]))
        elif op == C.ANY:
            out.append(rng.choice("abc1 -"))
        elif op == C.IN:
            out.append(_in(av, rng))
        elif op == C.CATEGORY:
            out.append(_cat(av, rng))
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            lo, hi, sub = av
            hi = min(hi, lo + 3) if hi != C.MAXREPEAT else lo + 3
            for _ in range(rng.randint(lo, max(lo, hi))):
                out.append(_gen(sub, rng, groups))
        elif op == C.SUBPATTERN:
            s = _gen(av[3], rng, groups)
            if av[0]:
                groups[av[0]] = s
            out.append(s)
        elif op == C.BRANCH:
            out.append(_gen(rng.choice(av[1]), rng, groups))
        elif op in (C.AT, C.ASSERT, C.ASSERT_NOT):
            pass
        elif op == C.GROUPREF:
            out.append(groups.get(av, ""))
    return "".join(out)


def samples(pattern, flags=0, n=6, seed=1):
    rng = random.Random(seed)
    parsed = sp.parse(pattern, flags)
    res = set()
    for _ in range(n * 3):
        s = _gen(parsed, rng, {})
        if re.search(pattern, s, flags):
            res.add(s)
        if len(res) >= n:
            break
    return sorted(res)
