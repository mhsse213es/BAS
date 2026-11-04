"""A pySigma object's repr can leak into a query. The Lucene backend escapes `(`, `=` and so on, so the leaked text
looks different from the other backends'. 40 Elastic queries shipped with this defect because the gate only knew the
unescaped form."""
from translate import looks_corrupt


def test_the_unescaped_leak_is_caught():
    assert looks_corrupt("f:SigmaRegularExpression(regexp=SigmaString(['a']), flags=set())")


def test_the_lucene_escaped_leak_is_caught():
    # exactly as shipped for AUDRULE-000035
    assert looks_corrupt(
        r"file.path:SigmaRegularExpression\(regexp\=SigmaString\(\['\\\\sessionresume_\[a\-zA\-Z\]\{8\}$'\]\),\ flags\=set\(\)\)")


def test_an_ordinary_query_is_not_flagged():
    assert not looks_corrupt(r"process.command_line:*\-\-Sigma* AND event.code:4688")
    assert not looks_corrupt(r"process.command_line:/\s-[FTd]\s/")
