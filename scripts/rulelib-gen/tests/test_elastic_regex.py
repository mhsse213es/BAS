"""Lucene query_string regexes must match the whole field value, so a Sigma search regex needs padding."""
import pytest

from elastic_regex import Unsupported, pad_query_regexes


def test_an_unanchored_regex_is_padded_so_it_matches_anywhere_in_the_value():
    assert pad_query_regexes("process.command_line:/-D/") == "process.command_line:/.*(-D).*/"


def test_anchors_are_honoured_and_not_padded():
    assert pad_query_regexes("f:/^abc$/") == "f:/(abc)/"
    assert pad_query_regexes("f:/^abc/") == "f:/(abc).*/"


def test_case_insensitive_prefix_becomes_letter_classes_because_query_string_has_no_flag():
    out = pad_query_regexes("f:/(?i)ab\.c/")
    assert out == "f:/.*([aA][bB]\.[cC]).*/"


def test_only_regexes_are_touched_and_the_rest_of_the_query_is_kept_verbatim():
    q = "a:*\:\/\/localhost* AND f:/x/ OR b:\"q\" AND g:/y|z/"
    assert pad_query_regexes(q) == "a:*\:\/\/localhost* AND f:/.*(x).*/ OR b:\"q\" AND g:/.*(y|z).*/"


def test_an_escaped_slash_inside_the_regex_stays_inside_it():
    assert pad_query_regexes("f:/a\/b/") == "f:/.*(a\/b).*/"


def test_a_query_without_a_regex_is_unchanged():
    q = "f:abc AND g:(x OR y)"
    assert pad_query_regexes(q) == q


def test_a_regex_lucene_cannot_express_is_refused():
    with pytest.raises(Unsupported):
        pad_query_regexes("f:/a(?=b)/")


def test_translate_rule_pads_the_regex_in_the_shipped_lucene_query():
    from sigma.collection import SigmaCollection
    import translate
    yml = ("title: t\nstatus: test\nlogsource:\n  product: linux\n  category: process_creation\ndetection:\n"
           "  sel:\n    Image|endswith: '/auditctl'\n    CommandLine|re: '-D'\n  condition: sel\n")
    trs, _ = translate.translate_rule(SigmaCollection.from_yaml(yml).rules[0])
    q = {t["backend"]: t for t in trs}["elastic"]["query"]
    assert "/.*(-D).*/" in q and "/-D/" not in q


def test_a_regex_the_ecs_windows_pipeline_stringifies_is_recovered_in_lucene_and_dsl():
    from sigma.collection import SigmaCollection
    import json
    import translate
    yml = ("title: t\nstatus: test\nlogsource:\n  product: windows\n  category: file_event\ndetection:\n"
           "  sel:\n    TargetFilename|re: '\\\\sessionresume_[a-zA-Z]{8}$'\n  condition: sel\n")
    trs, fails = translate.translate_rule(SigmaCollection.from_yaml(yml).rules[0])
    by = {t["backend"]: t for t in trs}
    assert "elastic" in by, fails
    assert "SigmaRegularExpression" not in by["elastic"]["query"] and "AUDRX" not in by["elastic"]["query"]
    assert "sessionresume_" in by["elastic"]["query"] and by["elastic"]["query"].count("/") >= 2
    dsl = json.loads(by["elastic"]["dsl"])["query"]["regexp"]
    assert list(dsl.values())[0]["value"].startswith(".*(")


def test_an_empty_alternative_is_spelled_so_lucene_accepts_it():
    from elastic_regex import to_lucene
    assert to_lucene(r"a(?:\s|)b")[0] == ".*(a([ \t\n\r\f\v]|())b).*"
    assert "(|" not in to_lucene(r"(|a)")[0].replace("(()|", "")


def test_a_long_bounded_negated_repeat_before_more_pattern_is_refused_but_other_long_repeats_are_kept():
    import pytest
    from elastic_regex import Unsupported, to_lucene
    with pytest.raises(Unsupported):
        to_lucene(r'\.exe[^"]{0,64}werfault\.exe')
    to_lucene(r'(?:x|y)\\[^\\]{1,256}$')   # followed only by the end: fine on Elasticsearch
    to_lucene(r'-k\s\w{1,64}(?:\s?-p)?')   # not a negated class: fine
    to_lucene(r'^a[^"]{0,64}b')            # anchored at the start: fine
