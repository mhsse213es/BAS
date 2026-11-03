"""QRadar's pySigma backend needs pySigma < 0.10 while every other backend needs 1.4, so it runs in a separate Python
environment. The generator talks to it through a tiny JSON protocol and merges what comes back into each rule record."""
import json
import sys

import pytest

from external_backend import ExternalBackendError, merge_external, run_external


def _record():
    return {"id": "AUDRULE-000001", "sigmaId": "s1", "translations": [{"backend": "splunk"}], "failures": []}


def test_merge_adds_a_generic_translation_with_its_generator_and_never_a_mapping_claim():
    rec = _record()
    merge_external(rec, "qradar", "AQL", {"query": "SELECT 1"}, "pySigma 0.9.11 / qradar 0.3.3")
    t = rec["translations"][-1]
    assert t == {"backend": "qradar", "language": "AQL", "query": "SELECT 1", "generator": "pySigma 0.9.11 / qradar 0.3.3",
                 "mapping": "generic", "pipeline": "", "dataSource": ""}
    assert rec["failures"] == []


def test_merge_records_a_failure_with_its_reason_and_adds_no_translation():
    rec = _record()
    merge_external(rec, "qradar", "AQL", {"reason": "SigmaTransformationError: unsupported field"}, "g")
    assert rec["failures"] == [{"backend": "qradar", "reason": "SigmaTransformationError: unsupported field"}]
    assert [t["backend"] for t in rec["translations"]] == ["splunk"]


def test_merge_with_no_answer_for_the_rule_is_a_failure_not_silence():
    rec = _record()
    merge_external(rec, "qradar", "AQL", None, "g")
    assert rec["failures"][0]["backend"] == "qradar" and "no result" in rec["failures"][0]["reason"]


STUB = r'''
import json, sys
items = json.load(sys.stdin)
out = {"_meta": {"generator": "stub 1.0"}}
for it in items:
    out[it["id"]] = {"query": "Q:" + it["id"]} if it["id"] != "bad" else {"reason": "Boom: nope"}
json.dump(out, sys.stdout)
'''


def test_run_external_sends_items_and_reads_results_and_generator(tmp_path):
    script = tmp_path / "stub.py"
    script.write_text(STUB)
    results, generator = run_external(sys.executable, str(script), [{"id": "a", "path": "x"}, {"id": "bad", "path": "y"}])
    assert generator == "stub 1.0"
    assert results["a"] == {"query": "Q:a"} and results["bad"] == {"reason": "Boom: nope"}


def test_run_external_fails_loudly_when_the_other_environment_breaks(tmp_path):
    script = tmp_path / "crash.py"
    script.write_text("import sys\nprint('traceback here', file=sys.stderr)\nsys.exit(3)\n")
    with pytest.raises(ExternalBackendError, match="exit 3"):
        run_external(sys.executable, str(script), [{"id": "a", "path": "x"}])


def test_run_external_rejects_output_that_is_not_json(tmp_path):
    script = tmp_path / "junk.py"
    script.write_text("print('not json')\n")
    with pytest.raises(ExternalBackendError, match="not valid JSON"):
        run_external(sys.executable, str(script), [{"id": "a", "path": "x"}])
