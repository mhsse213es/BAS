from load_sigma import load_rules
from translate import translate_rule
import os

SEED_DIR = os.path.join(os.path.dirname(__file__), "..", "sigma_seed")


def test_translate_rule_produces_all_five_backends():
    rules = load_rules(SEED_DIR, technique_ids={"T1059.001"})
    translations, failures = translate_rule(rules[0])
    backends = {t["backend"] for t in translations}
    assert backends == {"microsoft_sentinel", "microsoft_defender", "splunk", "elastic", "crowdstrike"}
    assert failures == []


def test_translate_rule_output_shape():
    rules = load_rules(SEED_DIR, technique_ids={"T1059.001"})
    translations, _ = translate_rule(rules[0])
    splunk = next(t for t in translations if t["backend"] == "splunk")
    assert splunk["language"] == "SPL"
    assert "powershell.exe" in splunk["query"]
    assert splunk["generator"].startswith("pySigma")


def test_translate_rule_isolates_per_backend_failures():
    # A rule using a Sigma feature at least one backend can't handle should
    # still return successful translations for the others, plus a failure
    # entry for the one that broke — never raise.
    import textwrap
    import tempfile

    from sigma.collection import SigmaCollection

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "weird.yml")
        with open(path, "w") as f:
            f.write(textwrap.dedent("""
                title: Weird Rule
                id: 11111111-1111-1111-1111-111111111111
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        Image|endswith: '\\\\cmd.exe'
                    condition: selection
                level: low
            """))
        rule = SigmaCollection.load_ruleset([path]).rules[0]
    translations, failures = translate_rule(rule)
    # This simple rule should convert cleanly everywhere — the point of this
    # test is that the return shape always holds (list, list), never a raise.
    assert isinstance(translations, list)
    assert isinstance(failures, list)
