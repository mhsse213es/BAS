import os
import tempfile
import textwrap

from techniques import covered_techniques


def test_covered_techniques_reads_technique_id_next_to_detection_profiles():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "scenario1.yaml"), "w") as f:
            f.write(textwrap.dedent("""
                id: scenario1
                name: Test Scenario
                steps:
                  - name: step with profile
                    technique_id: T1059.001
                    detection_profiles:
                      - windows_encoded_powershell
                  - name: step without profile
                    technique_id: T1547.001
            """))
        result = covered_techniques(d)
    assert result == {"T1059.001"}


def test_covered_techniques_scans_multiple_files():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "a.yaml"), "w") as f:
            f.write(textwrap.dedent("""
                id: a
                name: A
                steps:
                  - name: s1
                    technique_id: T1558.003
                    detection_profiles: [windows_kerberoast]
            """))
        with open(os.path.join(d, "b.yaml"), "w") as f:
            f.write(textwrap.dedent("""
                id: b
                name: B
                steps:
                  - name: s2
                    technique_id: T1059.001
                    detection_profiles: [windows_encoded_powershell]
            """))
        result = covered_techniques(d)
    assert result == {"T1558.003", "T1059.001"}
