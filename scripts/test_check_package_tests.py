import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("cpt", REPO_ROOT / "scripts" / "check-package-tests.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def pkg(root, rel, lines, tests=False):
    d = Path(root) / "internal" / rel
    d.mkdir(parents=True, exist_ok=True)
    (d / "a.go").write_text("\n".join(["package x"] + [f"var v{i} = {i}" for i in range(lines - 1)]) + "\n", encoding="utf-8")
    if tests:
        (d / "a_test.go").write_text("package x\n", encoding="utf-8")


class TestPackageTestGate(unittest.TestCase):
    def test_large_untested_package_fails(self):
        root = tempfile.mkdtemp()
        pkg(root, "siem", 300)
        self.assertEqual(gate.check(root), ["internal/siem: 300 lines, no tests"])

    def test_large_tested_package_passes(self):
        root = tempfile.mkdtemp()
        pkg(root, "siem", 300, tests=True)
        self.assertEqual(gate.check(root), [])

    def test_small_untested_package_passes(self):
        root = tempfile.mkdtemp()
        pkg(root, "helper", 200)
        self.assertEqual(gate.check(root), [])

    def test_blank_lines_do_not_count(self):
        root = tempfile.mkdtemp()
        d = Path(root) / "internal" / "sparse"
        d.mkdir(parents=True)
        (d / "a.go").write_text("package x\n" + "\n" * 500, encoding="utf-8")
        self.assertEqual(gate.check(root), [])

    def test_packages_outside_internal_are_not_gated(self):
        root = tempfile.mkdtemp()
        d = Path(root) / "cmd" / "tool"
        d.mkdir(parents=True)
        (d / "main.go").write_text("\n".join(["package main"] + ["var x = 1"] * 400), encoding="utf-8")
        self.assertEqual(gate.check(root), [])


if __name__ == "__main__":
    unittest.main()
