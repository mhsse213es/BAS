"""Coverage gate: every internal/ package over THRESHOLD non-blank lines of
non-test Go must have at least one _test.go file. Stdlib only.
Usage: python3 scripts/check-package-tests.py [orchestrator_dir]"""
import sys
from pathlib import Path

THRESHOLD = 200
ROOT_PKG = "internal"


def check(orch, threshold=THRESHOLD):
    base = Path(orch) / ROOT_PKG
    dirs = sorted({p.parent for p in base.rglob("*.go") if not p.name.endswith("_test.go")})
    failures = []
    for d in dirs:
        src = [p for p in d.glob("*.go") if not p.name.endswith("_test.go")]
        lines = sum(1 for p in src for line in p.read_text(encoding="utf-8").splitlines() if line.strip())
        has_tests = any(d.glob("*_test.go"))
        if lines > threshold and not has_tests:
            failures.append(f"{d.relative_to(orch).as_posix()}: {lines} lines, no tests")
    return failures


def main():
    orch = Path(sys.argv[1] if len(sys.argv) > 1 else "orchestrator")
    failures = check(orch)
    if failures:
        print("package test gate: FAIL")
        for f in failures:
            print(f"  {f}")
        return 1
    print("package test gate: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
