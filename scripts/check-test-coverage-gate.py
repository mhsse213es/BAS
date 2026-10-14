#!/usr/bin/env python3
"""Group I (AUDSPECT_ASSESSMENT_REPORT.md), I2's root-cause fix: "add a
coverage gate in CI so no package ships large + untested again." internal/
siem was 446 LOC with zero test files before this gate existed.

Reads the coverage profile `go test ./... -coverprofile=coverage.out`
already produces (CI's own "go test (race + coverage)" step), aggregates
statement counts per Go package, and fails if any package with more than
MIN_STATEMENTS_TO_FLAG statements has 0% of them covered. This only catches
the exact failure mode the report found -- a sizeable package with NO tests
at all -- not an across-the-board minimum-percentage mandate, which would
block unrelated work on partially-covered packages for reasons this gate
was never meant to enforce.

Usage: python3 scripts/check-test-coverage-gate.py [coverage.out]
"""
import re
import sys

MIN_STATEMENTS_TO_FLAG = 40

# coverage.out line shape (set/count mode):
#   <file>:<start line>.<start col>,<end line>.<end col> <numstmt> <count>
LINE_RE = re.compile(r"^(\S+):\d+\.\d+,\d+\.\d+ (\d+) (\d+)$")


def package_of(file_path: str) -> str:
    # Drop the filename, keep the directory as the package key -- e.g.
    # github.com/audspect/bas/internal/siem/qradar.go -> .../internal/siem.
    return file_path.rsplit("/", 1)[0]


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "orchestrator/coverage.out"
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"::error::coverage profile not found at {path} -- "
              f"run `go test ./... -coverprofile=coverage.out` first")
        return 1

    totals: dict[str, list[int]] = {}  # package -> [total statements, covered statements]
    for line in lines[1:]:  # skip the "mode: ..." header
        line = line.strip()
        if not line:
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        file_path, numstmt, count = m.group(1), int(m.group(2)), int(m.group(3))
        pkg = package_of(file_path)
        totals.setdefault(pkg, [0, 0])
        totals[pkg][0] += numstmt
        if count > 0:
            totals[pkg][1] += numstmt

    violations = []
    for pkg, (total, covered) in sorted(totals.items()):
        if total > MIN_STATEMENTS_TO_FLAG and covered == 0:
            violations.append((pkg, total))

    if violations:
        print("::error::Packages with no test coverage at all (sizeable, 0% covered):")
        for pkg, total in violations:
            print(f"::error::  {pkg} -- {total} statements, 0 covered")
        print(f"\nEach package above {MIN_STATEMENTS_TO_FLAG} statements needs at least "
              f"some test coverage. Add tests, or if the package is genuinely untestable "
              f"(e.g. pure wiring with no branches), keep it under the threshold by "
              f"splitting out the logic that IS testable.")
        return 1

    print("check-test-coverage-gate: OK -- no sizeable package is at 0% coverage.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
