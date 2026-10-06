#!/usr/bin/env python3
"""H1 guardrail: no schema/role DDL in runtime Go code.

Since H1 only `orchestrator migrate` changes the schema (embedded migrations,
seed, role step). This flags DDL, GRANT/REVOKE and TRUNCATE inside Go string
literals anywhere else under orchestrator/. A hit is boot-time DDL that belongs
in a new numbered migration -- never add an allowlist entry for it.

Exempt: *_test.go, internal/db/legacy/ (frozen pre-H1 chain, adoption only),
internal/db/migrate/ (the migrate command), tools/h1-capture-baseline/,
internal/testutil/ (test-only harness; imported only by _test.go files).

Usage: python3 scripts/h1-check-no-runtime-ddl.py [repo_root]
"""
import re
import sys
from pathlib import Path

DDL = re.compile(
    r"(?i:\b(CREATE|ALTER|DROP)\s+(TABLE|INDEX|UNIQUE\s+INDEX|SEQUENCE|TYPE|FUNCTION|TRIGGER|EXTENSION|ROLE|SCHEMA|VIEW)\b)"
    # Uppercase only (this codebase's SQL style): "grant"/"truncate" also occur
    # in English report prose and Go template funcs.
    r"|\bGRANT\s|\bREVOKE\s|\bTRUNCATE\s")
EXEMPT = ("internal/db/legacy/", "internal/db/migrate/", "tools/h1-capture-baseline/",
          "internal/testutil/")  # test-only harness, never linked into the server


def literals(src):
    """Yield (start_line, text) for every Go string literal, skipping comments and runes."""
    i, line, n = 0, 1, len(src)
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
        elif src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += src.count("\n", i, j)
            i = j
        elif c == "`":
            j = src.find("`", i + 1)
            j = n if j < 0 else j
            yield line, src[i + 1:j]
            line += src.count("\n", i, j)
            i = j + 1
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            if c == '"':
                yield line, src[i + 1:j]
            i = j + 1
        else:
            i += 1


def scan(root):
    hits = []
    base = Path(root) / "orchestrator"
    for f in sorted(base.rglob("*.go")):
        rel = f.relative_to(base).as_posix()
        if rel.endswith("_test.go") or rel.startswith(EXEMPT):
            continue
        src = f.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        for start, text in literals(src):
            for m in DDL.finditer(text):
                hits.append((str(f), start + text.count("\n", 0, m.start()), m.group(0).strip()))
    return hits


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    hits = scan(root)
    for f, n, what in hits:
        print(f"{f}:{n}: runtime DDL '{what}' -- move it into a new migration (H1)")
    if hits:
        return 1
    print("h1-check-no-runtime-ddl: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
