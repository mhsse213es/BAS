import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "h1ddl", os.path.join(os.path.dirname(__file__), "h1-check-no-runtime-ddl.py"))
h1ddl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h1ddl)


def tree(files):
    d = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = d / "orchestrator" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return d


class TestScan(unittest.TestCase):
    def test_flags_runtime_ddl_in_backtick_and_quoted_literals(self):
        d = tree({
            "internal/api/x.go": "package api\nvar a = `CREATE TABLE t (id int)`\nvar b = \"ALTER ROLE bas_app PASSWORD 'x'\"\n",
            "internal/api/y.go": "package api\nvar c = `GRANT SELECT ON t TO bas_app`\nvar e = `drop index i`\n",
        })
        hits = h1ddl.scan(d)
        self.assertEqual(sorted((Path(f).name, n) for f, n, _ in hits),
                         [("x.go", 2), ("x.go", 3), ("y.go", 2), ("y.go", 3)])

    def test_multiline_literal_reports_the_statement_line(self):
        d = tree({"internal/api/m.go": "package api\nvar q = `\n  SELECT 1;\n  CREATE INDEX i ON t (id)`\n"})
        self.assertEqual([n for _, n, _ in h1ddl.scan(d)], [4])

    def test_allowed_locations_and_non_ddl_are_ignored(self):
        ddl = "package p\nvar a = `CREATE TABLE t (id int)`\nvar b = `REVOKE ALL ON t FROM x`\n"
        d = tree({
            "internal/db/legacy/a.go": ddl,
            "internal/db/migrate/a.go": ddl,
            "tools/h1-capture-baseline/main.go": ddl,
            "internal/api/a_test.go": ddl,
            "internal/testutil/db.go": "package testutil\nvar t = `TRUNCATE TABLE x CASCADE`\n",
            "internal/api/ok.go": "package api\n// CREATE TABLE in a comment\nvar q = `SELECT created FROM t WHERE grant_id = $1`\nvar s = \"drop\"\n",
            # English prose and template funcs are not SQL (real hits in internal/reporting).
            "internal/reporting/r.go": "package reporting\nvar a = \"Harvested credentials grant silent access\"\nvar b = `{{truncate .SHA256 20}}`\n",
        })
        self.assertEqual(h1ddl.scan(d), [])


if __name__ == "__main__":
    unittest.main()
