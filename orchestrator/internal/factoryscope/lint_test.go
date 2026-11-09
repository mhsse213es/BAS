package factoryscope

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The factory validation lab runs content checks on its own agent every few minutes (scenario_runs.execution_kind =
// 'factory_validation'). Those runs are the product's internal quality loop, not customer assessments. Once they
// leaked into Live Runs and into every figure computed from the runs list. This test makes that hard to repeat:
// every SQL string in non-test code that reads scenario_runs must do one of three things.
//
//  1. exclude factory runs (mention 'factory_validation'), or
//  2. be scoped to one specific run, agent, campaign or sweep (WHERE starts with that predicate), so it cannot list
//     unrelated runs, or
//  3. be on the allowlist below, with the reason it must see every run.
//
// A new query that lists or aggregates runs fails here until its author picks one, on purpose.

var readsRuns = regexp.MustCompile(`(?is)\b(FROM|JOIN)\s+scenario_runs\b`)

// scoped: WHERE begins with an equality on one identifying column (optionally table-aliased).
var scoped = regexp.MustCompile(`(?is)\bWHERE\s+(\w+\.)?(id|campaign_id|sweep_id|em_sweep_id|agent_id)\s*(=\s*\$\d|=\s*ANY\s*\()`)

// allowlist maps "relative/path.go" to why every query in that file may read all runs, factory runs included.
var allowlist = map[string]string{
	"api/liveness.go":                 "reaps stuck and disconnected runs; the lab's runs must be reaped like any other",
	"validationlab/orchestrator.go":   "the lab's own bookkeeping reads its own runs",
	"tcv/reconcile.go":                "reconciles content validations against factory runs on purpose",
	"contentregistry/runs.go":         "content registry run ledger, keyed by content version",
	"contentregistry/legacy_intel.go": "one-off migration of legacy intel runs",
	"db/attempt_context_store.go":     "per-run execution attempt context, keyed by run",
	"db/killchain_proofs.go":          "per-run proofs, keyed by run",
	"db/killchain_groundtruth.go":     "per-run ground truth, keyed by run",
	"verifysync/job.go":               "sync job over runs that have verifications attached",
	"pathcorrelation/runlookup.go":    "looks a run up by the id carried on an alert",
	"emsweep/dispatcher.go":           "sweep dispatcher bookkeeping, keyed by sweep",
	"campaign/store.go":               "campaign store reads the runs of one campaign",
	"api/mtls_context.go":             "ownership check: is any of these run ids another agent's? must see every run",
	"api/revalidation.go":             "looks up the scenario of one finding's last run by id",
	"threatcontent/threatcontent.go":  "the content factory's own run count per content version, validation runs included on purpose",
}

// allowedSnippets exempts a single query, identified by text it contains, where a whole file must not be exempt.
var allowedSnippets = map[string]string{
	"GROUP BY agent_id) sr ON sr.agent_id = a.agent_id":     "per-agent simulation count on the agents list: each agent's own total",
	"WHERE scenario_id = $1 AND agent_id = $2 AND id != $3": "previous run of the same scenario on the same agent, for the trend of one run",
}

func TestEveryRunsQueryExcludesOrScopesFactoryRuns(t *testing.T) {
	root := ".."
	var violations []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if _, ok := allowlist[rel]; ok {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, src, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			sql, uerr := strconv.Unquote(lit.Value)
			if uerr != nil || !readsRuns.MatchString(sql) {
				return true
			}
			if strings.Contains(sql, "factory_validation") || scoped.MatchString(sql) {
				return true
			}
			for snippet := range allowedSnippets {
				if strings.Contains(sql, snippet) {
					return true
				}
			}
			line := fset.Position(lit.Pos()).Line
			violations = append(violations, rel+":"+strconv.Itoa(line))
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Fatalf("these queries read scenario_runs without excluding factory runs or scoping to one run/agent/campaign/sweep.\n"+
			"Add `AND execution_kind <> 'factory_validation'` (customer-facing lists and aggregates), scope the query, or\n"+
			"add the file to the allowlist in factoryscope/lint_test.go with a reason:\n  %s", strings.Join(violations, "\n  "))
	}
}

// An allowed snippet that no longer appears anywhere is dead weight that could later exempt something else.
func TestAllowedSnippetsStillExist(t *testing.T) {
	found := map[string]bool{}
	_ = filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, _ := os.ReadFile(path)
		for snippet := range allowedSnippets {
			if strings.Contains(string(src), snippet) {
				found[snippet] = true
			}
		}
		return nil
	})
	for snippet := range allowedSnippets {
		if !found[snippet] {
			t.Errorf("allowed snippet no longer appears in the code, remove it: %q", snippet)
		}
	}
}

// Every allowlist entry must still name a real file, so the list cannot rot into a blanket exemption.
func TestAllowlistNamesRealFiles(t *testing.T) {
	for rel := range allowlist {
		if _, err := os.Stat(filepath.Join("..", filepath.FromSlash(rel))); err != nil {
			t.Errorf("allowlist entry %q does not exist: %v", rel, err)
		}
	}
}
