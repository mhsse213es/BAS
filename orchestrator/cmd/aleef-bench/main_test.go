package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/aleef/bank"
	"github.com/audspect/bas/internal/aleef/bench"
)

// Synthetic ids only.
var synth = []bench.Label{{ID: "T1", Operation: "a"}, {ID: "T2", Operation: "b"}}

func TestComposePolicyRefusesWhenSealedUnavailable(t *testing.T) {
	_, err := composePolicy(synth, func(string) (bank.Policy, bool) { return bank.FixedPolicy(), false })
	if err == nil || !strings.Contains(err.Error(), "aleefsealed") {
		t.Fatalf("want refusal naming the build tag, got %v", err)
	}
}

func TestComposePolicyMergesDisjointHooksGenerically(t *testing.T) {
	lookup := func(id string) (bank.Policy, bool) {
		p := bank.FixedPolicy()
		switch id {
		case "T1":
			p.CanReadAccount = func(bank.Principal, string) bool { return true }
		case "T2":
			p.CanSettle = func(bank.Payment) bool { return true }
		}
		return p, true
	}
	m, err := composePolicy(synth, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if !m.CanReadAccount(bank.Principal{ID: "x"}, "y") || !m.CanSettle(bank.Payment{}) {
		t.Fatal("replaced hooks not merged")
	}
	if m.CanApprove == nil || m.LegacyAuthorize(bank.Principal{ID: "x"}, "account", "y") {
		t.Fatal("untouched hooks must stay fixed")
	}
}

func TestComposePolicyRejectsConflictsAndNoOps(t *testing.T) {
	same := func(id string) (bank.Policy, bool) {
		p := bank.FixedPolicy()
		p.CanReadAccount = func(bank.Principal, string) bool { return true }
		return p, true
	}
	if _, err := composePolicy(synth, same); err == nil {
		t.Fatal("two ids replacing one hook must be refused")
	}
	if _, err := composePolicy(synth, func(string) (bank.Policy, bool) { return bank.FixedPolicy(), true }); err == nil {
		t.Fatal("a policy identical to the fixed one must be refused")
	}
}

func TestRunRequiresLabelsUnlessFixedOnly(t *testing.T) {
	if err := run(nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "-labels") {
		t.Fatalf("want labels error, got %v", err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "labels.json")
	_ = os.WriteFile(p, []byte(`[{"id":"T1","operation":"a"}]`), 0o600)
	if err := run([]string{"-labels", p}, &bytes.Buffer{}); err == nil {
		t.Fatal("default build must refuse before running")
	}
}

func TestClassifyUsesDeclarativeTableOnly(t *testing.T) {
	// reads are classified by method, everything else only via the table
	if opClass["GET /v2/accounts/{id}"] != "" {
		t.Fatal("reads must not be listed individually")
	}
	for k := range opClass {
		if strings.HasPrefix(k, "GET ") {
			t.Fatalf("table lists a read: %s", k)
		}
	}
}

// Needs Docker (throwaway Postgres). Skipped with -short.
func TestFixedOnlyRehearsalEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("needs Docker")
	}
	var out bytes.Buffer
	if err := run([]string{"-fixed-only"}, &out); err != nil {
		t.Fatal(err)
	}
	md := out.String()
	for _, want := range []string{"Verified findings: 0 (must be 0)", "| cleanup_left_no_objects | PASS |", "| no_prod_target | PASS |"} {
		if !strings.Contains(md, want) {
			t.Fatalf("report lacks %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "0 (NO TESTS") {
		t.Fatalf("an operation the declared fixtures can cover has no tests:\n%s", md)
	}
	if strings.Contains(md, "unconfirmed: cleanup failed") {
		t.Fatalf("cleanup failures:\n%s", md)
	}
}
