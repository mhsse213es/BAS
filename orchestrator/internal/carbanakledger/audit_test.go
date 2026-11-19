package carbanakledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var auditT0 = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)

func openLog(t *testing.T, path string) *Log {
	t.Helper()
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return l
}

func appendThree(t *testing.T, l *Log) {
	t.Helper()
	steps := []struct {
		step, action string
		d            Decision
		rule         string
	}{
		{"8a", "session", Approved, ""},
		{"8b", "beneficiary", Rejected, "beneficiary_second_approver_missing"},
		{"8c", "transfer", Flagged, "amount_over_limit"},
	}
	for _, s := range steps {
		if _, err := l.Append("run-1", s.step, "op1", s.action, s.d, s.rule, auditT0); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
}

func TestAuditChainVerifiesAfterAppends(t *testing.T) {
	l := openLog(t, filepath.Join(t.TempDir(), "audit.jsonl"))
	appendThree(t, l)
	intact, bad := l.Verify()
	if !intact {
		t.Fatalf("fresh chain reported tampered at row %d", bad)
	}
}

func TestAuditChainDetectsTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openLog(t, path)
	appendThree(t, l)

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(b), `"decision":"rejected"`, `"decision":"approved"`, 1)
	if mutated == string(b) {
		t.Fatal("test setup: decision not found to mutate")
	}
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}

	l2 := openLog(t, path)
	intact, bad := l2.Verify()
	if intact {
		t.Fatal("tampered row was not detected")
	}
	if bad != 1 {
		t.Fatalf("first bad row = %d, want 1 (the mutated 8b row)", bad)
	}
}

func TestAuditLogSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openLog(t, path)
	appendThree(t, l)

	l2 := openLog(t, path)
	rows := l2.Rows("run-1")
	if len(rows) != 3 {
		t.Fatalf("reopened log has %d rows, want 3", len(rows))
	}
	if intact, _ := l2.Verify(); !intact {
		t.Fatal("reopened chain does not verify")
	}
	if _, err := l2.Append("run-1", "8d", "op1", "approve", Rejected, "maker_checker_self_approval", auditT0); err != nil {
		t.Fatalf("Append after restart: %v", err)
	}
	if intact, _ := openLog(t, path).Verify(); !intact {
		t.Fatal("chain broken by append after restart")
	}
}

func TestAuditIsDeterministicWithFixedTime(t *testing.T) {
	a := openLog(t, filepath.Join(t.TempDir(), "a.jsonl"))
	b := openLog(t, filepath.Join(t.TempDir(), "b.jsonl"))
	appendThree(t, a)
	appendThree(t, b)
	ra, rb := a.Rows("run-1"), b.Rows("run-1")
	for i := range ra {
		if ra[i].Hash != rb[i].Hash {
			t.Fatalf("row %d hash differs across identical runs", i)
		}
	}
}
