package verification

import (
	"context"
	"errors"
	"flag"
	"os"
	"testing"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestAttest_DefaultsWorkflowStateAndSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		rec, err := store.Attest(context.Background(), AttestInput{
			RunID: "run-1", ExpectationID: "exp-1", VerifiedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if rec.WorkflowState != StateApproved {
			t.Fatalf("WorkflowState = %q, want %q", rec.WorkflowState, StateApproved)
		}
		if rec.Source != SourceManual {
			t.Fatalf("Source = %q, want %q", rec.Source, SourceManual)
		}
		if rec.SupersedesID != "" {
			t.Fatalf("SupersedesID = %q, want empty for first attestation", rec.SupersedesID)
		}
		if !rec.Active {
			t.Fatal("expected Active = true")
		}
	})
}

func TestAttest_PersistsRuleIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		rec, err := store.Attest(context.Background(), AttestInput{
			RunID: "run-rule-1", ExpectationID: "exp-rule-1", VerifiedBy: "alice",
			RuleIDs: []string{"AUDRULE-000001", "AUDRULE-000002"},
		})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if len(rec.RuleIDs) != 2 || rec.RuleIDs[0] != "AUDRULE-000001" || rec.RuleIDs[1] != "AUDRULE-000002" {
			t.Fatalf("rec.RuleIDs = %v, want [AUDRULE-000001 AUDRULE-000002]", rec.RuleIDs)
		}

		// Round-trip through a fresh read, not just the RETURNING clause.
		reread, err := store.CurrentForRun(context.Background(), "run-rule-1")
		if err != nil {
			t.Fatalf("CurrentForRun: %v", err)
		}
		if len(reread["exp-rule-1"].RuleIDs) != 2 {
			t.Fatalf("reread RuleIDs = %v, want 2 entries", reread["exp-rule-1"].RuleIDs)
		}
	})
}

func TestAttest_NilRuleIDsDoesNotViolateNotNull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		// RuleIDs deliberately left nil (zero value) — must not violate the
		// rule_ids text[] NOT NULL column constraint.
		rec, err := store.Attest(context.Background(), AttestInput{
			RunID: "run-rule-2", ExpectationID: "exp-rule-2", VerifiedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Attest with nil RuleIDs: %v", err)
		}
		if len(rec.RuleIDs) != 0 {
			t.Fatalf("rec.RuleIDs = %v, want empty", rec.RuleIDs)
		}
	})
}

func TestCurrentApprovedForRun_OnlyApprovedRegardlessOfResult(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		if _, err := store.Attest(ctx, AttestInput{
			RunID: "run-approved-1", ExpectationID: "exp-approved-detected",
			Result: ResultDetected, WorkflowState: StateApproved, VerifiedBy: "analyst",
		}); err != nil {
			t.Fatalf("seed approved/detected: %v", err)
		}
		if _, err := store.Attest(ctx, AttestInput{
			RunID: "run-approved-1", ExpectationID: "exp-approved-notdetected",
			Result: ResultNotDetected, WorkflowState: StateApproved, VerifiedBy: "analyst",
		}); err != nil {
			t.Fatalf("seed approved/notdetected: %v", err)
		}
		if _, err := store.Attest(ctx, AttestInput{
			RunID: "run-approved-1", ExpectationID: "exp-pending",
			Result: ResultDetected, WorkflowState: StatePending, VerifiedBy: "analyst",
		}); err != nil {
			t.Fatalf("seed pending: %v", err)
		}

		got, err := store.CurrentApprovedForRun(ctx, "run-approved-1")
		if err != nil {
			t.Fatalf("CurrentApprovedForRun: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("len(got) = %d, want 2 (both Approved rows, regardless of Result; Pending excluded)", len(got))
		}
		byExp := map[string]Record{}
		for _, r := range got {
			byExp[r.ExpectationID] = r
		}
		if _, ok := byExp["exp-approved-detected"]; !ok {
			t.Error("missing exp-approved-detected")
		}
		if _, ok := byExp["exp-approved-notdetected"]; !ok {
			t.Error("missing exp-approved-notdetected")
		}
		if _, ok := byExp["exp-pending"]; ok {
			t.Error("exp-pending (WorkflowState=Pending) must be excluded")
		}
	})
}

func TestAttest_SecondAttestationSupersedesFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		first, err := store.Attest(ctx, AttestInput{
			RunID: "run-2", ExpectationID: "exp-2", Result: ResultDetected, VerifiedBy: "alice",
		})
		if err != nil {
			t.Fatalf("first Attest: %v", err)
		}

		second, err := store.Attest(ctx, AttestInput{
			RunID: "run-2", ExpectationID: "exp-2", Result: ResultNotDetected, VerifiedBy: "bob",
		})
		if err != nil {
			t.Fatalf("second Attest: %v", err)
		}

		if second.SupersedesID != first.ID {
			t.Fatalf("second.SupersedesID = %q, want %q", second.SupersedesID, first.ID)
		}
		if !second.Active {
			t.Fatal("expected second record to be Active")
		}

		reloadedFirst, ok, err := store.Get(ctx, first.ID)
		if err != nil || !ok {
			t.Fatalf("Get(first.ID): ok=%v err=%v", ok, err)
		}
		if reloadedFirst.Active {
			t.Fatal("expected first record to be superseded (Active=false)")
		}

		history, err := store.History(ctx, "run-2", "exp-2")
		if err != nil {
			t.Fatalf("History: %v", err)
		}
		if len(history) != 2 {
			t.Fatalf("History returned %d records, want 2", len(history))
		}
		if history[0].ID != second.ID {
			t.Fatalf("History[0].ID = %q, want newest (%q) first", history[0].ID, second.ID)
		}
	})
}

func TestCurrentForRun_OnlyActiveRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		if _, err := store.Attest(ctx, AttestInput{RunID: "run-3", ExpectationID: "exp-a", VerifiedBy: "alice"}); err != nil {
			t.Fatalf("Attest exp-a: %v", err)
		}
		if _, err := store.Attest(ctx, AttestInput{RunID: "run-3", ExpectationID: "exp-b", VerifiedBy: "alice"}); err != nil {
			t.Fatalf("Attest exp-b: %v", err)
		}
		if _, err := store.Attest(ctx, AttestInput{RunID: "run-3", ExpectationID: "exp-a", VerifiedBy: "bob"}); err != nil {
			t.Fatalf("supersede exp-a: %v", err)
		}

		current, err := store.CurrentForRun(ctx, "run-3")
		if err != nil {
			t.Fatalf("CurrentForRun: %v", err)
		}
		if len(current) != 2 {
			t.Fatalf("CurrentForRun returned %d entries, want 2", len(current))
		}
		if current["exp-a"].VerifiedBy != "bob" {
			t.Fatalf("exp-a.VerifiedBy = %q, want bob (the superseding attestation)", current["exp-a"].VerifiedBy)
		}
	})
}

func TestGet_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		_, ok, err := store.Get(context.Background(), "does-not-exist")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if ok {
			t.Fatal("expected ok=false for missing id")
		}
	})
}

func TestIsUniqueViolation(t *testing.T) {
	if isUniqueViolation(errors.New("plain error")) {
		t.Fatal("plain error should not be a unique violation")
	}
	if isUniqueViolation(pgx.ErrNoRows) {
		t.Fatal("pgx.ErrNoRows should not be a unique violation")
	}
	if !isUniqueViolation(fakeSQLStateErr{state: "23505"}) {
		t.Fatal("23505 SQLSTATE should be detected as a unique violation")
	}
	if isUniqueViolation(fakeSQLStateErr{state: "23503"}) {
		t.Fatal("23503 (foreign key violation) should not match unique violation")
	}
}

type fakeSQLStateErr struct{ state string }

func (e fakeSQLStateErr) Error() string    { return "fake: " + e.state }
func (e fakeSQLStateErr) SQLState() string { return e.state }
