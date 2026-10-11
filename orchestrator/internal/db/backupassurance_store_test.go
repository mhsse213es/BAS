package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/backupassurance"
	"github.com/audspect/bas/internal/db"
)

func sixPassingResults() []backupassurance.CheckResult {
	out := make([]backupassurance.CheckResult, 0, 6)
	for _, c := range []backupassurance.Check{
		backupassurance.CheckDeletionProtection, backupassurance.CheckImmutability, backupassurance.CheckOfflineIsolation,
		backupassurance.CheckPrivilegeSeparation, backupassurance.CheckRestoreIntegrity, backupassurance.CheckRPORTO,
	} {
		out = append(out, backupassurance.CheckResult{Check: c, Verdict: "PASS", Simulated: true, Observer: "fake:test-v1"})
	}
	return out
}

func TestWriteBackupAssuranceAssessment_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		assessmentID, err := db.WriteBackupAssuranceAssessment(context.Background(), pool, sixPassingResults())
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		if assessmentID == "" {
			t.Fatal("assessmentID is empty, want a fresh non-empty ID")
		}
		got, err := db.ReadBackupAssuranceAssessment(context.Background(), pool, assessmentID)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(got) != 6 {
			t.Fatalf("got %d results, want 6", len(got))
		}
	})
}

func TestWriteBackupAssuranceAssessment_RejectsInvalidSkipPairBeforeOpeningTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		bad := sixPassingResults()
		bad[0].Verdict = "SKIPPED" // no SkipReason set -- invalid pair
		_, err := db.WriteBackupAssuranceAssessment(context.Background(), pool, bad)
		if err == nil {
			t.Fatal("err = nil, want a validation error for an invalid Verdict/SkipReason pair")
		}
	})
}

func TestWriteBackupAssuranceAssessment_MidTransactionFailureLeavesZeroRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var before int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM backup_assurance_results`).Scan(&before); err != nil {
			t.Fatalf("count before: %v", err)
		}

		// An empty check_name would NOT violate the NOT NULL constraint (an
		// empty string is still non-null), so that can't force a real
		// mid-transaction failure. Instead duplicate check 3's name onto
		// check 4: both land under the SAME freshly-minted assessment_id
		// inside the same transaction, so the 4th insert collides with the
		// UNIQUE(assessment_id, check_name) constraint the 3rd insert just
		// satisfied -- a genuine SQL-level failure partway through the 6.
		bad := sixPassingResults()
		bad[3].Check = bad[2].Check
		_, err := db.WriteBackupAssuranceAssessment(context.Background(), pool, bad)
		if err == nil {
			t.Fatal("err = nil, want a write failure from the duplicate check_name within one assessment")
		}

		var after int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM backup_assurance_results`).Scan(&after); err != nil {
			t.Fatalf("count after: %v", err)
		}
		if after != before {
			t.Fatalf("row count changed from %d to %d -- a failed write must leave zero new rows, not a partial 3-of-6 assessment", before, after)
		}
	})
}

func TestReadBackupAssuranceAssessment_NonexistentIDReturnsNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.ReadBackupAssuranceAssessment(context.Background(), pool, "does-not-exist")
		if !errors.Is(err, db.ErrAssessmentNotFound) {
			t.Fatalf("err = %v, want ErrAssessmentNotFound", err)
		}
	})
}

func TestReadBackupAssuranceAssessment_IncompleteRowCountIsDataIntegrityError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		assessmentID, err := db.WriteBackupAssuranceAssessment(context.Background(), pool, sixPassingResults())
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		// Simulate corruption: delete one of the 6 rows directly.
		if _, err := pool.Exec(context.Background(), `DELETE FROM backup_assurance_results WHERE assessment_id = $1 AND check_name = 'rpo_rto'`, assessmentID); err != nil {
			t.Fatalf("corrupt: %v", err)
		}
		_, err = db.ReadBackupAssuranceAssessment(context.Background(), pool, assessmentID)
		if !errors.Is(err, db.ErrAssessmentIncomplete) {
			t.Fatalf("err = %v, want ErrAssessmentIncomplete for a 5-of-6 row count", err)
		}
	})
}

func TestBackupAssuranceResults_DatabaseRejectsSimulatedFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := pool.Exec(context.Background(), `
			INSERT INTO backup_assurance_results (assessment_id, check_name, verdict, simulated, observer)
			VALUES ('ba-direct-insert-test', 'deletion_protection', 'PASS', FALSE, 'direct-insert')`)
		if err == nil {
			t.Fatal("direct insert with simulated=FALSE succeeded, want the database's own CHECK (simulated = TRUE) to reject it")
		}
	})
}
