package auditpurge_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auditarchive"
	"github.com/audspect/bas/internal/auditpurge"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

const testPurgePassword = "purge-pw-testing-only"

type memRecorder struct{ details []map[string]any }

func (r *memRecorder) Record(_ context.Context, d map[string]any) error {
	r.details = append(r.details, d)
	return nil
}

func purgerPool(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	cfg := admin.Config().Copy()
	cfg.ConnConfig.User = "bas_audit_purger"
	cfg.ConnConfig.Password = testPurgePassword
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// seedAudit inserts an audit row whose timestamp is ageDays before now.
func seedAudit(t *testing.T, pool *pgxpool.Pool, action string, ageDays int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO audit_logs (ts, action, resource, detail) VALUES (NOW() - make_interval(days => $1), $2, 'r', '{"k":1}')`,
		ageDays, action); err != nil {
		t.Fatal(err)
	}
}

func countAudit(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func setup(t *testing.T, pool *pgxpool.Pool) (*pgxpool.Pool, *rsa.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	if err := db.EnsurePurgeRole(ctx, pool, testPurgePassword); err != nil {
		t.Fatal(err)
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return purgerPool(t, pool), k
}

// Rows older than the maximum are archived, verified and deleted. Rows inside the window stay.
func TestRun_ArchivesThenDeletesOnlyEligibleRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(admin *pgxpool.Pool) {
		p, k := setup(t, admin)
		seedAudit(t, admin, "old-400", 400)
		seedAudit(t, admin, "old-370", 370)
		seedAudit(t, admin, "kept-100", 100)
		seedAudit(t, admin, "kept-10", 10)
		dir := t.TempDir()
		rec := &memRecorder{}
		cfg := auditpurge.Config{Enabled: true, MaxRetentionDays: 365, BatchSize: 1, ArchiveDir: dir}

		n, err := auditpurge.Run(context.Background(), p, cfg, k, rec, time.Now())
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if n != 2 {
			t.Fatalf("purged %d rows, want 2", n)
		}
		if got := countAudit(t, admin); got != 2 {
			t.Fatalf("%d rows left, want 2 (the 100- and 10-day rows)", got)
		}
		if len(rec.details) != 2 {
			t.Fatalf("recorded %d batches, want one record per batch (2)", len(rec.details))
		}
		// Every archived batch re-verifies from disk with the public key.
		matches, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
		if len(matches) != 2 {
			t.Fatalf("%d archive files, want 2", len(matches))
		}
		for _, f := range matches {
			body, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			mb, err := os.ReadFile(f[:len(f)-len(".jsonl")] + ".manifest.json")
			if err != nil {
				t.Fatal(err)
			}
			var m auditarchive.Manifest
			if err := json.Unmarshal(mb, &m); err != nil {
				t.Fatal(err)
			}
			if err := auditarchive.Verify(body, m, &k.PublicKey); err != nil {
				t.Errorf("archive %s does not verify: %v", f, err)
			}
		}
	})
}

// If the archive cannot be written, no row is deleted.
func TestRun_AbortsDeletionWhenArchiveFails(t *testing.T) {
	sharedDB.RunWithPool(t, func(admin *pgxpool.Pool) {
		p, k := setup(t, admin)
		seedAudit(t, admin, "old-400", 400)
		seedAudit(t, admin, "old-390", 390)
		cfg := auditpurge.Config{Enabled: true, MaxRetentionDays: 365, BatchSize: 10,
			ArchiveDir: filepath.Join(t.TempDir(), "does-not-exist")}

		if _, err := auditpurge.Run(context.Background(), p, cfg, k, &memRecorder{}, time.Now()); err == nil {
			t.Fatal("Run must fail when the archive directory is missing")
		}
		if got := countAudit(t, admin); got != 2 {
			t.Fatalf("%d rows left after a failed archive, want 2 (nothing deleted)", got)
		}
	})
}

// A purge stopped after one batch resumes on the next run and deletes nothing it has not archived.
func TestRun_ResumesAfterInterruption(t *testing.T) {
	sharedDB.RunWithPool(t, func(admin *pgxpool.Pool) {
		p, k := setup(t, admin)
		for i := 0; i < 4; i++ {
			seedAudit(t, admin, "old", 400)
		}
		seedAudit(t, admin, "kept", 10)
		dir := t.TempDir()
		ctx := context.Background()

		first := auditpurge.Config{Enabled: true, MaxRetentionDays: 365, BatchSize: 2, MaxBatches: 1, ArchiveDir: dir}
		if n, err := auditpurge.Run(ctx, p, first, k, &memRecorder{}, time.Now()); err != nil || n != 2 {
			t.Fatalf("first run purged %d (err %v), want 2", n, err)
		}
		rest := auditpurge.Config{Enabled: true, MaxRetentionDays: 365, BatchSize: 2, ArchiveDir: dir}
		if n, err := auditpurge.Run(ctx, p, rest, k, &memRecorder{}, time.Now()); err != nil || n != 2 {
			t.Fatalf("resumed run purged %d (err %v), want 2", n, err)
		}
		if got := countAudit(t, admin); got != 1 {
			t.Fatalf("%d rows left, want only the 10-day row", got)
		}
	})
}

// Purging is off unless enabled: nothing is deleted.
func TestRun_DisabledByDefaultDeletesNothing(t *testing.T) {
	sharedDB.RunWithPool(t, func(admin *pgxpool.Pool) {
		p, k := setup(t, admin)
		seedAudit(t, admin, "old", 400)
		n, err := auditpurge.Run(context.Background(), p, auditpurge.Config{MaxRetentionDays: 365, ArchiveDir: t.TempDir()}, k, &memRecorder{}, time.Now())
		if err != nil || n != 0 {
			t.Fatalf("disabled purge: purged %d (err %v), want 0", n, err)
		}
		if got := countAudit(t, admin); got != 1 {
			t.Fatalf("%d rows left, want 1", got)
		}
	})
}
