package exercise

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEvidenceChain_AppendBuildsHashChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := seedExecution(t, store)

		var prevHash string
		for i := 1; i <= 3; i++ {
			payload := map[string]any{"i": i}
			ev, err := chain.Append(ctx, execID, "se1", "email_sent", "system", "test", payload)
			if err != nil {
				t.Fatalf("Append %d: %v", i, err)
			}
			if ev.Seq != int64(i) {
				t.Fatalf("record %d seq = %d, want %d", i, ev.Seq, i)
			}
			if ev.PrevHash != prevHash {
				t.Fatalf("record %d prev_hash = %q, want %q", i, ev.PrevHash, prevHash)
			}
			// Recompute the chained hash the same way evidence.go does.
			pb, _ := json.Marshal(payload)
			ph := sha256.Sum256(pb)
			payHash := hex.EncodeToString(ph[:])
			combined := sha256.Sum256([]byte(payHash + prevHash))
			want := hex.EncodeToString(combined[:])
			if ev.SHA256 != want {
				t.Fatalf("record %d sha256 = %q, want %q", i, ev.SHA256, want)
			}
			prevHash = ev.SHA256
		}
	})
}

func TestEvidenceChain_VerifyIntactAndTampered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := seedExecution(t, store)

		for i := 1; i <= 3; i++ {
			if _, err := chain.Append(ctx, execID, "se1", "email_sent", "system", "test", map[string]any{"i": i}); err != nil {
				t.Fatalf("Append %d: %v", i, err)
			}
		}
		if err := chain.Verify(ctx, execID); err != nil {
			t.Fatalf("intact chain should verify, got %v", err)
		}

		// Tamper: mutate the payload of the seq-2 record directly in the DB.
		if _, err := pool.Exec(ctx,
			`UPDATE exercise_evidence SET payload_json = $1 WHERE execution_id=$2 AND seq=2`,
			[]byte(`{"i":999}`), execID); err != nil {
			t.Fatalf("tamper update: %v", err)
		}
		err := chain.Verify(ctx, execID)
		if err == nil {
			t.Fatal("tampered chain must fail Verify")
		}
		if !strings.Contains(err.Error(), "seq 2") {
			t.Fatalf("Verify error should name the tampered seq, got %v", err)
		}
	})
}

func TestEvidenceChain_RecordAdapter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		chain := NewEvidenceChain(store)
		execID := seedExecution(t, store)
		if err := chain.Record(context.Background(), execID, "se1", "link_clicked", "target", "tracker", map[string]any{"ok": true}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	})
}
