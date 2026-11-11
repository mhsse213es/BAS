package contentregistry

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRejectionRecordsExclusionReason covers Gap 3 end to end: the only route to
// REJECTED records a valid code, Transition refuses REJECTED, and the database
// refuses a REJECTED event with no code.
func TestRejectionRecordsExclusionReason(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		vid := mustCreateDraftVersion(t, reg, "user:admin1", "reject-reason-1")

		// Transition must not be able to reject, with or without a reason.
		if err := reg.Transition(ctx, vid, LifecycleRejected, "user:admin1", "free text"); !errors.Is(err, ErrRejectionNeedsReason) {
			t.Fatalf("Transition to REJECTED: got %v, want ErrRejectionNeedsReason", err)
		}

		// RejectVersion refuses a code that is not one of the five.
		if err := reg.RejectVersion(ctx, vid, "user:admin1", ExclusionReason("not a code"), "note"); !errors.Is(err, ErrRejectionNeedsReason) {
			t.Fatalf("RejectVersion with bad code: got %v, want ErrRejectionNeedsReason", err)
		}
		var lc string
		if err := pool.QueryRow(ctx, `SELECT lifecycle FROM content_versions WHERE id = $1`, vid).Scan(&lc); err != nil {
			t.Fatalf("read lifecycle: %v", err)
		}
		if lc != string(LifecycleDraft) {
			t.Fatalf("refused rejections must not change lifecycle: got %s", lc)
		}

		// A valid code is recorded on the event.
		if err := reg.RejectVersion(ctx, vid, "user:admin1", ExclusionRelevance, "outside supported scope"); err != nil {
			t.Fatalf("RejectVersion with valid code: %v", err)
		}
		var code *string
		if err := pool.QueryRow(ctx,
			`SELECT reason_code FROM content_version_events
			 WHERE content_version_id = $1 AND to_lifecycle = 'REJECTED'`, vid,
		).Scan(&code); err != nil {
			t.Fatalf("read reason_code: %v", err)
		}
		if code == nil || *code != string(ExclusionRelevance) {
			t.Fatalf("reason_code = %v, want %q", code, ExclusionRelevance)
		}

		// The database itself refuses a REJECTED event without a code.
		if _, err := pool.Exec(ctx,
			`INSERT INTO content_version_events (content_version_id, from_lifecycle, to_lifecycle, from_trust, to_trust, actor, reason)
			 VALUES ($1, 'DRAFT', 'REJECTED', 'UNTRUSTED', 'UNTRUSTED', 'user:admin1', 'bypass')`, vid,
		); err == nil {
			t.Fatal("database accepted a REJECTED event with no reason_code")
		}
	})
}
