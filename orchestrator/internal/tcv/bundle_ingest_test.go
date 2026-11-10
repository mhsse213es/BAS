package tcv

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// failingQuerier fails every write. Query/QueryRow are never reached by the
// ingest orchestration (the lookup is injected), so they fail loudly if they are.
type failingQuerier struct{}

func (failingQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("write refused")
}
func (failingQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	panic("ingest must not query directly; use the injected lookup")
}
func (failingQuerier) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("ingest must not query directly; use the injected lookup")
}

// The lookup is injected so the orchestration is tested without a database.
// The real lookup (DBVersionLookup) is covered by the database-backed test.
func fakeLookup(known map[string]string) VersionLookup {
	return func(_ context.Context, shas []string) (map[string]string, error) {
		out := map[string]string{}
		for _, s := range shas {
			if v, ok := known[s]; ok {
				out[s] = v
			}
		}
		return out, nil
	}
}

func TestIngestBundleManifest_RecordsMatchedAndReportsUnmatched(t *testing.T) {
	m := testManifest() // aaaa, bbbb match; cccc does not
	lookup := fakeLookup(map[string]string{"aaaa": "cv-a", "bbbb": "cv-b"})

	// Every write fails, which is the log-and-continue path: ingest must still
	// report the unmatched hashes and not abort the whole run.
	recorded, unmatched, err := IngestBundleManifest(context.Background(), failingQuerier{}, lookup, m)
	if err != nil {
		t.Fatalf("IngestBundleManifest returned error for a per-event failure: %v", err)
	}
	if recorded != 0 {
		t.Errorf("recorded = %d, want 0 when every write fails", recorded)
	}
	if len(unmatched) != 1 || unmatched[0] != "cccc" {
		t.Errorf("unmatched = %v, want [cccc]", unmatched)
	}
}

func TestIngestBundleManifest_InvalidManifestFailsBeforeLookup(t *testing.T) {
	m := testManifest()
	m.PackagedAt = time.Time{}
	called := false
	lookup := func(context.Context, []string) (map[string]string, error) {
		called = true
		return nil, nil
	}

	if _, _, err := IngestBundleManifest(context.Background(), failingQuerier{}, lookup, m); err == nil {
		t.Fatal("expected an error for a manifest with zero packaged_at")
	}
	if called {
		t.Error("lookup must not run for an invalid manifest")
	}
}

func TestIngestBundleManifest_LookupErrorIsReturned(t *testing.T) {
	boom := errors.New("db down")
	lookup := func(context.Context, []string) (map[string]string, error) { return nil, boom }

	if _, _, err := IngestBundleManifest(context.Background(), failingQuerier{}, lookup, testManifest()); !errors.Is(err, boom) {
		t.Errorf("err = %v, want the lookup error", err)
	}
}
