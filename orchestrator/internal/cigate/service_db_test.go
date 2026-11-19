package cigate

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

type fakeDispatcher struct {
	runID, skip string
	gotName     string
	gotAgent    string
	calls       int
}

func (f *fakeDispatcher) DispatchFactoryValidation(_ context.Context, sc *scenario.Scenario, agentID string) (string, string, error) {
	f.calls++
	f.gotName, f.gotAgent = sc.Name, agentID
	return f.runID, f.skip, nil
}

func artifact(id, name string) []byte {
	return []byte("id: " + id + "\nname: " + name + "\nsteps:\n  - {name: a, technique_id: T1082, framework: custom, command: x}\n")
}

// seedVersion writes one content version the way migration-era rows were written, with an explicit version number
// and lifecycle, so a test can set up "newest version" and "retired" cases.
func seedVersion(t *testing.T, pool *pgxpool.Pool, id string, version int, lifecycle string, art []byte) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO scenarios (scenario_id, origin) VALUES ($1, 'LOCAL') ON CONFLICT DO NOTHING`, id); err != nil {
		t.Fatalf("seed scenarios row: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO content_versions
		(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes, trust_level, lifecycle, intake_source, schema_version, created_by)
		VALUES ($1, 'LOCAL', $2::int, 'sha-'||$1||'-'||$2::int::text, octet_length($3::bytea), $3::bytea, 'UNTRUSTED', $4, 'custom', 1, 'intake')`,
		id, version, art, lifecycle); err != nil {
		t.Fatalf("seed content_versions row: %v", err)
	}
}

func newService(pool *pgxpool.Pool, d Dispatcher) *Service {
	return NewService(pool, contentregistry.New(pool, testutil.DevVerifier()), d, "lab-agent")
}

func TestService_StartValidatesTheNewestVersionOfAContentId(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedVersion(t, pool, "ci-newest", 1, "DRAFT", artifact("ci-newest", "OLD"))
		seedVersion(t, pool, "ci-newest", 2, "DRAFT", artifact("ci-newest", "NEW"))
		d := &fakeDispatcher{runID: "run-1"}

		runID, err := newService(pool, d).Start(context.Background(), "ci-newest")
		if err != nil || runID != "run-1" {
			t.Fatalf("Start = %q, %v; want run-1, nil", runID, err)
		}
		if d.gotName != "NEW" || d.gotAgent != "lab-agent" {
			t.Fatalf("dispatched %q on %q, want the newest version on the lab agent", d.gotName, d.gotAgent)
		}
	})
}

func TestService_StartRefusesWhatCannotBeValidated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedVersion(t, pool, "ci-retired", 1, "RETIRED", artifact("ci-retired", "R"))
		seedVersion(t, pool, "ci-ok", 1, "DRAFT", artifact("ci-ok", "OK"))

		d := &fakeDispatcher{}
		if _, err := newService(pool, d).Start(ctx, "no-such-content"); !errors.Is(err, ErrUnknownContent) {
			t.Fatalf("unknown content: err = %v, want ErrUnknownContent", err)
		}
		var refused *RefusedError
		if _, err := newService(pool, d).Start(ctx, "ci-retired"); !errors.As(err, &refused) {
			t.Fatalf("retired content: err = %v, want a refusal", err)
		}
		if d.calls != 0 {
			t.Fatalf("content that was refused still reached the lab agent (%d dispatches)", d.calls)
		}

		busy := &fakeDispatcher{skip: "agent busy"}
		if _, err := newService(pool, busy).Start(ctx, "ci-ok"); !errors.As(err, &refused) || refused.Reason != "agent busy" {
			t.Fatalf("busy lab: err = %v, want a refusal carrying the lab's reason", err)
		}
	})
}
