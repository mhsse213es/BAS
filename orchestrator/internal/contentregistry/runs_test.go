package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

type mapLookup map[string]*scenario.Scenario

func (m mapLookup) Get(id string) (*scenario.Scenario, bool) { s, ok := m[id]; return s, ok }

func TestRunContent_UsesStoredVersionNotCurrent(t *testing.T) { // A9
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		old := []byte("id: hist\nname: Old name\nsteps:\n  - {name: s1, technique_id: T1082, framework: custom, command: a}\n")
		if err := r.RegisterLocalApproved(ctx, "hist", old, "user:op"); err != nil {
			t.Fatal(err)
		}
		ev, _ := r.ResolveExecutable(ctx, "hist")
		_, _ = pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ('ha','h')`)
		var runID string
		_ = pool.QueryRow(ctx, `INSERT INTO scenario_runs (scenario_id, agent_id, execution_kind, content_version_id)
			VALUES ('hist','ha','content',$1) RETURNING id`, ev.VersionID).Scan(&runID)
		current := mapLookup{"hist": {ID: "hist", Name: "New name"}}
		rc := r.RunContent(ctx, runID, current)
		if rc.Status != RunVersioned || rc.Scenario.Name != "Old name" || rc.Version != 1 {
			t.Fatalf("got %+v", rc)
		}
		res := r.ForRun(ctx, runID, nil)
		if sc, ok := res.Get("hist"); !ok || sc.Name != "Old name" {
			t.Fatalf("resolver must serve the pinned version: %+v", sc)
		}
	})
}

func TestRunContent_LegacyLabelledAndSyntheticEmpty(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		_, _ = pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ('la','h')`)
		var legacyID, synthID string
		// The legacy run is completed: idx_scenario_runs_agent_running allows
		// only one running run per agent.
		if err := pool.QueryRow(ctx, `INSERT INTO scenario_runs (scenario_id, agent_id, status) VALUES ('lg','la','completed') RETURNING id`).Scan(&legacyID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `INSERT INTO scenario_runs (scenario_id, agent_id, execution_kind) VALUES ('__variant__t1082','la','variant') RETURNING id`).Scan(&synthID); err != nil {
			t.Fatal(err)
		}
		rc := r.RunContent(ctx, legacyID, mapLookup{"lg": {ID: "lg", Name: "Current"}})
		if rc.Status != RunUnversioned || rc.Scenario.Name != "Current" ||
			rc.Label() != "Unversioned — interpreted against current content" {
			t.Fatalf("legacy: %+v label=%q", rc, rc.Label())
		}
		if s := r.RunContent(ctx, synthID, mapLookup{}); s.Status != RunSynthetic || s.Scenario != nil {
			t.Fatalf("synthetic: %+v", s)
		}
	})
}

func TestRunContent_UnreadableNeverFallsBack(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		_ = r.RegisterLocalApproved(ctx, "ur", []byte("id: ur\nname: U\nlocal_check: true\n"), "user:op")
		ev, _ := r.ResolveExecutable(ctx, "ur")
		bad := []byte("id: [broken")
		_, _ = pool.Exec(ctx, `UPDATE content_versions SET artifact_bytes=$1, artifact_size=$2 WHERE id=$3`, bad, len(bad), ev.VersionID)
		_, _ = pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ('ua','h')`)
		var runID string
		// Checked: a failed insert would make the Unreadable assertion vacuous.
		if err := pool.QueryRow(ctx, `INSERT INTO scenario_runs (scenario_id, agent_id, execution_kind, content_version_id)
			VALUES ('ur','ua','content',$1) RETURNING id`, ev.VersionID).Scan(&runID); err != nil {
			t.Fatal(err)
		}
		rc := r.RunContent(ctx, runID, mapLookup{"ur": {ID: "ur", Name: "Current"}})
		if rc.Status != RunUnreadable || rc.Scenario != nil || rc.Label() != "Content version unreadable" {
			t.Fatalf("got %+v", rc)
		}
		// A corrupt artifact is a permanent state, not an infrastructure blip.
		if rc.Transient || rc.Err == nil {
			t.Fatalf("corrupt version must be permanent with an error: %+v", rc)
		}
		// So is a run row that does not exist.
		if miss := r.RunContent(ctx, "no-such-run", nil); miss.Status != RunUnreadable || miss.Transient || miss.Err == nil || !miss.NotFound {
			t.Fatalf("missing run must be permanent: %+v", miss)
		}
	})
}

func TestRunContent_MissingVersionIsPermanent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ('ma','h')`); err != nil {
			t.Fatal(err)
		}
		// The FK forbids a dangling pin, so pin a real version and then
		// repoint it at a nonexistent id with FK triggers disabled
		// (session_replication_role = replica) to simulate a lost version.
		if err := r.RegisterLocalApproved(ctx, "mv", []byte("id: mv\nname: M\nlocal_check: true\n"), "user:op"); err != nil {
			t.Fatal(err)
		}
		ev, _ := r.ResolveExecutable(ctx, "mv")
		var runID string
		if err := pool.QueryRow(ctx, `INSERT INTO scenario_runs (scenario_id, agent_id, execution_kind, content_version_id)
			VALUES ('mv','ma','content',$1) RETURNING id`, ev.VersionID).Scan(&runID); err != nil {
			t.Fatal(err)
		}
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		if _, err := conn.Exec(ctx, `SET session_replication_role = replica`); err != nil {
			t.Skipf("cannot bypass FK to simulate a missing version: %v", err)
		}
		_, err = conn.Exec(ctx, `UPDATE scenario_runs SET content_version_id = 'cv-gone' WHERE id = $1`, runID)
		_, _ = conn.Exec(ctx, `SET session_replication_role = origin`)
		if err != nil {
			t.Fatal(err)
		}
		rc := r.RunContent(ctx, runID, nil)
		if rc.Status != RunUnreadable || rc.Transient || rc.VersionID != "cv-gone" || rc.Err == nil {
			t.Fatalf("missing version must be permanent: %+v", rc)
		}
	})
}

func TestRunContent_CancelledContextIsTransient(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		r := New(pool, testutil.DevVerifier())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		rc := r.RunContent(ctx, "any-run", nil)
		if rc.Status != RunUnreadable || !rc.Transient || rc.Err == nil {
			t.Fatalf("cancelled context must be transient: %+v", rc)
		}
	})
}
