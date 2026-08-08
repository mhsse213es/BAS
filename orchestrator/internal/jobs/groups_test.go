package jobs

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestResolveGroupAgentIDs_RecursesIntoDescendantGroups(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var parentID, childID int64
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO agent_groups (name) VALUES ('Finance') RETURNING id`).Scan(&parentID); err != nil {
			t.Fatalf("insert parent group: %v", err)
		}
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO agent_groups (name, parent_id) VALUES ('Finance-Servers', $1) RETURNING id`, parentID).Scan(&childID); err != nil {
			t.Fatalf("insert child group: %v", err)
		}
		mustExecJobsNotif(t, pool, `INSERT INTO agents (agent_id, hostname, group_id) VALUES ('grp-direct', 'DIRECT-HOST', $1)`, parentID)
		mustExecJobsNotif(t, pool, `INSERT INTO agents (agent_id, hostname, group_id) VALUES ('grp-nested', 'NESTED-HOST', $1)`, childID)
		mustExecJobsNotif(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('grp-outside', 'OUTSIDE-HOST')`)

		store := NewStore(pool)
		got, err := store.ResolveGroupAgentIDs(context.Background(), []int64{parentID})
		if err != nil {
			t.Fatalf("ResolveGroupAgentIDs: %v", err)
		}
		want := map[string]bool{"grp-direct": true, "grp-nested": true}
		if len(got) != 2 {
			t.Fatalf("got %v, want exactly grp-direct and grp-nested", got)
		}
		for _, id := range got {
			if !want[id] {
				t.Errorf("unexpected agent %q in result", id)
			}
		}
	})
}

func TestResolveGroupAgentIDs_EmptyInput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		got, err := store.ResolveGroupAgentIDs(context.Background(), nil)
		if err != nil {
			t.Fatalf("ResolveGroupAgentIDs: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})
}
