package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
)

func seedHostRun(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname) VALUES ('ha1', 'HOST-HA1') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, mode)
		VALUES ('host-run', 'credential-access', 'h', 'ha1', 'completed', '[]', NOW(), 'posture')`); err != nil {
		t.Fatal(err)
	}
}

func hostEv(id uint64, cmd string) killchain.HostEvent {
	return killchain.HostEvent{RecordID: id, EventID: 4688, Host: "WS-01",
		Time: time.Date(2026, 10, 20, 9, 1, 0, 0, time.UTC), Subject: "svc", NewProcess: "rundll32.exe", CommandLine: cmd}
}

func TestHostEvents_RoundTripKeepsDuplicatesAndAudit(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedHostRun(t, pool)
		ctx := context.Background()
		s := db.KillChainStore{Pool: pool}
		audit := killchain.AuditState{ProcessCreation: killchain.AuditDisabled, Logon: killchain.AuditEnabled}
		dup := hostEv(101, "marker-x")
		if err := s.PutHostEvents(ctx, "host-run", []killchain.HostEvent{dup, dup}, audit); err != nil {
			t.Fatal(err)
		}
		got, gotAudit, found, err := s.HostEventsForRun(ctx, "host-run")
		if err != nil || !found {
			t.Fatalf("found=%v err=%v", found, err)
		}
		if len(got) != 2 {
			t.Fatalf("duplicates were collapsed at storage (%d rows); the evaluator must see them", len(got))
		}
		if gotAudit != audit {
			t.Fatalf("audit = %+v, want %+v", gotAudit, audit)
		}
		if got[0].RecordID != 101 || got[0].CommandLine != "marker-x" || got[0].Time.IsZero() {
			t.Fatalf("event fields lost: %+v", got[0])
		}
	})
}

// Re-delivery replaces the run's events. It does not accumulate them.
func TestHostEvents_RedeliveryReplacesRatherThanAccumulates(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedHostRun(t, pool)
		ctx := context.Background()
		s := db.KillChainStore{Pool: pool}
		audit := killchain.AuditState{ProcessCreation: killchain.AuditEnabled, Logon: killchain.AuditEnabled}
		_ = s.PutHostEvents(ctx, "host-run", []killchain.HostEvent{hostEv(1, "a"), hostEv(2, "b")}, audit)
		_ = s.PutHostEvents(ctx, "host-run", []killchain.HostEvent{hostEv(1, "a"), hostEv(2, "b")}, audit)
		got, _, _, _ := s.HostEventsForRun(ctx, "host-run")
		if len(got) != 2 {
			t.Fatalf("re-delivery left %d rows, want 2", len(got))
		}
	})
}

// No audit record means no batch was received. That is reported as not found, not
// as an empty but complete batch.
func TestHostEvents_NoBatchIsNotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := db.KillChainStore{Pool: pool}
		_, _, found, err := s.HostEventsForRun(context.Background(), "never")
		if err != nil || found {
			t.Fatalf("found=%v err=%v", found, err)
		}
	})
}
