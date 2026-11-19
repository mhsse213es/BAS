package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/ws"
)

// A trust-driven state change leaves an audit row with both states and the hash that caused it. Before this
// the only trace was a log line, so a quarantine could not be explained once the log had rotated.

func trustTestHandler(t *testing.T, pool *pgxpool.Pool, cur, prev string) *Handler {
	t.Helper()
	path := filepath.Join(t.TempDir(), "BINARIES.sha256")
	body := cur + "  bas-agent-linux-amd64\n#prev " + prev + "  bas-agent-linux-amd64\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(pool, ws.NewHub(), nil, "").WithManifest(integrity.LoadManifest(path))
}

func trustAuditRows(t *testing.T, pool *pgxpool.Pool, agentID string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT detail->>'from' || '>' || (detail->>'to') || ' ' || (detail->>'binary_hash')
		   FROM audit_logs WHERE action = 'agent.trust_state_changed' AND resource = $1 ORDER BY id`, agentID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func TestApplyBinaryTrustState_WritesAuditRowPerTransition(t *testing.T) {
	cur := strings.Repeat("a", 64)
	prev := strings.Repeat("b", 64)
	unknown := strings.Repeat("c", 64)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		const id = "trust-audit-agent"
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')`, id); err != nil {
			t.Fatal(err)
		}
		h := trustTestHandler(t, pool, cur, prev)

		h.applyBinaryTrustState(ctx, id, cur, true) // current binary, already active: no change, no row
		if rows := trustAuditRows(t, pool, id); len(rows) != 0 {
			t.Fatalf("no transition, but audit rows: %v", rows)
		}

		h.applyBinaryTrustState(ctx, id, prev, false)    // previous signed release: active -> outdated
		h.applyBinaryTrustState(ctx, id, cur, true)      // current binary: outdated -> active
		h.applyBinaryTrustState(ctx, id, unknown, false) // unknown binary: active -> quarantined

		got := trustAuditRows(t, pool, id)
		want := []string{"active>outdated " + prev, "outdated>active " + cur, "active>quarantined " + unknown}
		if len(got) != len(want) {
			t.Fatalf("audit rows = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("row %d = %q, want %q", i, got[i], want[i])
			}
		}

		h.applyBinaryTrustState(ctx, id, unknown, false) // still quarantined: nothing new
		h.applyBinaryTrustState(ctx, id, cur, true)      // quarantine is never lifted by a heartbeat
		if rows := trustAuditRows(t, pool, id); len(rows) != 3 {
			t.Fatalf("a no-op heartbeat added audit rows: %v", rows)
		}
	})
}
