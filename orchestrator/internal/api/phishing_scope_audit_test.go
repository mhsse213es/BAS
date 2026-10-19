package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/ws"
	"github.com/audspect/bas/internal/scenario"
)

// scopeAuditRows returns the recorded allowlist rows, oldest first.
func scopeAuditRows(t *testing.T, pool *pgxpool.Pool) []struct {
	Detail  map[string]any
	Outcome string
} {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT detail, outcome FROM audit_logs WHERE action = $1 ORDER BY ts, id`, ActionPhishingScopeRecorded)
	if err != nil {
		t.Fatalf("query audit rows: %v", err)
	}
	defer rows.Close()
	var out []struct {
		Detail  map[string]any
		Outcome string
	}
	for rows.Next() {
		var raw []byte
		var outcome string
		if err := rows.Scan(&raw, &outcome); err != nil {
			t.Fatalf("scan: %v", err)
		}
		var d map[string]any
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("decode detail: %v", err)
		}
		out = append(out, struct {
			Detail  map[string]any
			Outcome string
		}{d, outcome})
	}
	return out
}

// A row is written at startup and only when the allowlist actually changes. A
// restart with the same configuration must not add a row.
func TestRecordPhishingScope_WritesOnlyOnChange(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		t.Setenv(EnvPhishIdentityTargetUsers, "")
		t.Setenv(EnvPhishOAuthSPObjectIDs, goodClientGUID)

		if err := h.RecordPhishingScopeAtStartup(context.Background()); err != nil {
			t.Fatalf("first record: %v", err)
		}
		if err := h.RecordPhishingScopeAtStartup(context.Background()); err != nil {
			t.Fatalf("second record: %v", err)
		}
		if n := len(scopeAuditRows(t, pool)); n != 1 {
			t.Fatalf("rows after two identical startups = %d, want 1", n)
		}

		t.Setenv(EnvPhishOAuthSPObjectIDs, goodClientGUID+","+otherClientGUID)
		if err := h.RecordPhishingScopeAtStartup(context.Background()); err != nil {
			t.Fatalf("changed record: %v", err)
		}
		rows := scopeAuditRows(t, pool)
		if len(rows) != 2 {
			t.Fatalf("rows after a change = %d, want 2", len(rows))
		}
		if rows[1].Detail["previous"] != rows[0].Detail["fingerprint"] {
			t.Errorf("latest row's previous = %v, want the earlier fingerprint %v", rows[1].Detail["previous"], rows[0].Detail["fingerprint"])
		}
	})
}

// A malformed value is recorded as an error, and its raw text is not stored. A
// bad user entry may be a real name.
func TestRecordPhishingScope_MalformedRecordedWithoutRawValue(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		t.Setenv(EnvPhishIdentityTargetUsers, "jane.doe-personal-name")
		t.Setenv(EnvPhishOAuthSPObjectIDs, "")

		if err := h.RecordPhishingScopeAtStartup(context.Background()); err != nil {
			t.Fatalf("record: %v", err)
		}
		rows := scopeAuditRows(t, pool)
		if len(rows) != 1 || rows[0].Outcome != "error" {
			t.Fatalf("rows = %+v, want one error row", rows)
		}
		raw, _ := json.Marshal(rows[0].Detail)
		if strings.Contains(string(raw), "jane.doe") {
			t.Errorf("audit detail stores the raw malformed value: %s", raw)
		}
	})
}
