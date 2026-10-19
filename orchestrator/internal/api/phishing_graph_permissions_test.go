package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// The declared permissions are the approved ones, and nothing more. PH-ID-003 gets
// the sign-in read and the Conditional Access read. PH-ID-002 gets the reviewed
// consent-grant read. PH-ID-005 gets nothing until its $select is verified.
func TestPhishingGraphPermissions_DeclaredSetMatchesApprovals(t *testing.T) {
	want := map[string][]string{
		"PH-ID-002": {"Directory.Read.All"},
		"PH-ID-003": {"AuditLog.Read.All", "Policy.Read.ConditionalAccess"},
		"PH-ID-005": nil,
	}
	for id, perms := range want {
		got := phishingGraphPermissions[id]
		if len(got) != len(perms) {
			t.Errorf("%s: declared %v, want %v", id, got, perms)
			continue
		}
		for i := range perms {
			if got[i] != perms[i] {
				t.Errorf("%s: declared %v, want %v", id, got, perms)
			}
		}
	}
}

// Declaring a permission does not make a scenario available. PH-ID-002 and PH-ID-003
// stay gated until their filters and live behavior are verified.
func TestPhishingGraphPermissions_DeclarationDoesNotEnableScenario(t *testing.T) {
	for _, id := range []string{"PH-ID-002", "PH-ID-003"} {
		if !graphReviewPending[id] {
			t.Errorf("%s: must remain gated by graph_permission_review_pending", id)
		}
	}
}

// The startup record carries the declared permissions, so a change to them is
// audited the same way a change to the allowlist is.
func TestRecordPhishingScope_RecordsDeclaredPermissions(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		t.Setenv(EnvPhishIdentityTargetUsers, "")
		t.Setenv(EnvPhishOAuthSPObjectIDs, "")
		if err := h.RecordPhishingScopeAtStartup(context.Background()); err != nil {
			t.Fatalf("record: %v", err)
		}
		rows := scopeAuditRows(t, pool)
		if len(rows) != 1 {
			t.Fatalf("rows = %d, want 1", len(rows))
		}
		raw, _ := json.Marshal(rows[0].Detail["graphPermissions"])
		if !strings.Contains(string(raw), "Policy.Read.ConditionalAccess") {
			t.Errorf("startup record does not carry the declared permissions: %s", raw)
		}
	})
}

