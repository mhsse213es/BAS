package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/variant"
	"github.com/jackc/pgx/v5/pgxpool"
)
// seedLabAgent seeds an active agent labelled Lab. Variant dispatch tests exercise dispatch mechanics, which apply
// to a lab endpoint; policy on other labels is covered by the cleanup gate tests.
func seedLabAgent(t *testing.T, pool *pgxpool.Pool, agentID, osVersion string) {
	t.Helper()
	seedActiveAgent(t, pool, agentID, osVersion)
	setAgentEnvLabel(t, pool, agentID, "Lab")
}


func tpl(cleanup, status string) variant.Template {
	return variant.Template{TechniqueID: "T1", BaseID: "b", Command: "c", Cleanup: cleanup, CleanupStatus: status}
}

// Outside a lab, only a variant whose cleanup is eligible may run. A lab may run anything.
func TestSplitByCleanup_OutsideALabOnlyEligibleVariantsRun(t *testing.T) {
	templates := []variant.Template{
		tpl("rm x", variant.CleanupVerified),
		tpl("", variant.CleanupReadOnly),
		tpl("", variant.CleanupUnverified),
		tpl("rm y", variant.CleanupUnverified),
	}
	runnable, blocked := splitByCleanup(templates, "Production")
	if len(runnable) != 2 || len(blocked) != 2 {
		t.Fatalf("production: runnable=%d blocked=%d, want 2 and 2", len(runnable), len(blocked))
	}
	runnable, blocked = splitByCleanup(templates, "Staging")
	if len(runnable) != 2 || len(blocked) != 2 {
		t.Fatalf("staging: runnable=%d blocked=%d, want 2 and 2", len(runnable), len(blocked))
	}
}

func TestSplitByCleanup_LabRunsEverything(t *testing.T) {
	templates := []variant.Template{tpl("", variant.CleanupUnverified), tpl("", "")}
	runnable, blocked := splitByCleanup(templates, "Lab")
	if len(runnable) != 2 || len(blocked) != 0 {
		t.Errorf("lab: runnable=%d blocked=%d, want 2 and 0", len(runnable), len(blocked))
	}
}

func TestIsLabEndpoint(t *testing.T) {
	for label, want := range map[string]bool{"Lab": true, "  lab ": true, "LAB": true, "Production": false, "": false, "labs": false} {
		if got := isLabEndpoint(label); got != want {
			t.Errorf("isLabEndpoint(%q) = %v, want %v", label, got, want)
		}
	}
}

// An ART cleanup is verified as authored upstream. Caldera has no cleanup in this store, so it is always unverified.
func TestCleanupStatusFor(t *testing.T) {
	if got := cleanupStatusFor("rm x", "art"); got != variant.CleanupVerified {
		t.Errorf("ART with cleanup = %q, want verified", got)
	}
	if got := cleanupStatusFor("", "art"); got != variant.CleanupUnverified {
		t.Errorf("ART without cleanup = %q, want unverified", got)
	}
	if got := cleanupStatusFor("rm x", variant.SourceCaldera); got != variant.CleanupUnverified {
		t.Errorf("Caldera = %q, want unverified even with a cleanup", got)
	}
}

// A family marked verified must name its cleanup. Checked before the database is touched.
func TestCreatePayloadFamily_VerifiedNeedsACleanup(t *testing.T) {
	h := &Handler{}
	body, _ := json.Marshal(map[string]string{
		"techniqueId": "T1005", "name": "x", "payload": "dir", "cleanupStatus": "verified",
	})
	rec := httptest.NewRecorder()
	h.CreatePayloadFamily(rec, httptest.NewRequest(http.MethodPost, "/api/payload-families", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for verified without cleanup, body: %s", rec.Code, rec.Body.String())
	}
}

func TestCreatePayloadFamily_UnknownStatusRejected(t *testing.T) {
	h := &Handler{}
	body, _ := json.Marshal(map[string]string{
		"techniqueId": "T1005", "name": "x", "payload": "dir", "cleanupStatus": "maybe",
	})
	rec := httptest.NewRecorder()
	h.CreatePayloadFamily(rec, httptest.NewRequest(http.MethodPost, "/api/payload-families", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
