package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// TestAttackMatrix_Success pins the static enterprise matrix shape: all 14
// tactics in kill-chain order, each carrying a techniques array, with a known
// technique (T1059.001) appearing under its tactic.
func TestAttackMatrix_Success(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	rec := httptest.NewRecorder()
	h.AttackMatrix(rec, httptest.NewRequest(http.MethodGet, "/api/attack/matrix", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out struct {
		Tactics []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Techniques []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"techniques"`
		} `json:"tactics"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantOrder := []string{
		"reconnaissance", "resource-development", "initial-access", "execution",
		"persistence", "privilege-escalation", "defense-evasion", "credential-access",
		"discovery", "lateral-movement", "collection", "command-and-control",
		"exfiltration", "impact",
	}
	if len(out.Tactics) != len(wantOrder) {
		t.Fatalf("tactic count = %d, want %d", len(out.Tactics), len(wantOrder))
	}
	var foundExecTech bool
	for i, want := range wantOrder {
		if out.Tactics[i].ID != want {
			t.Errorf("tactics[%d].id = %q, want %q (kill-chain order)", i, out.Tactics[i].ID, want)
		}
		if out.Tactics[i].ID == "execution" {
			for _, tech := range out.Tactics[i].Techniques {
				if tech.ID == "T1059.001" {
					foundExecTech = true
				}
			}
		}
	}
	if !foundExecTech {
		t.Error("expected T1059.001 under the execution tactic")
	}
}

func TestAttackTechnique_Success(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	rec := httptest.NewRecorder()
	h.AttackTechnique(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/api/attack/technique/T1059.001", nil), "id", "T1059.001"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["name"] != "PowerShell" {
		t.Errorf("name = %v, want PowerShell", out["name"])
	}
}

func TestAttackTechnique_NotFound(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	rec := httptest.NewRecorder()
	h.AttackTechnique(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/api/attack/technique/bogus", nil), "id", "bogus"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
