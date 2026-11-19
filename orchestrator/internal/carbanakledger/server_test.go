package carbanakledger

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		ListenAddr:        "127.0.0.1:8745",
		AuditPath:         "",
		SessionTTLSeconds: 1800,
		Window: WindowConfig{
			Timezone:  "Asia/Kolkata",
			StartHour: 9,
			EndHour:   18,
			Weekdays:  []int{1, 2, 3, 4, 5},
		},
		Identities: []Identity{
			{ID: "op1", Token: "synthetic-op1", Roles: []string{"operator"}, Limit: 100},
			{ID: "op2", Token: "synthetic-op2", Roles: []string{"operator", "approver"}, Limit: 100},
			{ID: "admin", Token: "synthetic-admin", Roles: []string{"privileged", "approver"}, Limit: 100},
		},
	}
}

// newTestServer returns a server with a fixed clock at a time inside the
// operating window (Monday 10:00 IST) and a fresh audit log.
func newTestServer(t *testing.T, at time.Time) *Server {
	t.Helper()
	cfg := testConfig()
	log, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(cfg, log, func() time.Time { return at })
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

var insideWindow = time.Date(2026, 11, 16, 4, 30, 0, 0, time.UTC) // 10:00 IST Monday
var outsideWindow = time.Date(2026, 11, 16, 14, 30, 0, 0, time.UTC) // 20:00 IST Monday

func do(t *testing.T, s *Server, method, path, remote string, body any) map[string]any {
	t.Helper()
	var buf strings.Builder
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, strings.NewReader(buf.String()))
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: bad json %q: %v", method, path, rec.Body.String(), err)
		}
	}
	if rec.Code >= 400 {
		t.Fatalf("%s %s: status %d body %s", method, path, rec.Code, rec.Body.String())
	}
	return out
}

func login(t *testing.T, s *Server, id, token, remote string) string {
	t.Helper()
	out := do(t, s, "POST", "/session", remote, map[string]string{
		"identity": id, "token": token, "run_id": "run-1", "step": "8a",
	})
	sid, _ := out["session_id"].(string)
	if sid == "" {
		t.Fatalf("login %s returned no session: %v", id, out)
	}
	return sid
}

const loopback = "127.0.0.1:5555"

func TestLoginWithValidSyntheticCredentialApproved(t *testing.T) {
	s := newTestServer(t, insideWindow)
	out := do(t, s, "POST", "/session", loopback, map[string]string{
		"identity": "op1", "token": "synthetic-op1", "run_id": "run-1", "step": "8a",
	})
	if out["decision"] != "approved" {
		t.Fatalf("decision = %v, want approved", out["decision"])
	}
}

func TestLoginWithBadTokenRejected(t *testing.T) {
	s := newTestServer(t, insideWindow)
	out := do(t, s, "POST", "/session", loopback, map[string]string{
		"identity": "op1", "token": "wrong", "run_id": "run-1", "step": "8a",
	})
	if out["decision"] != "rejected" || out["rule_fired"] != "invalid_credential" {
		t.Fatalf("got %v, want rejected/invalid_credential", out)
	}
}

func TestTransferInsideWindowUnderLimitApproved(t *testing.T) {
	s := newTestServer(t, insideWindow)
	sid := login(t, s, "op1", "synthetic-op1", loopback)
	out := do(t, s, "POST", "/transfer", loopback, map[string]any{
		"session_id": sid, "run_id": "run-1", "step": "8c", "amount": 50,
	})
	if out["decision"] != "approved" {
		t.Fatalf("decision = %v, want approved", out["decision"])
	}
}

func TestTransferOutsideWindowFlagged(t *testing.T) {
	s := newTestServer(t, outsideWindow)
	sid := login(t, s, "op1", "synthetic-op1", loopback)
	out := do(t, s, "POST", "/transfer", loopback, map[string]any{
		"session_id": sid, "run_id": "run-1", "step": "8c", "amount": 50,
	})
	if out["decision"] != "flagged" || out["rule_fired"] != "outside_operating_window" {
		t.Fatalf("got %v, want flagged/outside_operating_window", out)
	}
}

func TestSelfApprovalRejected(t *testing.T) {
	s := newTestServer(t, insideWindow)
	sid := login(t, s, "op2", "synthetic-op2", loopback)
	tx := do(t, s, "POST", "/transfer", loopback, map[string]any{
		"session_id": sid, "run_id": "run-1", "step": "8c", "amount": 50,
	})
	out := do(t, s, "POST", "/approve", loopback, map[string]any{
		"session_id": sid, "run_id": "run-1", "step": "8d", "txn_id": tx["txn_id"],
	})
	if out["decision"] != "rejected" || out["rule_fired"] != "maker_checker_self_approval" {
		t.Fatalf("got %v, want rejected/maker_checker_self_approval", out)
	}
}

func TestApprovalByNonApproverRejected(t *testing.T) {
	s := newTestServer(t, insideWindow)
	init := login(t, s, "op2", "synthetic-op2", loopback)
	tx := do(t, s, "POST", "/transfer", loopback, map[string]any{
		"session_id": init, "run_id": "run-1", "step": "8c", "amount": 50,
	})
	other := login(t, s, "op1", "synthetic-op1", loopback)
	out := do(t, s, "POST", "/approve", loopback, map[string]any{
		"session_id": other, "run_id": "run-1", "step": "8e", "txn_id": tx["txn_id"],
	})
	if out["decision"] != "rejected" || out["rule_fired"] != "approver_role_missing" {
		t.Fatalf("got %v, want rejected/approver_role_missing", out)
	}
}

func TestClientSuppliedHostFieldIgnored(t *testing.T) {
	s := newTestServer(t, insideWindow)
	sid := login(t, s, "op1", "synthetic-op1", loopback)
	// Same session, but the request really comes from another host. The body
	// claims the original host; the ledger must still see the mismatch.
	out := do(t, s, "POST", "/transfer", "10.1.1.1:5555", map[string]any{
		"session_id": sid, "run_id": "run-1", "step": "8c", "amount": 50, "host": "127.0.0.1",
	})
	if out["decision"] != "flagged" || out["rule_fired"] != "session_anomaly" {
		t.Fatalf("got %v, want flagged/session_anomaly (host taken from connection, not body)", out)
	}
}

func TestAlertsListNonApprovedDecisions(t *testing.T) {
	s := newTestServer(t, outsideWindow)
	sid := login(t, s, "op1", "synthetic-op1", loopback)
	do(t, s, "POST", "/transfer", loopback, map[string]any{
		"session_id": sid, "run_id": "run-9", "step": "8c", "amount": 50,
	})
	out := do(t, s, "GET", "/alerts?run_id=run-9", loopback, nil)
	alerts, _ := out["alerts"].([]any)
	if len(alerts) != 1 {
		t.Fatalf("alerts = %v, want one flagged transfer", out["alerts"])
	}
}

func TestAuditVerifyIntact(t *testing.T) {
	s := newTestServer(t, insideWindow)
	login(t, s, "op1", "synthetic-op1", loopback)
	out := do(t, s, "GET", "/audit/verify", loopback, nil)
	if out["intact"] != true {
		t.Fatalf("verify = %v, want intact", out)
	}
}

func TestCheckListenAddrLoopbackAllowed(t *testing.T) {
	if err := CheckListenAddr("127.0.0.1:8745", "", false); err != nil {
		t.Fatalf("loopback refused: %v", err)
	}
}

func TestCheckListenAddrNonLocalRefusedByDefault(t *testing.T) {
	if err := CheckListenAddr("10.0.0.5:8745", "ledger.lab", false); err == nil {
		t.Fatal("non-loopback bind allowed without the override")
	}
}

func TestCheckListenAddrProductionHostnameRefused(t *testing.T) {
	if err := CheckListenAddr("10.0.0.5:8745", "ledger.bank.example", true); err == nil {
		t.Fatal("non-loopback bind allowed for a production-style hostname")
	}
}

func TestCheckListenAddrLabHostnameAllowedWithOverride(t *testing.T) {
	for _, h := range []string{"ledger.lab", "ledger.test", "ledger.invalid"} {
		if err := CheckListenAddr("10.0.0.5:8745", h, true); err != nil {
			t.Fatalf("lab hostname %q refused with override: %v", h, err)
		}
	}
}

func TestListenReportsPortInUse(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	_, err = Listen(held.Addr().String())
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("expected port-in-use error, got %v", err)
	}
}

var _ http.Handler = (*Server)(nil)
