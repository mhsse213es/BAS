package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkcorrelation"
	"github.com/audspect/bas/internal/networkpolicy"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func createTestPolicyImport(t *testing.T, h *Handler, pool *pgxpool.Pool) string {
	t.Helper()
	req := networkPolicyImportReq(t, pool, validPolicyImportBody())
	rec := callAuthed(h.CreateNetworkPolicyImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create policy import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created networkpolicy.PolicyImport
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	return created.ID
}

func TestEvaluateNetworkPolicy_ValidRequestReturnsEvaluations(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		importID := createTestPolicyImport(t, h, pool)

		body := map[string]any{
			"policyImportId": importID,
			"queries":        []map[string]any{{"sourceZone": "dmz", "destCidr": "203.0.113.5/32", "protocol": "tcp", "port": 443}},
		}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpolicy-eval-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-policy-evaluations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.EvaluateNetworkPolicy, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var evals []networkpolicy.PolicyEvaluation
		if err := json.Unmarshal(rec.Body.Bytes(), &evals); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(evals) != 1 {
			t.Fatalf("got %d evaluations, want 1", len(evals))
		}
	})
}

func TestEvaluateNetworkPolicy_UnknownPolicyImportReturns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{"policyImportId": "nonexistent-id", "queries": []map[string]any{{"port": 443}}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpolicy-eval-404", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-policy-evaluations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.EvaluateNetworkPolicy, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestEvaluateNetworkPolicy_MissingPolicyImportIdRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{"queries": []map[string]any{{"port": 443}}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpolicy-eval-noid", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-policy-evaluations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.EvaluateNetworkPolicy, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestEvaluateNetworkPolicy_OversizedBodyRejectedBeforeFullDecode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "netpolicy-eval-oversize", "pw12345678", string(auth.RoleAnalyst), true)
		oversized := []byte(`{"policyImportId":"` + strings.Repeat("x", maxNetworkPolicyEvaluationRequestBytes+1) + `"}`)
		req := authedRequest(t, http.MethodPost, "/api/network-policy-evaluations", bytes.NewReader(oversized), auth.RoleAnalyst, userID)
		rec := callAuthed(h.EvaluateNetworkPolicy, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestGetNetworkReachabilityComparison_EndToEndAgainstRealDiscoveryRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		openPort := ln.Addr().(*net.TCPAddr).Port

		discoveryReq := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{{"host": "127.0.0.1", "port": openPort}}})
		discoveryRec := callAuthed(h.TriggerNetworkDiscoveryRun, discoveryReq)
		if discoveryRec.Code != http.StatusCreated {
			t.Fatalf("trigger discovery: status = %d, body = %s", discoveryRec.Code, discoveryRec.Body.String())
		}
		var discoveryResp struct{ RunID string `json:"runId"` }
		if err := json.Unmarshal(discoveryRec.Body.Bytes(), &discoveryResp); err != nil {
			t.Fatalf("decode discovery: %v", err)
		}

		// A permissive policy import whose default is allow, so the
		// /32 destination of the actual probed target resolves to
		// PolicySupported -- paired with Phase 1's real Observed result,
		// this must label as consistent-allow end to end.
		policyBody := map[string]any{
			"sourceType": "manual-normalized", "defaultPolicy": "allow",
			"zones": []map[string]any{{"name": "any", "cidrs": []string{"0.0.0.0/0"}}},
			"rules": []map[string]any{{"id": "r1", "order": 1, "sourceZone": "any", "destZone": "any", "action": "allow"}},
		}
		policyReq := networkPolicyImportReq(t, pool, policyBody)
		policyRec := callAuthed(h.CreateNetworkPolicyImport, policyReq)
		if policyRec.Code != http.StatusCreated {
			t.Fatalf("create policy: status = %d, body = %s", policyRec.Code, policyRec.Body.String())
		}
		var policyResp networkpolicy.PolicyImport
		if err := json.Unmarshal(policyRec.Body.Bytes(), &policyResp); err != nil {
			t.Fatalf("decode policy: %v", err)
		}

		compareURL := "/api/network-reachability-comparisons?policyImportId=" + policyResp.ID + "&discoveryRunId=" + discoveryResp.RunID
		compareReq := authedRequest(t, http.MethodGet, compareURL, nil, auth.RoleViewer, "")
		compareRec := callAuthed(h.GetNetworkReachabilityComparison, compareReq)
		if compareRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", compareRec.Code, compareRec.Body.String())
		}
		var comparisons []networkcorrelation.ReachabilityComparison
		if err := json.Unmarshal(compareRec.Body.Bytes(), &comparisons); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(comparisons) != 1 {
			t.Fatalf("got %d comparisons, want 1", len(comparisons))
		}
		if comparisons[0].Label != networkcorrelation.ConsistentAllow {
			t.Fatalf("label = %q, want consistent-allow -- a permissive policy plus a real observed-open port must agree", comparisons[0].Label)
		}
	})
}

func TestGetNetworkReachabilityComparison_SourceRestrictedRuleNotFalselyMatchedBySyntheticSource(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// This policy's only rule is scoped to an "admin" source zone --
		// a very common real pattern ("allow SSH only from the admin
		// subnet"). The configured vantage point's own NetworkPosition
		// ("test-harness-network", see testVantagePoint) is NOT a
		// declared zone in this import, so there is no real evidence the
		// probe actually originated from "admin". The comparison must
		// not silently assume it did just because queriesFromObservations
		// has to synthesize *some* source CIDR to run EvaluatePolicyMatrix
		// at all -- that synthetic value must never be allowed to satisfy
		// a rule that genuinely restricts by source.
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		openPort := ln.Addr().(*net.TCPAddr).Port

		discoveryReq := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{{"host": "127.0.0.1", "port": openPort}}})
		discoveryRec := callAuthed(h.TriggerNetworkDiscoveryRun, discoveryReq)
		if discoveryRec.Code != http.StatusCreated {
			t.Fatalf("trigger discovery: status = %d, body = %s", discoveryRec.Code, discoveryRec.Body.String())
		}
		var discoveryResp struct{ RunID string `json:"runId"` }
		if err := json.Unmarshal(discoveryRec.Body.Bytes(), &discoveryResp); err != nil {
			t.Fatalf("decode discovery: %v", err)
		}

		policyBody := map[string]any{
			"sourceType": "manual-normalized", "defaultPolicy": "deny",
			"zones": []map[string]any{{"name": "admin", "cidrs": []string{"10.0.9.0/24"}}},
			"rules": []map[string]any{{"id": "allow-admin-only", "order": 1, "sourceZone": "admin", "destCidr": "0.0.0.0/0", "action": "allow"}},
		}
		policyReq := networkPolicyImportReq(t, pool, policyBody)
		policyRec := callAuthed(h.CreateNetworkPolicyImport, policyReq)
		if policyRec.Code != http.StatusCreated {
			t.Fatalf("create policy: status = %d, body = %s", policyRec.Code, policyRec.Body.String())
		}
		var policyResp networkpolicy.PolicyImport
		if err := json.Unmarshal(policyRec.Body.Bytes(), &policyResp); err != nil {
			t.Fatalf("decode policy: %v", err)
		}

		compareURL := "/api/network-reachability-comparisons?policyImportId=" + policyResp.ID + "&discoveryRunId=" + discoveryResp.RunID
		compareReq := authedRequest(t, http.MethodGet, compareURL, nil, auth.RoleViewer, "")
		compareRec := callAuthed(h.GetNetworkReachabilityComparison, compareReq)
		if compareRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", compareRec.Code, compareRec.Body.String())
		}
		var comparisons []networkcorrelation.ReachabilityComparison
		if err := json.Unmarshal(compareRec.Body.Bytes(), &comparisons); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(comparisons) != 1 {
			t.Fatalf("got %d comparisons, want 1", len(comparisons))
		}
		if comparisons[0].Evaluation.State != cloudgraph.Unknown {
			t.Fatalf("evaluation state = %q, want unknown -- a source-restricted admin-only rule must never be satisfied by evidence this comparison does not actually have", comparisons[0].Evaluation.State)
		}
		if comparisons[0].Evaluation.Limitations == "" {
			t.Fatal("want a non-empty limitation explaining why the source-restricted match was not trusted")
		}
		if comparisons[0].Label != networkcorrelation.PolicyInconclusive {
			t.Fatalf("label = %q, want policy-inconclusive", comparisons[0].Label)
		}
	})
}

func TestGetNetworkReachabilityComparison_MissingParamsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/network-reachability-comparisons", nil, auth.RoleViewer, "")
		rec := callAuthed(h.GetNetworkReachabilityComparison, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestGetNetworkReachabilityComparison_UnknownDiscoveryRunReturns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		importID := createTestPolicyImport(t, h, pool)
		url := "/api/network-reachability-comparisons?policyImportId=" + importID + "&discoveryRunId=nonexistent-run"
		req := authedRequest(t, http.MethodGet, url, nil, auth.RoleViewer, "")
		rec := callAuthed(h.GetNetworkReachabilityComparison, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}
