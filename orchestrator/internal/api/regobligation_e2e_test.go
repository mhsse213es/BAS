package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/regobligation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// TestRegulatoryMapping_IndiaAndUAE_EndToEnd -- Review Focus #4 and
// spec §9's acceptance criteria: each of the two seed obligations is
// independently creatable, independently supports a real evidence
// snapshot derived from a genuinely computed Network BAS check result,
// and listing all obligations returns both without either leaking into
// the other's control-mapping/snapshot data.
func TestRegulatoryMapping_IndiaAndUAE_EndToEnd(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "regmapping-e2e-op", "pw12345678", string(auth.RoleAnalyst), true)

		// --- India: RBI network-segmentation obligation, evidenced by
		// a real zoneisolation.isolation-check result. A policy import
		// with an explicit allow rule makes the pair policy-permitted
		// but unobserved, so the real classification is deterministic:
		// unconfirmed-exposure. ---
		indiaTopoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "payment-core", "cidrs": []string{"10.10.0.0/24"}},
				{"name": "corporate", "cidrs": []string{"10.20.0.0/24"}},
			},
			"edges": []map[string]any{
				{"fromZone": "payment-core", "toZone": "corporate"},
			},
		})
		indiaIsolationID := createTestIsolationImport(t, h, pool, []map[string]any{
			{"canonicalId": "zp-1", "zoneA": "payment-core", "zoneB": "corporate"},
		})
		policyBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "payment-core", "cidrs": []string{"10.10.0.0/24"}},
				{"name": "corporate", "cidrs": []string{"10.20.0.0/24"}},
			},
			"rules": []map[string]any{
				{"order": 1, "sourceZone": "payment-core", "destZone": "corporate", "protocol": "tcp", "action": "allow"},
			},
			"defaultPolicy": "deny",
		}
		pb, _ := json.Marshal(policyBody)
		pReq := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(pb), auth.RoleAnalyst, userID)
		pRec := callAuthed(h.CreateNetworkPolicyImport, pReq)
		if pRec.Code != http.StatusCreated {
			t.Fatalf("create India policy import: status = %d, body = %s", pRec.Code, pRec.Body.String())
		}
		var indiaPolicy struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(pRec.Body.Bytes(), &indiaPolicy); err != nil {
			t.Fatalf("decode India policy import: %v", err)
		}

		isolationReqBody, _ := json.Marshal(map[string]any{
			"topologyImportId":  indiaTopoID,
			"isolationImportId": indiaIsolationID,
			"policyImportId":    indiaPolicy.ID,
			"port":              443,
			"protocol":          "tcp",
		})
		isolationReq := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(isolationReqBody), auth.RoleAnalyst, userID)
		isolationRec := callAuthed(h.FindIsolationChecks, isolationReq)
		if isolationRec.Code != http.StatusOK {
			t.Fatalf("isolation check: expected 200, got %d: %s", isolationRec.Code, isolationRec.Body.String())
		}
		var isolationResp struct {
			Results []struct {
				Severity string `json:"severity"`
			} `json:"results"`
		}
		if err := json.Unmarshal(isolationRec.Body.Bytes(), &isolationResp); err != nil {
			t.Fatalf("decode isolation check response: %v", err)
		}
		if len(isolationResp.Results) != 1 {
			t.Fatalf("expected exactly 1 isolation check result, got %d", len(isolationResp.Results))
		}
		indiaOutcome := isolationResp.Results[0].Severity
		if indiaOutcome == "" {
			t.Fatal("expected a non-empty severity from the real isolation check")
		}

		indiaObligationID := createTestObligation(t, h, pool, map[string]any{
			"jurisdiction":    "India",
			"regulator":       "RBI",
			"sector":          "Banking",
			"entityType":      "Regulated Financial Institution",
			"title":           "Network segmentation for critical payment/banking systems",
			"obligationType":  "mandatory",
			"sourceReference": "RBI Cyber Security Framework for Banks",
			"effectiveDate":   "2016-06-02T00:00:00Z",
			"version":         "RBI CSF 2016 (as amended)",
			"controlMappings": []map[string]any{
				{"canonicalId": "cm-1", "controlName": "Segmentation between critical payment-processing zones and the general corporate network", "capabilityName": "zoneisolation.isolation-check"},
			},
		})

		indiaSnapshotID, indiaSnapshotCode := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     indiaObligationID,
			"controlMappingId": "cm-1",
			"capabilityName":   "zoneisolation.isolation-check",
			"status":           "captured",
			"capturedOutcome":  indiaOutcome,
			"importReferences": map[string]string{
				"topologyImportId":  indiaTopoID,
				"isolationImportId": indiaIsolationID,
				"policyImportId":    indiaPolicy.ID,
			},
		})
		if indiaSnapshotCode != http.StatusCreated {
			t.Fatalf("expected 201 creating the India snapshot, got %d", indiaSnapshotCode)
		}

		// --- UAE: UAE Central Bank vendor remote-access obligation,
		// evidenced by a real remoteaccess.path-check result. The
		// tunnel's "state": "up" makes the route genuinely reachable. ---
		uaeTopoID := createNetworkTopologyImportForRemoteAccessTest(t, h, userID,
			[]map[string]any{
				{"name": "vendor-remote", "cidrs": []string{"10.30.0.0/24"}},
				{"name": "clinical-core", "cidrs": []string{"10.40.0.0/24"}},
			},
			[]map[string]any{},
		)
		uaeRemoteID := createRemoteAccessImportForPathTest(t, h, userID,
			[]map[string]any{
				{"canonicalId": "vpn-1", "fromZone": "vendor-remote", "toZone": "clinical-core", "state": "up"},
			},
		)

		remoteAccessReqBody, _ := json.Marshal(map[string]any{
			"topologyImportId":     uaeTopoID,
			"remoteAccessImportId": uaeRemoteID,
			"sourceHost":           "10.30.0.5",
			"destHost":             "10.40.0.5",
			"port":                 443,
			"protocol":             "tcp",
		})
		remoteAccessReq := authedRequest(t, http.MethodPost, "/api/remote-access-paths", bytes.NewReader(remoteAccessReqBody), auth.RoleAnalyst, userID)
		remoteAccessRec := callAuthed(h.FindRemoteAccessPaths, remoteAccessReq)
		if remoteAccessRec.Code != http.StatusOK {
			t.Fatalf("remote access path check: expected 200, got %d: %s", remoteAccessRec.Code, remoteAccessRec.Body.String())
		}
		var remoteAccessResp struct {
			Results []struct {
				State string `json:"state"`
			} `json:"results"`
		}
		if err := json.Unmarshal(remoteAccessRec.Body.Bytes(), &remoteAccessResp); err != nil {
			t.Fatalf("decode remote access path response: %v", err)
		}
		if len(remoteAccessResp.Results) != 1 {
			t.Fatalf("expected exactly 1 remote access path result, got %d", len(remoteAccessResp.Results))
		}
		uaeOutcome := remoteAccessResp.Results[0].State
		if uaeOutcome == "" {
			t.Fatal("expected a non-empty state from the real remote access path check")
		}

		uaeObligationID := createTestObligation(t, h, pool, map[string]any{
			"jurisdiction":    "UAE",
			"regulator":       "UAE Central Bank",
			"sector":          "Banking",
			"entityType":      "Regulated Financial Institution",
			"title":           "Third-party/vendor remote-access control for regulated financial institutions",
			"obligationType":  "mandatory",
			"sourceReference": "UAE Central Bank Information Assurance Standards",
			"effectiveDate":   "2018-01-01T00:00:00Z",
			"version":         "IAS 1.0",
			"controlMappings": []map[string]any{
				{"canonicalId": "cm-1", "controlName": "Vendor VPN/remote-access paths are routed only through approved, monitored channels", "capabilityName": "remoteaccess.path-check"},
			},
		})

		uaeSnapshotID, uaeSnapshotCode := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     uaeObligationID,
			"controlMappingId": "cm-1",
			"capabilityName":   "remoteaccess.path-check",
			"status":           "captured",
			"capturedOutcome":  uaeOutcome,
			"importReferences": map[string]string{
				"topologyImportId":     uaeTopoID,
				"remoteAccessImportId": uaeRemoteID,
			},
		})
		if uaeSnapshotCode != http.StatusCreated {
			t.Fatalf("expected 201 creating the UAE snapshot, got %d", uaeSnapshotCode)
		}

		// --- Both obligations must appear in the list, with their own
		// snapshots scoped correctly, no leakage. ---
		listReq := authedRequest(t, http.MethodGet, "/api/regulatory-obligations", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListRegulatoryObligations, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list obligations: expected 200, got %d: %s", listRec.Code, listRec.Body.String())
		}
		var obligationList []regobligation.Obligation
		if err := json.Unmarshal(listRec.Body.Bytes(), &obligationList); err != nil {
			t.Fatalf("decode obligation list: %v", err)
		}
		var sawIndia, sawUAE bool
		for _, ob := range obligationList {
			if ob.ID == indiaObligationID {
				sawIndia = true
			}
			if ob.ID == uaeObligationID {
				sawUAE = true
			}
		}
		if !sawIndia || !sawUAE {
			t.Fatalf("expected both India (%s) and UAE (%s) obligations in the list, sawIndia=%v sawUAE=%v",
				indiaObligationID, uaeObligationID, sawIndia, sawUAE)
		}

		indiaSnapshotsReq := authedRequest(t, http.MethodGet, "/api/regulatory-evidence-snapshots?obligationId="+indiaObligationID, nil, auth.RoleViewer, "")
		indiaSnapshotsRec := callAuthed(h.ListEvidenceSnapshots, indiaSnapshotsReq)
		var indiaSnapshots []regobligation.EvidenceSnapshot
		if err := json.Unmarshal(indiaSnapshotsRec.Body.Bytes(), &indiaSnapshots); err != nil {
			t.Fatalf("decode India snapshots: %v", err)
		}
		if len(indiaSnapshots) != 1 || indiaSnapshots[0].ID != indiaSnapshotID {
			t.Fatalf("expected exactly the India snapshot scoped to the India obligation, got %+v", indiaSnapshots)
		}
		if indiaSnapshots[0].CapabilityName != "zoneisolation.isolation-check" {
			t.Errorf("India snapshot capabilityName leaked/mismatched: %q", indiaSnapshots[0].CapabilityName)
		}

		uaeSnapshotsReq := authedRequest(t, http.MethodGet, "/api/regulatory-evidence-snapshots?obligationId="+uaeObligationID, nil, auth.RoleViewer, "")
		uaeSnapshotsRec := callAuthed(h.ListEvidenceSnapshots, uaeSnapshotsReq)
		var uaeSnapshots []regobligation.EvidenceSnapshot
		if err := json.Unmarshal(uaeSnapshotsRec.Body.Bytes(), &uaeSnapshots); err != nil {
			t.Fatalf("decode UAE snapshots: %v", err)
		}
		if len(uaeSnapshots) != 1 || uaeSnapshots[0].ID != uaeSnapshotID {
			t.Fatalf("expected exactly the UAE snapshot scoped to the UAE obligation, got %+v", uaeSnapshots)
		}
		if uaeSnapshots[0].CapabilityName != "remoteaccess.path-check" {
			t.Errorf("UAE snapshot capabilityName leaked/mismatched: %q", uaeSnapshots[0].CapabilityName)
		}
	})
}
