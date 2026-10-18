package defender

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestListMachines_ReturnsNormalizedMachines proves every field this
// client maps is read from the real, documented Microsoft field names
// (learn.microsoft.com/defender-endpoint/api/machine) -- a fixture
// using the wrong key would silently leave the mapped field at its
// zero value, which this test also asserts isn't the case.
func TestListMachines_ReturnsNormalizedMachines(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	firstSeen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	lastSeen := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	machinesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "machine-1", "computerDnsName": "HOST1", "osPlatform": "Windows11",
					"osArchitecture": "64-bit", "onboardingStatus": "Onboarded",
					"healthStatus": "Active", "riskScore": "Low", "exposureLevel": "Medium",
					"deviceValue": "Normal", "rbacGroupId": "grp-1", "rbacGroupName": "Default",
					"firstSeen": firstSeen.Format(time.RFC3339), "lastSeen": lastSeen.Format(time.RFC3339),
					"lastIpAddress": "10.0.0.5", "aadDeviceId": "aad-1",
					"machineTags": []string{"lab"},
				},
			},
		})
	}))
	defer machinesSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, machinesSrv.URL)
	machines, err := c.ListMachines(context.Background())
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	if len(machines) != 1 {
		t.Fatalf("machines = %+v, want 1", machines)
	}
	m := machines[0]
	if m.ID != "machine-1" || m.ComputerDNSName != "HOST1" || m.OSPlatform != "Windows11" ||
		m.OSArchitecture != "64-bit" || m.OnboardingStatus != "Onboarded" || m.HealthStatus != "Active" ||
		m.RiskScore != "Low" || m.ExposureLevel != "Medium" || m.DeviceValue != "Normal" ||
		m.RBACGroupID != "grp-1" || m.RBACGroupName != "Default" || m.LastIPAddress != "10.0.0.5" ||
		m.AADDeviceID != "aad-1" || len(m.MachineTags) != 1 || m.MachineTags[0] != "lab" {
		t.Fatalf("machine = %+v, missing or wrong field(s)", m)
	}
	if !m.FirstSeen.Equal(firstSeen) {
		t.Errorf("FirstSeen = %v, want %v", m.FirstSeen, firstSeen)
	}
	if !m.LastSeen.Equal(lastSeen) {
		t.Errorf("LastSeen = %v, want %v", m.LastSeen, lastSeen)
	}
}

// TestListMachines_FollowsODataNextLink proves pagination genuinely
// follows the real @odata.nextLink field across pages until it's
// absent, rather than reading only the first page.
func TestListMachines_FollowsODataNextLink(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var page2URL string
	mux := http.NewServeMux()
	mux.HandleFunc("/machines", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value":           []map[string]any{{"id": "machine-1", "computerDnsName": "HOST1"}},
			"@odata.nextLink": page2URL,
		})
	})
	mux.HandleFunc("/machines/page2", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{{"id": "machine-2", "computerDnsName": "HOST2"}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	page2URL = srv.URL + "/machines/page2"

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, srv.URL)
	machines, err := c.ListMachines(context.Background())
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	if len(machines) != 2 {
		t.Fatalf("machines = %+v, want 2 (one from each page)", machines)
	}
	if machines[0].ID != "machine-1" || machines[1].ID != "machine-2" {
		t.Fatalf("machines = %+v, want machine-1 then machine-2", machines)
	}
}

// TestListMachines_ForbiddenWithDisabledFeature_ReturnsClassifiedError
// proves the real licensing signal (item #5's requirement) propagates
// out of ListMachines as a *ClassifiedError a caller can inspect via
// errors.As, not just a generic formatted error string.
func TestListMachines_ForbiddenWithDisabledFeature_ReturnsClassifiedError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	machinesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"code": "DisabledFeature", "message": "Tenant feature isn't enabled.", "target": "x"},
		})
	}))
	defer machinesSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, machinesSrv.URL)
	_, err := c.ListMachines(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	var ce *ClassifiedError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want a *ClassifiedError", err)
	}
	if ce.Kind != ErrKindFeatureDisabled {
		t.Errorf("Kind = %v, want ErrKindFeatureDisabled", ce.Kind)
	}
}

func TestListMachines_MalformedPayload_ReturnsError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	machinesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer machinesSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, machinesSrv.URL)
	if _, err := c.ListMachines(context.Background()); err == nil {
		t.Fatal("expected an error for a malformed response body")
	}
}

func TestListMachines_RateLimited_ReturnsClassifiedError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	machinesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"code": "TooManyRequests", "message": "quota exceeded", "target": "x"},
		})
	}))
	defer machinesSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, machinesSrv.URL)
	_, err := c.ListMachines(context.Background())
	var ce *ClassifiedError
	if !errors.As(err, &ce) || ce.Kind != ErrKindRateLimited {
		t.Fatalf("err = %v, want a *ClassifiedError with Kind ErrKindRateLimited", err)
	}
}

func TestListMachines_TransientServerError_ReturnsClassifiedError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	machinesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer machinesSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, machinesSrv.URL)
	_, err := c.ListMachines(context.Background())
	var ce *ClassifiedError
	if !errors.As(err, &ce) || ce.Kind != ErrKindTransient {
		t.Fatalf("err = %v, want a *ClassifiedError with Kind ErrKindTransient", err)
	}
}
