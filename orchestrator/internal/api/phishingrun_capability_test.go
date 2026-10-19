package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/phishscope"

	"github.com/audspect/bas/internal/phishcatalog"
)

// poolOnly is a non-nil pool for capability checks. The capability check never
// queries it, so an empty pool is enough.
func poolOnly() PhishingRunExecutorEnv {
	return PhishingRunExecutorEnv{Pool: &pgxpool.Pool{}}
}

func TestPhishingCapability_MissingDependencyIsUnavailableWithReason(t *testing.T) {
	cases := map[string]string{
		"PH-ID-002":  "identity_connector_not_configured",
		"PH-ID-003":  "identity_connector_not_configured",
		"PH-ID-004":  "identity_connector_not_configured",
		"PH-ID-005":  "identity_connector_not_configured",
		"PH-CHN-004": "calendar_connector_not_configured",
		"PH-DET-002": "itsm_connector_not_configured",
	}
	for id, reason := range cases {
		c := phishingCapabilityFor(poolOnly(), id, false)
		if c.Status != CapUnavailable || c.Reason != reason {
			t.Errorf("%s: got status=%q reason=%q, want unavailable/%s", id, c.Status, c.Reason, reason)
		}
	}
}

func TestPhishingCapability_PoolOnlyScenariosAvailable(t *testing.T) {
	for _, id := range []string{"PH-ID-001", "PH-IR-003", "PH-EVA-002", "PH-AUTH-002", "PH-CHN-005"} {
		if c := phishingCapabilityFor(poolOnly(), id, false); c.Status != CapAvailable {
			t.Errorf("%s: status=%q, want available", id, c.Status)
		}
	}
}

func TestPhishingCapability_NotRegisteredIsCatalogOnly(t *testing.T) {
	c := phishingCapabilityFor(poolOnly(), "PH-CHN-001", false)
	if c.Status != CapCatalogOnly || c.Reason != "not_registered" {
		t.Errorf("PH-CHN-001: got status=%q reason=%q, want catalog_only/not_registered", c.Status, c.Reason)
	}
}

// An experimental scenario stays experimental. Wiring its dependency does not
// make it reliable, and a missing dependency must not hide that it is experimental.
func TestPhishingCapability_ExperimentalStaysExperimental(t *testing.T) {
	wired := PhishingRunExecutorEnv{Pool: &pgxpool.Pool{}, IdentityReader: fakeIdentityReader{},
		IdentityScope: phishscope.Scope{Users: []string{"alice@contoso.example"}}}
	if c := phishingCapabilityFor(wired, "PH-ID-004", true); c.Status != CapExperimental {
		t.Errorf("wired experimental: status=%q, want experimental", c.Status)
	}
	if c := phishingCapabilityFor(poolOnly(), "PH-ID-004", true); c.Status != CapUnavailable {
		t.Errorf("unwired experimental: status=%q, want unavailable", c.Status)
	}
}

// Every registered scenario must declare its dependency row, so a new executor
// cannot be made runnable without its capability being stated.
func TestPhishingCapability_EveryRegisteredScenarioDeclared(t *testing.T) {
	cat, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	for _, sc := range cat {
		if _, ok := LookupPhishingRunExecutor(sc.ID); !ok {
			continue
		}
		if _, ok := phishingScenarioDeps[sc.ID]; !ok {
			t.Errorf("%s is registered but has no dependency declaration", sc.ID)
		}
	}
}

// The trigger refuses an unavailable scenario before it creates a run, so a
// crafted request cannot bypass a missing dependency. The handler has no database
// here, so a run attempt would fail loudly if the gate were missing.
func TestTriggerPhishingRun_UnavailableRefusedBeforeRun(t *testing.T) {
	h := &Handler{db: &pgxpool.Pool{}}
	body := `{"scenarioId":"PH-ID-004","parameters":{"userId":"u","threshold":3,"windowSeconds":600}}`
	rec := httptest.NewRecorder()
	h.TriggerPhishingRun(rec, httptest.NewRequest(http.MethodPost, "/api/phishing-runs", strings.NewReader(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d, want 409 for an unwired identity scenario", rec.Code)
	}
	var resp struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !strings.Contains(rec.Body.String(), "identity_connector_not_configured") {
		t.Errorf("body %q must name the missing dependency", rec.Body.String())
	}
}
