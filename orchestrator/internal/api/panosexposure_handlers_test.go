package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/panosexposure"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// Synthetic advisory and versions. Test fixtures only, not vendor data.
const panosTestBody = `{
  "advisory": {
    "cve": "CVE-TEST-0001",
    "source": "fixture: synthetic advisory",
    "affected": [{"introduced": "10.2.0", "fixedIn": "10.2.4-h2"}],
    "conditions": {"requireGlobalProtect": true, "requireAuthOverride": true, "requireSharedCert": true}
  },
  "assets": [
    {"id": "fw-vuln", "product": "pan-os", "version": "10.2.1", "globalProtect": "yes", "authOverride": "yes", "sharedOverrideCert": "yes"},
    {"id": "fw-patched", "product": "pan-os", "version": "10.2.5", "globalProtect": "yes", "authOverride": "yes", "sharedOverrideCert": "yes"},
    {"id": "fw-unknown", "product": "pan-os", "version": "10.2.1", "globalProtect": "yes", "authOverride": "unknown", "sharedOverrideCert": "yes"}
  ]
}`

func postPANOSAssess(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	req := httptest.NewRequest(http.MethodPost, "/api/panos-exposure/assess", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.AssessPANOSExposure(rec, req)
	return rec
}

func TestAssessPANOSExposure_ReturnsVerdictPerAsset(t *testing.T) {
	rec := postPANOSAssess(t, panosTestBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		CVE     string                 `json:"cve"`
		Results []panosexposure.Result `json:"results"`
		Counts  map[string]int         `json:"counts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.CVE != "CVE-TEST-0001" || len(out.Results) != 3 {
		t.Fatalf("unexpected response: %+v", out)
	}
	want := map[string]panosexposure.Verdict{
		"fw-vuln":    panosexposure.VerdictVulnerable,
		"fw-patched": panosexposure.VerdictNotAffected,
		"fw-unknown": panosexposure.VerdictUnknown,
	}
	for _, r := range out.Results {
		if r.Verdict != want[r.AssetID] {
			t.Fatalf("asset %s: verdict = %s, want %s", r.AssetID, r.Verdict, want[r.AssetID])
		}
	}
	if out.Counts["vulnerable"] != 1 || out.Counts["not_affected"] != 1 || out.Counts["unknown"] != 1 {
		t.Fatalf("counts = %v", out.Counts)
	}
}

func TestAssessPANOSExposure_RejectsEmptyAssets(t *testing.T) {
	body := `{"advisory": {"cve": "CVE-TEST-0001", "affected": [{"introduced": "10.2.0", "fixedIn": "10.2.4"}]}, "assets": []}`
	if rec := postPANOSAssess(t, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAssessPANOSExposure_RejectsUnknownFields(t *testing.T) {
	body := strings.Replace(panosTestBody, `"assets": [`, `"surprise": true, "assets": [`, 1)
	if rec := postPANOSAssess(t, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown field", rec.Code)
	}
}

func TestAssessPANOSExposure_RejectsTrailingData(t *testing.T) {
	if rec := postPANOSAssess(t, panosTestBody+` {"extra": 1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for trailing data", rec.Code)
	}
}

func TestAssessPANOSExposure_RejectsTooManyAssets(t *testing.T) {
	var assets []string
	for i := 0; i <= maxPANOSAssets; i++ {
		assets = append(assets, fmt.Sprintf(`{"id":"fw-%d","product":"pan-os","version":"10.2.5"}`, i))
	}
	body := fmt.Sprintf(`{"advisory":{"cve":"CVE-TEST-0001","affected":[{"introduced":"10.2.0","fixedIn":"10.2.4"}]},"assets":[%s]}`,
		strings.Join(assets, ","))
	if rec := postPANOSAssess(t, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 above %d assets", rec.Code, maxPANOSAssets)
	}
}

func TestAssessPANOSExposure_RegistryPathNamesTheRevision(t *testing.T) {
	body := `{"advisoryCve":"CVE-2026-0257","assets":[
	  {"id":"fw-1","product":"pan-os","version":"11.2.8","globalProtect":"yes","authOverride":"yes","sharedOverrideCert":"yes"}]}`
	rec := postPANOSAssess(t, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		AdvisoryVersion string                 `json:"advisoryVersion"`
		AdvisoryStatus  string                 `json:"advisoryStatus"`
		Results         []panosexposure.Result `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.AdvisoryVersion != "CVE-2026-0257 rev 1" || out.AdvisoryStatus != "verified" {
		t.Fatalf("advisory = %q (%s)", out.AdvisoryVersion, out.AdvisoryStatus)
	}
	if out.Results[0].AdvisoryVersion != "CVE-2026-0257 rev 1" {
		t.Fatalf("result did not record the revision: %q", out.Results[0].AdvisoryVersion)
	}
	if out.Results[0].Verdict != panosexposure.VerdictVulnerable {
		t.Fatalf("verdict = %s", out.Results[0].Verdict)
	}
}

func TestAssessPANOSExposure_RegistryRejectsUnknownCVEAndRevision(t *testing.T) {
	for _, body := range []string{
		`{"advisoryCve":"CVE-9999-0000","assets":[{"id":"x","product":"pan-os","version":"11.2.8"}]}`,
		`{"advisoryCve":"CVE-2026-0257","advisoryRevision":99,"assets":[{"id":"x","product":"pan-os","version":"11.2.8"}]}`,
	} {
		if rec := postPANOSAssess(t, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for %s", rec.Code, body)
		}
	}
}

func TestAssessPANOSExposure_RejectsBothOrNeitherAdvisory(t *testing.T) {
	both := `{"advisoryCve":"CVE-2026-0257","advisory":{"cve":"CVE-X","affected":[{"introduced":"10.2.0","fixedIn":"10.2.4"}]},
	  "assets":[{"id":"x","product":"pan-os","version":"11.2.8"}]}`
	neither := `{"assets":[{"id":"x","product":"pan-os","version":"11.2.8"}]}`
	for _, body := range []string{both, neither} {
		if rec := postPANOSAssess(t, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for %s", rec.Code, body)
		}
	}
}

func TestAssessPANOSExposure_CallerSuppliedIsLabelled(t *testing.T) {
	rec := postPANOSAssess(t, panosTestBody)
	if !strings.Contains(rec.Body.String(), "has not verified it") {
		t.Fatalf("caller-supplied advisory must say it is not verified by Audspect: %s", rec.Body.String())
	}
}

func TestAssessPANOSExposure_EachResultCarriesAdvisoryStatus(t *testing.T) {
	reg := postPANOSAssess(t, `{"advisoryCve":"CVE-2026-0257","assets":[{"id":"a","product":"pan-os","version":"11.2.8"}]}`)
	if !strings.Contains(reg.Body.String(), `"advisoryStatus":"verified"`) {
		t.Fatalf("registry result must state verified: %s", reg.Body.String())
	}
	legacy := postPANOSAssess(t, panosTestBody)
	if !strings.Contains(legacy.Body.String(), `"advisoryStatus":"caller-supplied"`) {
		t.Fatalf("legacy result must state caller-supplied: %s", legacy.Body.String())
	}
}
