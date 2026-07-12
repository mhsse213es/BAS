package api

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func campaignReq(path, campaignID, query string) *http.Request {
	if query != "" {
		path += "?" + query
	}
	return withURLParam(httptest.NewRequest(http.MethodGet, path, nil), "id", campaignID)
}

func seedCampaignWithRuns(t *testing.T, pool *pgxpool.Pool, campaignID string) {
	seedCampaign(t, pool, campaignID, "Fleet Scenario")
	seedReportableRun(t, pool, campaignID+"-r1", campaignID+"-a1", reportRunOpts{CampaignID: campaignID, TechniqueOverride: "T1059.001"})
	seedReportableRun(t, pool, campaignID+"-r2", campaignID+"-a2", reportRunOpts{CampaignID: campaignID, TechniqueOverride: "T1003.001"})
}

func TestGetCampaignReport_HTML(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaignWithRuns(t, pool, "camp-html")
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetCampaignReport(rec, campaignReq("/api/campaigns/camp-html/report", "camp-html", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "T1059.001") || !strings.Contains(body, "T1003.001") {
			t.Fatal("campaign HTML report should aggregate both child runs' techniques")
		}
	})
}

func TestGetCampaignReport_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetCampaignReport(rec, campaignReq("/api/campaigns/nope/report", "nope", ""))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetCampaignPDF_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaignWithRuns(t, pool, "camp-pdf")
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetCampaignPDF(rec, campaignReq("/api/campaigns/camp-pdf/pdf", "camp-pdf", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if !strings.HasPrefix(rec.Body.String(), "%PDF") {
			t.Fatal("body is not a PDF")
		}
		if !regexp.MustCompile(`filename="bas-campaign-.*\.pdf"`).MatchString(rec.Header().Get("Content-Disposition")) {
			t.Fatalf("content-disposition = %q", rec.Header().Get("Content-Disposition"))
		}
	})
}

func TestGetCampaignPDF_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetCampaignPDF(rec, campaignReq("/api/campaigns/nope/pdf", "nope", ""))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetCampaignCSV_AllChildRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaignWithRuns(t, pool, "camp-csv")
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetCampaignCSV(rec, campaignReq("/api/campaigns/camp-csv/forensic.csv", "camp-csv", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "T1059.001") || !strings.Contains(body, "T1003.001") {
			t.Fatal("campaign CSV should include rows from both child runs")
		}
		if !regexp.MustCompile(`filename="bas-campaign-forensic-.*\.csv"`).MatchString(rec.Header().Get("Content-Disposition")) {
			t.Fatalf("content-disposition = %q", rec.Header().Get("Content-Disposition"))
		}
		// unknown campaign → 404
		rec2 := httptest.NewRecorder()
		h.GetCampaignCSV(rec2, campaignReq("/api/campaigns/nope/forensic.csv", "nope", ""))
		if rec2.Code != http.StatusNotFound {
			t.Fatalf("unknown campaign: status = %d, want 404", rec2.Code)
		}
	})
}

func TestGetCampaignCSV_FilterApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaignWithRuns(t, pool, "camp-csv-f")
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetCampaignCSV(rec, campaignReq("/api/campaigns/camp-csv-f/forensic.csv", "camp-csv-f", "filter=prevented"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		// Both override techniques are FAILs → prevented filter drops them both.
		body := rec.Body.String()
		if strings.Contains(body, "T1059.001") || strings.Contains(body, "T1003.001") {
			t.Fatalf("filter=prevented should drop the failing rows:\n%s", body)
		}
		if !strings.Contains(rec.Header().Get("Content-Disposition"), "-prevented-") {
			t.Fatalf("filename missing -prevented- suffix: %q", rec.Header().Get("Content-Disposition"))
		}
	})
}
