package reporting

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/dbsim"
)

func TestDBSimReportHeaders(t *testing.T) {
	h := http.Header{}
	SetDBSimReportHeaders(h)
	if h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		t.Fatalf("headers: %v", h)
	}
}

func TestReportSummaryMatchesSummarize(t *testing.T) {
	r := dbsimTestReport("dbsim-db03-unauthorized-access", dbsim.ResultFail, dbsim.Dimensions{
		Prevention: dbsim.DimPass, Detection: dbsim.DimFail, Response: dbsim.DimNotExpected,
		Classification: dbsim.DimNotExpected, Audit: dbsim.DimNotExpected, Policy: dbsim.DimNotExpected,
	})
	s := dbsim.Summarize([]dbsim.StoredReport{r})
	out := dbsimRender(t, r)
	for _, want := range []string{
		"<td>" + strconv.Itoa(s.PreventionBlocked) + " / " + strconv.Itoa(s.PreventionAssessable) + "</td>",
		"<td>" + strconv.Itoa(s.DetectionCaught) + " / " + strconv.Itoa(s.DetectionAssessable) + "</td>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary cell %q missing", want)
		}
	}
}
