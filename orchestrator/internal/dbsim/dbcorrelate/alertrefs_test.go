package dbcorrelate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/detectverify"
)

func rawAlert(id, rule, host string, at time.Time, source map[string]any, truncated bool) detectverify.MatchedAlert {
	doc := map[string]any{"alertId": id, "ruleName": rule, "source": source}
	if truncated {
		doc["sourceTruncated"] = true
	}
	raw, _ := json.Marshal(doc)
	return detectverify.MatchedAlert{AlertID: id, RuleName: rule, Timestamp: at, RawJSON: raw}
}

func TestAlertRefsKeepOnlyWhatTheReportNeeds(t *testing.T) {
	stmt := strings.Repeat("A", 2000) + " /* dbsim:" + corrMarkerA + " */ SELECT * FROM t WHERE password=hunter2 " + strings.Repeat("B", 2000)
	a := rawAlert("al-1", "BAS rule", "dbsim-pg", corrT0, map[string]any{
		"message": stmt, "host.name": "dbsim-pg", "event.original": stmt, "user.name": "dbsim_lab",
		"kibana.alert.reason": "very long reason " + strings.Repeat("R", 5000),
	}, false)
	refs := AlertRefs([]detectverify.MatchedAlert{a}, corrMarkerA)
	if len(refs) != 1 {
		t.Fatalf("refs %d", len(refs))
	}
	r := refs[0]
	if r.ID != "al-1" || r.Rule != "BAS rule" || r.Host != "dbsim-pg" || !r.Time.Equal(corrT0) {
		t.Fatalf("ref %+v", r)
	}
	if len(r.Excerpt) == 0 || len(r.Excerpt) > dbsim.MaxAlertExcerptBytes {
		t.Fatalf("excerpt len %d", len(r.Excerpt))
	}
	if !strings.Contains(r.Excerpt, corrMarkerA) {
		t.Fatalf("excerpt lost the marker: %q", r.Excerpt)
	}
	if strings.Contains(r.Excerpt, "hunter2") {
		t.Fatalf("secret in excerpt: %q", r.Excerpt)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "RRRR") || strings.Contains(string(b), "user.name") {
		t.Fatalf("unneeded alert fields leaked: %s", b)
	}
}

func TestAlertRefsAreBoundedAndTolerateGarbage(t *testing.T) {
	var as []detectverify.MatchedAlert
	for i := 0; i < 40; i++ {
		as = append(as, corrAlert("a"+string(rune('a'+i%26)), corrT0, "q "+corrMarkerA))
	}
	as = append(as, detectverify.MatchedAlert{AlertID: "bad", RawJSON: json.RawMessage(`{not json`)})
	if n := len(AlertRefs(as, corrMarkerA)); n > dbsim.MaxAlertRefs {
		t.Fatalf("%d refs, cap %d", n, dbsim.MaxAlertRefs)
	}
	got := AlertRefs([]detectverify.MatchedAlert{{AlertID: "bad", RawJSON: json.RawMessage(`{not json`)}}, corrMarkerA)
	if len(got) != 1 || got[0].ID != "bad" {
		t.Fatalf("garbage alert dropped: %+v", got)
	}
}

func TestAlertRefsNestedHostAndNoMarker(t *testing.T) {
	a := rawAlert("n1", "r", "", corrT0, map[string]any{"host": map[string]any{"name": "dbsim-mysql"}, "message": "something else"}, false)
	refs := AlertRefs([]detectverify.MatchedAlert{a}, corrMarkerA)
	if refs[0].Host != "dbsim-mysql" || refs[0].Excerpt != "" {
		t.Fatalf("%+v", refs[0])
	}
}
