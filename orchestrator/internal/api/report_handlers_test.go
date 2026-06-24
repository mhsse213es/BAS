package api

import "testing"

func TestReportDownloadPath(t *testing.T) {
	cases := []struct {
		name, rtype, format, agent, fw, filter string
		want                                   string
		wantErr                                bool
	}{
		{"posture pdf", "posture", "pdf", "WIN-01", "", "", "/api/report/full/pdf?agentId=WIN-01", false},
		{"posture html", "posture", "html", "WIN-01", "", "", "/api/report/full/html?agentId=WIN-01", false},
		{"audit", "audit", "", "WIN-01", "", "", "/api/report/audit-pack?agentId=WIN-01", false},
		{"compliance", "compliance", "pdf", "WIN-01", "NIST", "", "/api/compliance/report?framework=NIST&agentId=WIN-01&format=pdf", false},
		{"posture with filter", "posture", "pdf", "WIN-01", "", "prevented", "/api/report/full/pdf?agentId=WIN-01&filter=prevented", false},
		{"posture no agent", "posture", "pdf", "", "", "", "", true},
		{"compliance no fw", "compliance", "html", "WIN-01", "", "", "", true},
		{"bad type", "executive", "pdf", "WIN-01", "", "", "", true},
	}
	for _, c := range cases {
		got, err := reportDownloadPath(c.rtype, c.format, c.agent, c.fw, c.filter)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: want error, got %q", c.name, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got (%q, %v), want %q", c.name, got, err, c.want)
		}
	}
}
