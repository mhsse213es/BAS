package scenario

import (
	"os"
	"strings"
	"testing"
)

// Carbanak BFSI plan Task 3: collection and exfiltration scenarios. Scenarios 29-31 write
// synthetic data to a run-specific temp folder and must remove everything they create in a
// finally block. Scenario 32 must send only synthetic bytes, and only to a .invalid name.
var carbanakTask3 = []struct {
	file, id, technique string
	writesSynthetic     bool
}{
	{"carbanak-bfsi-document-collection.yaml", "carbanak-bfsi-document-collection", "T1005", true},
	{"carbanak-bfsi-db-staging.yaml", "carbanak-bfsi-db-staging", "T1074.001", true},
	{"carbanak-bfsi-archive-records.yaml", "carbanak-bfsi-archive-records", "T1560.001", true},
	{"carbanak-bfsi-https-exfil-sim.yaml", "carbanak-bfsi-https-exfil-sim", "T1567", false}, // was T1041: that is exfiltration over an existing C2 channel, which this scenario does not have
}

func TestCarbanakBFSITask3Scenarios(t *testing.T) {
	for _, c := range carbanakTask3 {
		b, err := os.ReadFile("../../../scenarios/" + c.file)
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		s := string(b)
		idLine := "id: " + c.id + "\n"
		if !strings.HasPrefix(s, idLine) && !strings.Contains(s, "\n"+idLine) {
			t.Errorf("%s: id %q missing", c.file, c.id)
		}
		if !strings.Contains(s, "technique_id: "+c.technique+"\n") {
			t.Errorf("%s: technique_id %q missing", c.file, c.technique)
		}
		if c.writesSynthetic {
			if !strings.Contains(s, "finally") || !strings.Contains(s, "Remove-Item") {
				t.Errorf("%s: writes synthetic data but has no Remove-Item in a finally block", c.file)
			}
			if !strings.Contains(s, "Synthetic") {
				t.Errorf("%s: must state that the data it writes is synthetic", c.file)
			}
		} else {
			if !strings.Contains(s, ".invalid") {
				t.Errorf("%s: destination must be a .invalid name", c.file)
			}
			if !strings.Contains(s, "REFUSED") {
				t.Errorf("%s: must refuse a destination that is not a .invalid name", c.file)
			}
			if !strings.Contains(s, "Synthetic") {
				t.Errorf("%s: payload must be stated as synthetic", c.file)
			}
		}
	}
}
