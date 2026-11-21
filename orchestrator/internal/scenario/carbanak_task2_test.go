package scenario

import (
	"os"
	"strings"
	"testing"
)

// Carbanak BFSI plan Task 2: lateral-movement scenarios. Each must skip with a clear
// SKIP line when BAS_CARBANAK_TARGET_HOST is unset (never PASS), refuse a host without a
// .lab or .test label, and the two that create objects on the target (21, 22) must
// remove what they create.
var carbanakTask2 = []struct {
	file, id, technique string
	createsObject       bool
}{
	{"carbanak-bfsi-smb-admin-share.yaml", "carbanak-bfsi-smb-admin-share", "T1021.002", false},
	{"carbanak-bfsi-winrm-exec.yaml", "carbanak-bfsi-winrm-exec", "T1021.006", false},
	{"carbanak-bfsi-remote-service.yaml", "carbanak-bfsi-remote-service", "T1569.002", true},
	{"carbanak-bfsi-remote-task.yaml", "carbanak-bfsi-remote-task", "T1053.005", true},
}

func TestCarbanakBFSITask2Scenarios(t *testing.T) {
	for _, c := range carbanakTask2 {
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
		if !strings.Contains(s, "$env:BAS_CARBANAK_TARGET_HOST") {
			t.Errorf("%s: no target-host gate", c.file)
		}
		if !strings.Contains(s, "SKIP: ") {
			t.Errorf("%s: no SKIP line when the target host is unset", c.file)
		}
		if !strings.Contains(s, `\.(lab|test)$`) {
			t.Errorf("%s: host label check (.lab or .test) missing", c.file)
		}
		if c.createsObject && !strings.Contains(s, "finally") {
			t.Errorf("%s: creates an object on the target but has no cleanup in a finally block", c.file)
		}
	}
}
