package scenario

import (
	"os"
	"strings"
	"testing"
)

// Carbanak BFSI plan Task 1: discovery and credential-access scenarios. Each file must
// exist with its id and technique. The two credential-store probes (14, 15) must check
// existence only: their commands may not read any stored secret.
var carbanakTask1 = []struct {
	file, id, technique string
	existenceOnly       bool
}{
	{"carbanak-bfsi-gateway-discovery.yaml", "carbanak-bfsi-gateway-discovery", "T1083", false},
	{"carbanak-bfsi-db-discovery.yaml", "carbanak-bfsi-db-discovery", "T1046", false},
	{"carbanak-bfsi-priv-enum.yaml", "carbanak-bfsi-priv-enum", "T1069.002", false},
	{"carbanak-bfsi-share-discovery.yaml", "carbanak-bfsi-share-discovery", "T1135", false},
	{"carbanak-bfsi-credman-probe.yaml", "carbanak-bfsi-credman-probe", "T1555.004", true},
	{"carbanak-bfsi-browser-probe.yaml", "carbanak-bfsi-browser-probe", "T1555.003", true},
	{"carbanak-bfsi-kerberos-enum.yaml", "carbanak-bfsi-kerberos-enum", "T1558.003", false},
	{"carbanak-bfsi-synthetic-cred-discovery.yaml", "carbanak-bfsi-synthetic-cred-discovery", "T1552", false},
}

var forbiddenStoreReads = []string{"ReadAllBytes", "ReadAllText", "Login Data", "Local State", "Get-StoredCredential", "PROCESS_VM_READ", "Copy-Item"}

func TestCarbanakBFSITask1Scenarios(t *testing.T) {
	for _, c := range carbanakTask1 {
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
		if c.existenceOnly {
			for _, bad := range forbiddenStoreReads {
				if strings.Contains(s, bad) {
					t.Errorf("%s: must check existence only, found %q", c.file, bad)
				}
			}
		}
	}
}
