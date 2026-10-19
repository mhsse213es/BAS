package ioc

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

const credentialDumpNTLM = "aad3b435b51404eeaad3b435b51404ee"

// A credential-access step's dumped NTLM hash is credential material, not a
// threat indicator, and must not be stored in run_iocs (served by /iocs).
// The same 32-hex shape from an ordinary step is a legitimate file hash and
// must still be extracted.
func TestBuildRunIndicators_CredentialAccessHashNotStored(t *testing.T) {
	execs := []scenario.ExecResult{
		{TaskID: "cred", Stdout: "Administrator:500:" + credentialDumpNTLM + ":::"},
		{TaskID: "exec", Stdout: "file digest b1946ac92492d2347c6235b4d2611184"},
	}
	steps := map[string]scenario.Step{
		"cred": {TechniqueID: "T1003.001"},
		"exec": {TechniqueID: "T1059.001"},
	}
	inds := BuildRunIndicators(execs, nil, steps)

	var sawCredential, sawFileHash bool
	for _, ind := range inds {
		if ind.Type != "hash" {
			continue
		}
		if ind.Value == credentialDumpNTLM {
			sawCredential = true
		}
		if ind.Value == "b1946ac92492d2347c6235b4d2611184" {
			sawFileHash = true
		}
	}
	if sawCredential {
		t.Fatal("credential-access hash was stored as a run indicator")
	}
	if !sawFileHash {
		t.Fatal("non-credential 32-hex hash was dropped; only credential-access hashes may be withheld")
	}
}
