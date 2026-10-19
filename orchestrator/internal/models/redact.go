package models

import "strings"

const (
	// CredentialOutputWithheld replaces raw output of credential-access steps
	// wherever run data leaves the product (exports, report JSON).
	CredentialOutputWithheld = "[withheld: credential-access output is not exported]"
	credentialAccessTactic   = "credential-access"
)

// RedactCredentialOutput withholds the raw output and details of every
// credential-access result in place. Those steps capture credential material
// (for example NTLM hashes from an LSASS dump), which must not be exported to
// any role that can read the run. Other results are left untouched.
func RedactCredentialOutput(results []SimulationResult) {
	for i := range results {
		if !strings.EqualFold(results[i].Technique.Tactic, credentialAccessTactic) {
			continue
		}
		results[i].RawOutput = CredentialOutputWithheld
		results[i].Details = CredentialOutputWithheld
	}
}
