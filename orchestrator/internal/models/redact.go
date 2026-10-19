package models

import (
	"regexp"
	"strings"
)

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
		if a := results[i].DetectionAlert; a != nil && a.CommandLine != "" {
			// Copy rather than edit in place: the alert may be shared.
			alert := *a
			alert.CommandLine = WithholdCredentialHex(alert.CommandLine)
			results[i].DetectionAlert = &alert
		}
	}
}

// CredentialHexWithheld replaces hex runs long enough to be a hash or key
// (MD5 and longer) inside a value that is otherwise kept.
const CredentialHexWithheld = "[withheld-hex]"

var credentialHexRe = regexp.MustCompile(`[a-fA-F0-9]{32,}`)

// WithholdCredentialHex removes hash-shaped hex from a value, such as an NTLM
// hash passed on a command line, and returns the rest unchanged.
func WithholdCredentialHex(s string) string {
	return credentialHexRe.ReplaceAllString(s, CredentialHexWithheld)
}
