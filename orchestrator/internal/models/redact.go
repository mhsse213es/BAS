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

// RedactCredentialOutput makes run results safe to return outside the product,
// in place. Every result's raw output, details and alert command line have
// secret-shaped values withheld (tokens, keys, password assignments). For
// credential-access results the whole raw output and details are withheld,
// because those steps capture credential material (for example NTLM hashes
// from an LSASS dump). The name predates the secret scrub; it is kept so every
// export, report and list call site is unchanged.
func RedactCredentialOutput(results []SimulationResult) {
	for i := range results {
		results[i].RawOutput = WithholdSecrets(results[i].RawOutput)
		results[i].Details = WithholdSecrets(results[i].Details)
		if a := results[i].DetectionAlert; a != nil && a.CommandLine != "" {
			// Copy rather than edit in place: the alert may be shared.
			alert := *a
			alert.CommandLine = WithholdSecrets(alert.CommandLine)
			results[i].DetectionAlert = &alert
		}
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

// SecretWithheld replaces a secret-shaped value inside output that is otherwise kept.
const SecretWithheld = "[withheld: secret]"

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]{16,}=*`),
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	// A keyword at a word boundary, then a value of 16+ non-space characters.
	// The boundary stops suffix matches such as max_token_count=..., and the
	// length floor stops prose such as "token: pending approval" from matching.
	regexp.MustCompile(`(?i)\b((?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*)\S{16,}`),
}

// WithholdSecrets replaces the secret-shaped parts of a value. A credential
// assignment keeps its name (password=...) and loses only the value.
func WithholdSecrets(s string) string {
	for _, re := range secretPatterns {
		if re.NumSubexp() == 1 {
			s = re.ReplaceAllString(s, "${1}"+SecretWithheld)
			continue
		}
		s = re.ReplaceAllString(s, SecretWithheld)
	}
	return s
}
