package scenario

import "testing"

// A missing prerequisite or an absent required binary means the environment
// could not run the technique at all — it was never tested. That is a SKIP
// (not applicable here), not a BAS execution error, so it must not FAIL a
// factory validation. Genuine execution problems stay errors.
func TestClassifyExecution_PrereqAndBinaryAreSkippedNotErrored(t *testing.T) {
	cases := []struct {
		name     string
		combined string
		want     ExecutionOutcome
	}{
		{"binary missing (nmap)", "nmap : The term 'nmap' is not recognized as the name of a cmdlet", OutcomeSkipped},
		{"missing prerequisite (path)", "Cannot find path 'C:\\x' because it does not exist", OutcomeSkipped},
		{"generic execution error stays error", "something unexpected happened here", OutcomeError},
		{"malformed content stays error", "ParserError: unexpected token in expression", OutcomeError},
	}
	for _, c := range cases {
		out, _, detail := classifyExecution(ExecResult{ExitCode: 1}, c.combined)
		if out != c.want {
			t.Errorf("%s: outcome = %v, want %v (detail=%q)", c.name, out, c.want, detail)
		}
	}
}
