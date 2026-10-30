package rwevidence

import "testing"

// SinkDataProtectionStatus maps the sink evidence for one step to the status
// string DataProtectionFromDLPResult consumes. A receipt means the data reached
// the sink, so DLP did not stop it (NotDetected). No receipt is NOT proof of a
// block, because transport failure looks identical, so it stays Unknown (fail
// closed). Anything other than exactly one token is ambiguous and also Unknown.
func TestSinkDataProtectionStatus(t *testing.T) {
	cases := []struct {
		name     string
		tokens   int
		receipts int
		want     string
	}{
		{"no sink token means the step did not use the sink", 0, 0, ""},
		{"token issued and receipt received means data reached the sink", 1, 1, "NotDetected"},
		{"token issued but no receipt is not proof of a block", 1, 0, "Unknown"},
		{"two tokens for one run and technique is ambiguous", 2, 1, "Unknown"},
		{"two tokens with no receipt is ambiguous", 2, 0, "Unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := SinkDataProtectionStatus(tc.tokens, tc.receipts)
			if got != tc.want {
				t.Fatalf("SinkDataProtectionStatus(%d, %d) = %q, want %q", tc.tokens, tc.receipts, got, tc.want)
			}
		})
	}
}
