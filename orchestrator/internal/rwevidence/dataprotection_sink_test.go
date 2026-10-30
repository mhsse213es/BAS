package rwevidence

import "testing"

// SinkDataProtectionStatus maps the sink's evidence for one step to a status.
//
//   - A data receipt means the payload reached the sink, so DLP did not stop it
//     (NotDetected).
//   - A probe receipt with no data receipt means the sink was reachable from the
//     same path, and only the sensitive payload never arrived. That is a block
//     (Detected).
//   - No receipt at all is not proof of a block: a transport failure looks the
//     same, so it stays Unknown (fail closed).
//   - More than one token for the same run and technique is ambiguous (Unknown).
//   - Zero tokens means the step never used the sink and returns "".
func TestSinkDataProtectionStatus(t *testing.T) {
	cases := []struct {
		name     string
		tokens   int
		data     int
		probe    int
		want     string
	}{
		{"no sink token means the step did not use the sink", 0, 0, 0, ""},
		{"data receipt means the payload reached the sink", 1, 1, 0, "NotDetected"},
		{"data receipt wins even with a probe", 1, 1, 1, "NotDetected"},
		{"probe reached the sink but no payload did: blocked", 1, 0, 1, "Detected"},
		{"no receipt at all is not proof of a block", 1, 0, 0, "Unknown"},
		{"two tokens for one run and technique is ambiguous", 2, 1, 0, "Unknown"},
		{"two tokens with only a probe is ambiguous", 2, 0, 1, "Unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := SinkDataProtectionStatus(tc.tokens, tc.data, tc.probe)
			if got != tc.want {
				t.Fatalf("SinkDataProtectionStatus(%d, %d, %d) = %q, want %q", tc.tokens, tc.data, tc.probe, got, tc.want)
			}
		})
	}
}
