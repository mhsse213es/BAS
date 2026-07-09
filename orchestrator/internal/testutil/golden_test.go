package testutil

import "testing"

func TestAssertGoldenBytes_MatchesFile(t *testing.T) {
	AssertGoldenBytes(t, "example.json", []byte("{\"hello\":\"world\"}\n"))
}
