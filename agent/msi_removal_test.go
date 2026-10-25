package main

import (
	"strings"
	"testing"
)

func TestValidMSIProductCode(t *testing.T) {
	good := []string{"{7F82553E-E3B9-4686-A1EF-A8AE8723AD37}", "{7f82553e-e3b9-4686-a1ef-a8ae8723ad37}"}
	for _, g := range good {
		if !validMSIProductCode(g) {
			t.Fatalf("%q must be accepted", g)
		}
	}
	bad := []string{"", "7F82553E-E3B9-4686-A1EF-A8AE8723AD37", "{7F82553E-E3B9-4686-A1EF-A8AE8723AD3}",
		"{7F82553E-E3B9-4686-A1EF-A8AE8723AD37} & calc", "{7F82553E-E3B9-4686-A1EF-A8AE8723AD3G}", "{x}\r\n/qn", "{7F82553E-E3B9-4686-A1EF-A8AE8723AD37}\x00"}
	for _, b := range bad {
		if validMSIProductCode(b) {
			t.Fatalf("%q must be rejected: it ends up on a command line", b)
		}
	}
}

func TestMSIRemovalCommandIsAnArgumentListWithNoShellText(t *testing.T) {
	args, err := msiRemovalCommand("{7F82553E-E3B9-4686-A1EF-A8AE8723AD37}")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"msiexec.exe", "/x", "{7F82553E-E3B9-4686-A1EF-A8AE8723AD37}", "/qn", "/norestart"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %v", want, args)
		}
	}
	// The delay before msiexec lets the service reach Stopped first; it must be a plain
	// executable invocation, not a shell string built from registry data.
	if args[0] == "cmd.exe" || strings.Contains(joined, "&") || strings.Contains(joined, "|") {
		t.Fatalf("no shell composition allowed: %v", args)
	}
}

func TestMSIRemovalCommandRejectsInvalidCodes(t *testing.T) {
	if _, err := msiRemovalCommand("{bad} & calc"); err == nil {
		t.Fatal("an invalid product code must not produce a command")
	}
}
