package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"audspect/agent/dbprobe"
)

func TestDBProbeRuntimeErrorScrubsUserHostIdentityAndPassword(t *testing.T) {
	fa := setupHappy(t)
	fa.connectErr = errors.New(`failed to connect to host=db.lab.internal user=ro_user password=` + testCredPassword +
		` db=bas_lab: identity sysid-123 rejected`)
	out, err := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err == nil {
		t.Fatal("want error")
	}
	all := err.Error() + " " + strings.Join(out.Result.Notes, " ") + " " + out.Result.ErrorClass
	for _, leak := range []string{testCredPassword, "ro_user", "db.lab.internal", "sysid-123"} {
		if strings.Contains(all, leak) {
			t.Errorf("runtime error text leaks %q: %s", leak, all)
		}
	}
}

func TestScrubTruncatesOnRuneBoundary(t *testing.T) {
	msg := strings.Repeat("é", 400) // 2 bytes each; byte 300 would split a rune only if odd
	for _, pad := range []string{"", "x"} {
		got := scrubAll(pad + msg)
		if !utf8.ValidString(got) {
			t.Fatalf("truncation produced invalid UTF-8: %q", got)
		}
		if len(got) > 310 {
			t.Fatalf("not truncated: %d bytes", len(got))
		}
	}
	if g := scrubAll("abc user abc", "user", "", "abc"); strings.Contains(g, "user") || strings.Contains(g, "abc") {
		t.Fatalf("scrubAll: %q", g)
	}
}

func TestDBProbeExpectedExecClassMapping(t *testing.T) {
	cases := map[dbprobe.ProbeClass]string{
		dbprobe.ClassReadOnly:         "non_destructive",
		dbprobe.ClassBoundedSynthetic: "potentially_destructive",
		dbprobe.ClassMutation:         "destructive",
		"unknown":                     "destructive",
	}
	for c, want := range cases {
		if got := expectedExecClass(c); got != want {
			t.Errorf("expectedExecClass(%q) = %q, want %q", c, got, want)
		}
	}
}

func TestDBProbeSignedClassMustMatchCatalogClass(t *testing.T) {
	for _, class := range []string{"potentially_destructive", "destructive", "", "bogus"} {
		fa := setupHappy(t)
		step := testDBProbeStep(nil) // read_roles is read_only -> non_destructive
		step.ExecutionClass = class
		out, err := executeDBProbe(context.Background(), step)
		if err != nil || out.GateRefusal == "" || fa.count("Connect") != 0 {
			t.Errorf("class %q must be refused before Connect: err=%v out=%+v", class, err, out)
		}
	}
}
