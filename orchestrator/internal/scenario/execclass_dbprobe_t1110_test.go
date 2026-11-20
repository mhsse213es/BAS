package scenario

import "testing"

// DB-04-04 (auth_failed_login) is a bounded_synthetic probe under T1110. Without
// the dbprobe entries the resolver falls back to destructive and the build fails.
func TestT1110ResolvesDBProbeClasses(t *testing.T) {
	cases := map[string]ExecutionClass{
		"dbprobe_read_only":         ClassNonDestructive,
		"dbprobe_bounded_synthetic": ClassPotentiallyDestructive,
		"dbprobe_mutation":          ClassDestructive,
	}
	for key, want := range cases {
		if got := ResolveExecutionClass("T1110", key).Class; got != want {
			t.Errorf("T1110 %s resolves %q, want %q", key, got, want)
		}
	}
}
