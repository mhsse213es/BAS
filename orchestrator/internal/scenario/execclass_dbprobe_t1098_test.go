package scenario

import "testing"

// DB-04-06 runs its GRANT and REVOKE under T1098. Without the dbprobe entry the
// resolver falls back to destructive and the build refuses the step.
func TestT1098ResolvesDBProbeBoundedSynthetic(t *testing.T) {
	got := ResolveExecutionClass("T1098", "dbprobe_bounded_synthetic").Class
	if got != ClassPotentiallyDestructive {
		t.Fatalf("T1098 dbprobe_bounded_synthetic resolves %q, want %q", got, ClassPotentiallyDestructive)
	}
}
