package scenario

import "testing"

// DB-03 (read_customer_records, read_financial_records) runs under T1213.006.
// Without the dbprobe entries the resolver falls back to destructive and the
// build refuses the step.
func TestT1213006ResolvesDBProbeClasses(t *testing.T) {
	cases := map[string]ExecutionClass{
		"dbprobe_read_only":         ClassNonDestructive,
		"dbprobe_bounded_synthetic": ClassPotentiallyDestructive,
		"dbprobe_mutation":          ClassDestructive,
	}
	for key, want := range cases {
		if got := ResolveExecutionClass("T1213.006", key).Class; got != want {
			t.Errorf("T1213.006 %s resolves %q, want %q", key, got, want)
		}
	}
}
