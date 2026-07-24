package reporting

import "testing"

func TestDetectionComparator(t *testing.T) {
	c := detectionComparator{}
	cases := []struct {
		name, expected, observed string
		want                     ComparisonResult
	}{
		{"match", "Detected", "Detected", Match},
		{"mismatch", "Detected", "NotDetected", Mismatch},
		{"missing evidence", "Detected", "", MissingEvidence},
	}
	for _, c2 := range cases {
		if got := c.Compare(c2.expected, c2.observed); got != c2.want {
			t.Errorf("%s: Compare(%q,%q) = %v want %v", c2.name, c2.expected, c2.observed, got, c2.want)
		}
	}
}

func TestComparatorForRegistry(t *testing.T) {
	if _, ok := comparatorFor("detection").(detectionComparator); !ok {
		t.Error("comparatorFor(\"detection\") should return the registered detectionComparator")
	}
	// An unregistered family falls back to a no-op comparator that always
	// reports Unknown — never silently treated as a match or mismatch.
	if got := comparatorFor("nonexistent-family").Compare("X", "X"); got != Unknown {
		t.Errorf("unregistered family: got %v want Unknown", got)
	}
}

func TestRegisterComparator(t *testing.T) {
	RegisterComparator("test-only", detectionComparator{})
	if _, ok := comparatorFor("test-only").(detectionComparator); !ok {
		t.Error("newly registered comparator should be retrievable")
	}
}

func TestCollapseToStatus(t *testing.T) {
	cases := []struct {
		in   ComparisonResult
		want string
	}{
		{Match, StatusDetected},
		{Mismatch, StatusNotDetected},
		{NotApplicable, StatusNotApplicable},
		{MissingEvidence, StatusUnknown},
		{Unknown, StatusUnknown},
	}
	for _, c := range cases {
		if got := collapseToStatus(c.in); got != c.want {
			t.Errorf("collapseToStatus(%v) = %q want %q", c.in, got, c.want)
		}
	}
}
