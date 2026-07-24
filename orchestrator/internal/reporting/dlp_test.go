package reporting

import "testing"

func TestDLPComparator(t *testing.T) {
	c := dlpComparator{}
	cases := []struct {
		name, expected, observed string
		want                     ComparisonResult
	}{
		{"expect Block, observe Blocked", "Block", ObservationBlocked, Match},
		{"expect Block, observe Succeeded", "Block", ObservationSucceeded, Mismatch},
		{"expect Block, observe Unknown", "Block", ObservationUnknown, MissingEvidence},
		{"expect Allow, observe Succeeded", "Allow", ObservationSucceeded, Match},
		{"expect Allow, observe Blocked", "Allow", ObservationBlocked, Mismatch},
		{"expect Allow, observe Unknown", "Allow", ObservationUnknown, MissingEvidence},
		{"expect Warn, observe Blocked", "Warn", ObservationBlocked, Mismatch},
		{"expect Warn, observe Succeeded", "Warn", ObservationSucceeded, MissingEvidence},
		{"expect Warn, observe Unknown", "Warn", ObservationUnknown, MissingEvidence},
		{"expect Justify, observe Succeeded", "Justify", ObservationSucceeded, MissingEvidence},
		{"expect Audit, observe Succeeded", "Audit", ObservationSucceeded, MissingEvidence},
		{"expect Quarantine, observe Blocked", "Quarantine", ObservationBlocked, Mismatch},
		{"garbage observed value", "Block", "not-a-real-token", MissingEvidence},
	}
	for _, c2 := range cases {
		t.Run(c2.name, func(t *testing.T) {
			if got := c.Compare(c2.expected, c2.observed); got != c2.want {
				t.Errorf("Compare(%q,%q) = %v want %v", c2.expected, c2.observed, got, c2.want)
			}
		})
	}
}

func TestDLPComparatorRegistered(t *testing.T) {
	if _, ok := comparatorFor("dlp").(dlpComparator); !ok {
		t.Error("comparatorFor(\"dlp\") should return the registered dlpComparator")
	}
}
