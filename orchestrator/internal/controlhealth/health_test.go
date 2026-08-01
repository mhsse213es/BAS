package controlhealth

import (
	"testing"
	"time"
)

var testCat = CategoryDef{ID: "test-category", Name: "Test Category"}

func mkRow(tech, verdict string, daysAgo int, now time.Time) evidenceRow {
	return evidenceRow{TechniqueID: tech, Verdict: verdict, At: now.AddDate(0, 0, -daysAgo)}
}

func TestOverallHealth_AllCombinations(t *testing.T) {
	cases := []struct {
		name       string
		prevention string
		detection  string
		coverage   int
		want       string
	}{
		{"prevention pass, high coverage -> Healthy", "pass", HealthUnknownVerdict, 92, HealthHealthy},
		{"prevention pass, very low coverage -> Unknown", "pass", HealthUnknownVerdict, 8, HealthUnknown}, // 8 < unknownFloor(20)
		{"prevention pass, mid coverage -> PartiallyValidated", "pass", HealthUnknownVerdict, 45, HealthPartiallyValidated},
		{"prevention pass, exactly healthy floor -> Healthy", "pass", HealthUnknownVerdict, 70, HealthHealthy},
		{"prevention fail, detection pass -> Degraded", "fail", "pass", 90, HealthDegraded},
		{"prevention fail, detection fail -> Critical", "fail", "fail", 90, HealthCritical},
		{"prevention fail, detection unknown -> Degraded", "fail", HealthUnknownVerdict, 90, HealthDegraded},
		{"prevention unknown -> Unknown regardless of coverage", HealthUnknownVerdict, "pass", 100, HealthUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := overallHealth(c.prevention, c.detection, c.coverage)
			if got != c.want {
				t.Errorf("overallHealth(%q, %q, %d) = %q, want %q", c.prevention, c.detection, c.coverage, got, c.want)
			}
		})
	}
}

func TestAggregate_WeakestLink_OneFailFailsCategory(t *testing.T) {
	now := time.Now().UTC()
	rows := []evidenceRow{
		mkRow("T1059", "pass", 1, now),
		mkRow("T1003", "pass", 1, now),
		mkRow("T1078", "fail", 1, now),
	}
	verdict, validated, count, _ := aggregate(rows, []string{"T1059", "T1003", "T1078"}, now)
	if verdict != "fail" {
		t.Errorf("verdict = %q, want fail (weakest link)", verdict)
	}
	if validated != 3 {
		t.Errorf("validated = %d, want 3", validated)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestAggregate_MostRecentPerTechniqueWins(t *testing.T) {
	now := time.Now().UTC()
	rows := []evidenceRow{
		mkRow("T1059", "fail", 10, now), // older
		mkRow("T1059", "pass", 1, now),  // newer -- this one should win
	}
	verdict, validated, count, _ := aggregate(rows, []string{"T1059"}, now)
	if verdict != "pass" {
		t.Errorf("verdict = %q, want pass (most recent result)", verdict)
	}
	if validated != 1 {
		t.Errorf("validated = %d, want 1", validated)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2 (both rows counted as evidence)", count)
	}
}

func TestAggregate_RowsAfterAsOfExcluded(t *testing.T) {
	now := time.Now().UTC()
	rows := []evidenceRow{
		mkRow("T1059", "fail", -1, now), // 1 day in the FUTURE relative to asOf
	}
	verdict, validated, _, _ := aggregate(rows, []string{"T1059"}, now)
	if verdict != HealthUnknownVerdict || validated != 0 {
		t.Errorf("future-dated row must be excluded by asOf; got verdict=%q validated=%d", verdict, validated)
	}
}

func TestAggregate_NoEvidence_ReturnsUnknown(t *testing.T) {
	now := time.Now().UTC()
	verdict, validated, count, lastAt := aggregate(nil, []string{"T1059"}, now)
	if verdict != HealthUnknownVerdict || validated != 0 || count != 0 || lastAt != nil {
		t.Errorf("empty evidence should be all-zero unknown, got verdict=%q validated=%d count=%d lastAt=%v", verdict, validated, count, lastAt)
	}
}

func TestComputeTrend(t *testing.T) {
	cases := []struct {
		current, past, want string
	}{
		{HealthHealthy, HealthDegraded, "Improving"},
		{HealthCritical, HealthCritical, "Stable"},
		{HealthDegraded, HealthHealthy, "Declining"},
		{HealthUnknown, HealthHealthy, "InsufficientData"},
		{HealthHealthy, HealthUnknown, "InsufficientData"},
	}
	for _, c := range cases {
		got := computeTrend(c.current, c.past)
		if got != c.want {
			t.Errorf("computeTrend(%q, %q) = %q, want %q", c.current, c.past, got, c.want)
		}
	}
}

func TestComputeCategoryHealth_MappedButNoEvidence_IsUnknown(t *testing.T) {
	now := time.Now().UTC()
	got := computeCategoryHealth(testCat, []string{"T1059", "T1003"}, nil, nil, now)
	if got.OverallHealth != HealthUnknown {
		t.Errorf("OverallHealth = %q, want Unknown for a mapped-but-untested category", got.OverallHealth)
	}
	if got.MappedTechniques != 2 || got.ValidatedTechniques != 0 || got.Coverage != 0 {
		t.Errorf("got %+v, want MappedTechniques=2 ValidatedTechniques=0 Coverage=0", got)
	}
}
