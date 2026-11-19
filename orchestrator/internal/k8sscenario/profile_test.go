package k8sscenario

import (
	"errors"
	"testing"
)

func TestEnforceProfile_MatrixFollowsClass(t *testing.T) {
	cases := []struct {
		class, profile string
		allowed        bool
	}{
		{ClassLab, "safe", true}, {ClassLab, "lab", true}, {ClassLab, "controlled", true},
		{ClassNonProduction, "safe", true}, {ClassNonProduction, "lab", false}, {ClassNonProduction, "controlled", true},
		{ClassProduction, "safe", true}, {ClassProduction, "lab", false}, {ClassProduction, "controlled", false},
		{"unknown", "safe", false},
	}
	for _, c := range cases {
		err := EnforceProfile(c.class, c.profile)
		if c.allowed && err != nil {
			t.Errorf("%s/%s: refused: %v", c.class, c.profile, err)
		}
		if !c.allowed && !errors.Is(err, ErrProfileRefused) {
			t.Errorf("%s/%s: want ErrProfileRefused, got %v", c.class, c.profile, err)
		}
	}
}

func TestRefusalEvent_RecordsWhatWasAskedAndBy(t *testing.T) {
	ev := RefusalEvent("probe-1", "k8sc-9", "prod-east", ClassProduction, "lab", "alice")
	if ev.Type != "k8s.profile.refused" || ev.RunID != "probe-1" {
		t.Errorf("type/run wrong: %+v", ev)
	}
	for k, want := range map[string]string{"requester": "alice", "clusterId": "k8sc-9", "cluster": "prod-east",
		"class": ClassProduction, "profile": "lab"} {
		if ev.Fields[k] != want {
			t.Errorf("field %s = %q, want %q", k, ev.Fields[k], want)
		}
	}
}
