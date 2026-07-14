package pathcorrelation

import (
	"testing"

	"github.com/audspect/bas/internal/attackpath"
)

func TestDefaultEdgeTechniqueMapper(t *testing.T) {
	m := DefaultEdgeTechniqueMapper{}

	cases := []struct {
		kind    attackpath.EdgeKind
		wantIDs []string
	}{
		{attackpath.EdgeSMB, []string{"T1021.002"}},
		{attackpath.EdgeWinRM, []string{"T1021.006"}},
		{attackpath.EdgeRDP, []string{"T1021.001"}},
		{attackpath.EdgeAdminTo, []string{"T1078"}},
		{attackpath.EdgeHasSession, []string{"T1003", "T1552"}},
		{attackpath.EdgeMemberOf, []string{"T1078", "T1098"}},
		{attackpath.EdgeCredential, []string{"T1550", "T1555"}},
	}

	for _, c := range cases {
		got := m.Techniques(c.kind)
		if len(got) != len(c.wantIDs) {
			t.Fatalf("%s: want %d techniques, got %d: %+v", c.kind, len(c.wantIDs), len(got), got)
		}
		for i, id := range c.wantIDs {
			if got[i].TechniqueID != id {
				t.Fatalf("%s: technique[%d] = %q, want %q", c.kind, i, got[i].TechniqueID, id)
			}
			if got[i].Weight <= 0 || got[i].Weight > 1 {
				t.Fatalf("%s: technique[%d] weight %v out of (0,1] range", c.kind, i, got[i].Weight)
			}
			if got[i].Reason == "" {
				t.Fatalf("%s: technique[%d] has no reason", c.kind, i)
			}
		}
	}

	if got := m.Techniques(attackpath.EdgeKind("unknown")); len(got) != 0 {
		t.Fatalf("unknown edge kind should map to no techniques, got %+v", got)
	}
}
