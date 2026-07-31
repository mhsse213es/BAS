package pathcorrelation

import (
	"testing"

	"github.com/audspect/bas/internal/attackpath"
)

func TestRemediationFor(t *testing.T) {
	cases := []attackpath.EdgeKind{
		attackpath.EdgeSMB, attackpath.EdgeWinRM, attackpath.EdgeRDP,
		attackpath.EdgeAdminTo, attackpath.EdgeHasSession, attackpath.EdgeMemberOf,
		attackpath.EdgeCredential,
	}
	for _, kind := range cases {
		if got := RemediationFor(kind); got == "" {
			t.Errorf("RemediationFor(%s) = \"\", want a non-empty remediation sentence", kind)
		}
	}
	if got := RemediationFor(attackpath.EdgeKind("unknown")); got != "" {
		t.Errorf("RemediationFor(unknown) = %q, want empty string", got)
	}
}
