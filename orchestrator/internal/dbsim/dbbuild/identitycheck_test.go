package dbbuild

import (
	"context"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/scenario"
)

func TestBuildIdentityCheckStepIsOneSignedReadOnlyStep(t *testing.T) {
	// A client target that has NOT passed a check and with the client gate OFF:
	// the identity check is exactly what earns the pass, so it must still build.
	tg := labTarget()
	tg.Mode = dbsim.ModeClient
	tg.LabConfirmed = false
	o := opts(tg)
	o.RunID = "bas-dbsim-run:abc"
	st, spec, err := BuildIdentityCheckStep(context.Background(), tg, o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Executor != scenario.ExecutorDBProbe || st.Command != dbsim.ProbeCheckReadOnlyIdentity {
		t.Errorf("step = %q/%q", st.Executor, st.Command)
	}
	if st.ExecutionClass != scenario.ClassNonDestructive || st.ActionKey != "dbprobe_read_only" {
		t.Errorf("class/action = %q/%q", st.ExecutionClass, st.ActionKey)
	}
	if spec.ProbeID != dbsim.ProbeCheckReadOnlyIdentity || spec.TargetID != tg.ID || spec.RunID != "bas-dbsim-run:abc" ||
		spec.Mode != dbsim.ModeClient || !markerRe.MatchString(spec.Marker) || spec.CredentialRef != tg.CredentialRef {
		t.Errorf("spec = %+v", spec)
	}
	if !strings.Contains(string(st.DBProbe), spec.Marker) {
		t.Error("step DBProbe must carry the spec")
	}
}

func TestBuildIdentityCheckStepRefusals(t *testing.T) {
	ctx := context.Background()
	noAgent := labTarget()
	noAgent.AgentID = ""
	noCred := labTarget()
	noCred.CredentialRef = "plain-secret"
	noID := labTarget()
	noID.ExpectedIdentity = ""
	for name, tg := range map[string]dbsim.Target{"no agent": noAgent, "bad credential ref": noCred, "no identity": noID} {
		if _, _, err := BuildIdentityCheckStep(ctx, tg, opts(tg)); err == nil {
			t.Errorf("%s: want refusal", name)
		}
	}
	o := opts(labTarget())
	o.RunExpiry = o.RunExpiry.Add(-48 * 3600 * 1e9)
	if _, _, err := BuildIdentityCheckStep(ctx, labTarget(), o); err == nil {
		t.Error("expired run: want refusal")
	}
}
