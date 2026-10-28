package rwrecover

import (
	"testing"

	"github.com/audspect/bas/internal/rwevidence"
)

const (
	enumeratedTwo  = "EXEC T1490: 2 VSS shadow copy(ies) enumerated. Akira would now delete these. [BAS-SIM-AKIRA-S7]"
	enumeratedNone = "PASS: No VSS shadow copies found or vssadmin blocked  -  recovery inhibition surface is reduced. [BAS-SIM-AKIRA-S7]"
	survivalOne    = "EXEC T1490: survival check -- 1 VSS shadow copy(ies) present after the deletion step. [BAS-SIM-AKIRA-S8B]"
	survivalTwo    = "EXEC T1490: survival check -- 2 VSS shadow copy(ies) present after the deletion step. [BAS-SIM-AKIRA-S8B]"
)

func TestGrade_CopyCountDroppedIsLost(t *testing.T) {
	if got := Grade(true, enumeratedTwo, survivalOne); got != rwevidence.SurvivalLost {
		t.Fatalf("got %q, want lost", got)
	}
}

func TestGrade_CopyCountUnchangedIsConfirmed(t *testing.T) {
	if got := Grade(true, enumeratedTwo, survivalTwo); got != rwevidence.SurvivalConfirmed {
		t.Fatalf("got %q, want confirmed", got)
	}
}

func TestGrade_DeletionNotPerformedIsIndeterminate(t *testing.T) {
	if got := Grade(false, enumeratedTwo, survivalOne); got != rwevidence.SurvivalIndeterminate {
		t.Fatalf("got %q, want indeterminate -- nothing was targeted", got)
	}
}

func TestGrade_NoCopiesBeforeIsIndeterminate(t *testing.T) {
	if got := Grade(true, enumeratedNone, survivalOne); got != rwevidence.SurvivalIndeterminate {
		t.Fatalf("got %q, want indeterminate -- nothing to target", got)
	}
}

func TestGrade_UnreadablePreOrPostIsIndeterminate(t *testing.T) {
	if got := Grade(true, "", survivalOne); got != rwevidence.SurvivalIndeterminate {
		t.Fatalf("missing pre-count: got %q, want indeterminate", got)
	}
	if got := Grade(true, enumeratedTwo, "SKIP T1490: survival check could not read VSS state"); got != rwevidence.SurvivalIndeterminate {
		t.Fatalf("missing post-count: got %q, want indeterminate", got)
	}
}
