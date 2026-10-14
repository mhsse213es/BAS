package latdetect

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/latmove"
)

func TestVerifyRequestFor_BuildsFromTechniqueMitreID(t *testing.T) {
	tech := latmove.WMIRemoteProcessCreation()
	now := time.Now()
	req, ok := VerifyRequestFor(tech, "run1", "exp1", "ws02", "10.10.10.21", now, now, now.Add(5*time.Minute))
	if !ok {
		t.Fatal("expected ok=true for a technique with a MitreID")
	}
	if req.RunID != "run1" || req.ExpectationID != "exp1" || req.TechniqueID != "T1047" {
		t.Fatalf("req = %+v", req)
	}
	if req.HostName != "ws02" || req.HostIP != "10.10.10.21" {
		t.Fatalf("req host fields = %+v", req)
	}
}

func TestVerifyRequestFor_EmptyMitreIDIsNotOK(t *testing.T) {
	// Detection verification is keyed on MitreID; a technique with none
	// cannot be checked this way -- same rule as addetect.VerifyRequestFor.
	tech := latmove.Technique{ID: "no-mitre-id"}
	if _, ok := VerifyRequestFor(tech, "run1", "exp1", "ws02", "10.10.10.21", time.Now(), time.Now(), time.Now()); ok {
		t.Fatal("expected ok=false for a technique with no MitreID")
	}
}

func TestVerifyRequestFor_AllFiveTechniquesHaveMitreIDs(t *testing.T) {
	// Every shipped technique must be detection-checkable.
	for _, tech := range []latmove.Technique{
		latmove.WMIRemoteProcessCreation(),
		latmove.RemoteServiceCreation(),
		latmove.ScheduledTaskRemote(),
		latmove.WinRMRemoteExecution(),
		latmove.RDPInteractiveLogon(),
	} {
		if _, ok := VerifyRequestFor(tech, "r", "e", "h", "1.2.3.4", time.Now(), time.Now(), time.Now()); !ok {
			t.Fatalf("technique %s has no usable MitreID", tech.ID)
		}
	}
}
