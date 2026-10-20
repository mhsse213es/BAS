package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
)

func liveScenario() *scenario.Scenario {
	return &scenario.Scenario{ID: "lg", Name: "lg", Executable: true, SupportedOS: []string{"windows"}}
}

func gateStatus(t *testing.T, err error) int {
	t.Helper()
	var ge *liveGateError
	if !errors.As(err, &ge) {
		t.Fatalf("err = %v, want a *liveGateError", err)
	}
	return ge.Status
}

// Posture needs no confirmation and is never refused on OS mismatch. It only warns.
func TestLiveGates_PostureAllowedWithoutConfirmation(t *testing.T) {
	sc := liveScenario()
	warn, err := checkLiveGates(sc, "posture", false, false, "linux", time.Now())
	if err != nil {
		t.Fatalf("posture refused: %v", err)
	}
	if !strings.Contains(warn, "not applicable") {
		t.Fatalf("posture on a mismatched OS must warn, got %q", warn)
	}
}

func TestLiveGates_TelemetryNeedsConfirmLive(t *testing.T) {
	_, err := checkLiveGates(liveScenario(), "telemetry", false, false, "windows", time.Now())
	if gateStatus(t, err) != http.StatusBadRequest || !strings.Contains(err.Error(), "confirmLive") {
		t.Fatalf("err = %v, want the confirmLive refusal", err)
	}
}

func TestLiveGates_LabNeedsConfirmLabAsSecondApproval(t *testing.T) {
	_, err := checkLiveGates(liveScenario(), "lab", true, false, "windows", time.Now())
	if err == nil || !strings.Contains(err.Error(), "confirmLab") {
		t.Fatalf("err = %v, want the confirmLab refusal", err)
	}
}

// Lab is also live, so confirmLive is needed as well as confirmLab.
func TestLiveGates_LabNeedsConfirmLiveToo(t *testing.T) {
	_, err := checkLiveGates(liveScenario(), "lab", false, true, "windows", time.Now())
	if err == nil || !strings.Contains(err.Error(), "confirmLive") {
		t.Fatalf("err = %v, want the confirmLive refusal", err)
	}
}

func TestLiveGates_LabWithBothConfirmationsAllowed(t *testing.T) {
	if _, err := checkLiveGates(liveScenario(), "lab", true, true, "windows", time.Now()); err != nil {
		t.Fatalf("lab with both confirmations refused: %v", err)
	}
}

func TestLiveGates_NonExecutableScenarioRefusedLive(t *testing.T) {
	sc := liveScenario()
	sc.Executable = false
	_, err := checkLiveGates(sc, "telemetry", true, false, "windows", time.Now())
	if err == nil || !strings.Contains(err.Error(), "does not support live execution") {
		t.Fatalf("err = %v, want the not-executable refusal", err)
	}
}

// Live mode hard-blocks on OS mismatch. The refusal is a 400, not a warning.
func TestLiveGates_OSMismatchHardBlocksLive(t *testing.T) {
	_, err := checkLiveGates(liveScenario(), "telemetry", true, false, "linux", time.Now())
	if err == nil || !strings.Contains(err.Error(), "OS mismatch") {
		t.Fatalf("err = %v, want the OS mismatch refusal", err)
	}
}

// Window boundaries use the injected time, so the check is deterministic.
func TestLiveGates_ExecutionWindowRespectsTime(t *testing.T) {
	sc := liveScenario()
	sc.LivePolicy = &scenario.LivePolicy{ExecutionWindow: "09:00-10:00"}
	inside := time.Date(2026, 10, 20, 9, 30, 0, 0, time.Local)
	outside := time.Date(2026, 10, 20, 11, 0, 0, 0, time.Local)
	if _, err := checkLiveGates(sc, "telemetry", true, false, "windows", inside); err != nil {
		t.Fatalf("inside the window refused: %v", err)
	}
	_, err := checkLiveGates(sc, "telemetry", true, false, "windows", outside)
	if err == nil || !strings.Contains(err.Error(), "outside the approved execution window") {
		t.Fatalf("err = %v, want the window refusal", err)
	}
}

// A broken window spec is a server configuration fault, so it is a 500, not a 400.
func TestLiveGates_InvalidWindowIsServerError(t *testing.T) {
	sc := liveScenario()
	sc.LivePolicy = &scenario.LivePolicy{ExecutionWindow: "not-a-window"}
	_, err := checkLiveGates(sc, "telemetry", true, false, "windows", time.Now())
	if gateStatus(t, err) != http.StatusInternalServerError {
		t.Fatalf("err = %v, want a 500", err)
	}
}

// Posture ignores the window, which applies to live runs only.
func TestLiveGates_WindowDoesNotApplyToPosture(t *testing.T) {
	sc := liveScenario()
	sc.LivePolicy = &scenario.LivePolicy{ExecutionWindow: "09:00-10:00"}
	if _, err := checkLiveGates(sc, "posture", false, false, "windows", time.Date(2026, 10, 20, 15, 0, 0, 0, time.Local)); err != nil {
		t.Fatalf("posture refused by a live window: %v", err)
	}
}
