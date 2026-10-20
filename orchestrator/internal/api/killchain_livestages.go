package api

import (
	"errors"
	"os"
)

// liveStagesEnabled reports whether the server allows live campaign stages. It is off
// unless KILLCHAIN_LIVE_STAGES_ENABLED is exactly "true". It is read from the
// environment only, not through the API.
var liveStagesEnabled = func() bool {
	return os.Getenv("KILLCHAIN_LIVE_STAGES_ENABLED") == "true"
}

var (
	errLiveStagesDisabled     = errors.New("live campaign stages are disabled on this server (KILLCHAIN_LIVE_STAGES_ENABLED is not true)")
	errLiveStageNeedsApproval = errors.New("live campaign stages need campaign approval for this mode (confirmLive, and confirmLab for lab)")
)

// checkLiveStageStart refuses a live campaign stage before anything is dispatched.
// Posture needs nothing. A live stage needs the flag on and the campaign's approval
// for its mode. Scenario rules and the execution window are checked by checkLiveGates
// at the same point.
func checkLiveStageStart(mode string, approved bool) error {
	if mode == "" || mode == "posture" {
		return nil
	}
	if !liveStagesEnabled() {
		return errLiveStagesDisabled
	}
	if !approved {
		return errLiveStageNeedsApproval
	}
	return nil
}

// LiveCampaignStagesEnabled exposes the flag state for the startup log.
func LiveCampaignStagesEnabled() bool { return liveStagesEnabled() }
