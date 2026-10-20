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

// checkLiveStageStart refuses a live campaign stage before anything is dispatched.
// Posture is allowed. For any other mode the flag must be on, and even then the stage
// is refused until the campaign approval step exists. That step carries the
// confirmations that checkLiveGates needs, so no live stage can run without them.
func checkLiveStageStart(mode string) error {
	if mode == "" || mode == "posture" {
		return nil
	}
	if !liveStagesEnabled() {
		return errLiveStagesDisabled
	}
	return errLiveStageNeedsApproval
}

var (
	errLiveStagesDisabled     = errors.New("live campaign stages are disabled on this server (KILLCHAIN_LIVE_STAGES_ENABLED is not true)")
	errLiveStageNeedsApproval = errors.New("live campaign stages need campaign approval, which is not built yet")
)

// LiveCampaignStagesEnabled exposes the flag state for the startup log.
func LiveCampaignStagesEnabled() bool { return liveStagesEnabled() }
