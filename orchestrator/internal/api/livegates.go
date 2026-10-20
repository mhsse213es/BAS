package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/audspect/bas/internal/scenario"
)

// liveGateError is a refusal from checkLiveGates. Status is the HTTP status the
// caller sends. A broken server-side window spec is a 500, and every other refusal
// is a 400.
type liveGateError struct {
	Status int
	Msg    string
}

func (e *liveGateError) Error() string { return e.Msg }

// checkLiveGates is the request-level guardrail for a scenario run. Both the single-run
// handler and the campaign stage starter call it, so the rules cannot drift between
// them. It returns an OS warning for posture runs on a mismatched agent. A refusal is
// a *liveGateError. Dispatch-side checks (agent state, factory-lab ownership,
// concurrency) stay in dispatchRun.
func checkLiveGates(sc *scenario.Scenario, mode string, confirmLive, confirmLab bool, agentOS string, now time.Time) (string, error) {
	live := mode == "telemetry" || mode == "lab"

	if live && !sc.Executable {
		return "", &liveGateError{http.StatusBadRequest, "scenario does not support live execution — run it in posture mode"}
	}
	if live && !confirmLive {
		return "", &liveGateError{http.StatusBadRequest, "live execution requires explicit acknowledgement (confirmLive=true) — it runs real techniques"}
	}
	if mode == "lab" && !confirmLab {
		return "", &liveGateError{http.StatusBadRequest, "lab mode is a second approval gate (confirmLab=true) — it allows full-fidelity emulation and must target an isolated AD range only"}
	}

	// OS compatibility guardrail: live mode hard-blocks on mismatch.
	var osWarning string
	if len(sc.SupportedOS) > 0 && agentOS != "" {
		supported := false
		for _, o := range sc.SupportedOS {
			if strings.EqualFold(o, agentOS) {
				supported = true
				break
			}
		}
		if !supported {
			if live {
				return "", &liveGateError{http.StatusBadRequest, fmt.Sprintf("OS mismatch: scenario '%s' supports %v but agent OS is %s — run this scenario against a matching endpoint",
					sc.Name, sc.SupportedOS, agentOS)}
			}
			osWarning = fmt.Sprintf("scenario targets %v but agent OS is %s — posture checks will return 'not applicable'", sc.SupportedOS, agentOS)
		}
	}

	// Execution window: server-enforced for live runs only.
	if live && sc.LivePolicy != nil && sc.LivePolicy.ExecutionWindow != "" {
		ok, err := withinWindow(sc.LivePolicy.ExecutionWindow, now)
		if err != nil {
			return "", &liveGateError{http.StatusInternalServerError, "invalid execution_window in scenario policy: " + err.Error()}
		}
		if !ok {
			return "", &liveGateError{http.StatusBadRequest, "outside the approved execution window (" + sc.LivePolicy.ExecutionWindow + ") for live execution"}
		}
	}
	return osWarning, nil
}
