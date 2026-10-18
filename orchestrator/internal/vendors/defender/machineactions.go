package defender

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MachineAction is one normalized machineAction record -- Microsoft's
// real, documented resource type
// (learn.microsoft.com/defender-endpoint/api/machineaction). Status's
// documented enum has exactly six values: Pending, InProgress,
// Succeeded, Failed, TimeOut, Cancelled. This is independent, real
// evidence of whether a dispatched action (isolate/release/kill
// process/quarantine) actually completed -- never inferred from the
// dispatch call's own 2xx response, which only proves Defender
// accepted the request.
type MachineAction struct {
	ID        string
	Type      string
	Status    string
	MachineID string
}

type machineActionResponse struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	MachineID string `json:"machineId"`
}

// GetMachineAction calls GET {ActionBaseURL}/machineactions/{actionID}
// -- the real, documented Get MachineAction endpoint
// (learn.microsoft.com/defender-endpoint/api/get-machineaction-object).
// A caller uses this to independently re-verify that a previously
// dispatched action (whose ID came back from Isolate/Release/
// KillProcess/QuarantineFile) actually reached Status == "Succeeded",
// rather than trusting the dispatch call's own acceptance response.
func (c *Client) GetMachineAction(ctx context.Context, actionID string) (MachineAction, error) {
	token, err := c.actionTokens.Token(ctx)
	if err != nil {
		return MachineAction{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ActionBaseURL+"/machineactions/"+actionID, nil)
	if err != nil {
		return MachineAction{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return MachineAction{}, fmt.Errorf("defender get machine action: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return MachineAction{}, fmt.Errorf("defender get machine action: HTTP %d: %s", resp.StatusCode, data)
	}

	var out machineActionResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return MachineAction{}, fmt.Errorf("defender: parse machine action response: %w", err)
	}
	return MachineAction{ID: out.ID, Type: out.Type, Status: out.Status, MachineID: out.MachineID}, nil
}

// PollMachineActionUntilTerminal re-reads actionID via GetMachineAction
// until its Status reaches a terminal value (Succeeded, Failed,
// TimeOut, Cancelled) or attempts is exhausted, sleeping interval
// between reads -- the same baseline-independent-reread discipline
// phishidentity.RevokeAndVerifySignInSessions already uses for its own
// propagation-delay case. Pending/InProgress are the only non-terminal
// values; this never guesses a terminal outcome from a non-terminal
// read.
func (c *Client) PollMachineActionUntilTerminal(ctx context.Context, actionID string, attempts int, interval time.Duration) (MachineAction, error) {
	var last MachineAction
	for i := 0; i < attempts; i++ {
		a, err := c.GetMachineAction(ctx, actionID)
		if err != nil {
			return MachineAction{}, err
		}
		last = a
		switch a.Status {
		case "Succeeded", "Failed", "TimeOut", "Cancelled":
			return a, nil
		}
		if i < attempts-1 {
			time.Sleep(interval)
		}
	}
	return last, nil
}
