package defender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// BlockRecord is one device event the hunting API reports as a block.
type BlockRecord struct {
	Timestamp  time.Time
	ActionType string
}

// hostnamePattern limits a device name to characters that can't break out of
// the KQL string literal it is interpolated into.
var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// FindBlockEvents returns DeviceEvents rows on deviceName within [start, end]
// whose ActionType is a block: the documented ControlledFolderAccessViolationBlocked,
// or any Asr* action that ends in Blocked. Microsoft publishes no complete list
// of block action types, so this matches only these two forms. Absence of rows
// is not evidence the action was allowed. The caller must treat it as unknown.
//
// Advanced Hunting is a separate Microsoft resource with its own token scope
// (api.security.microsoft.com) and requires the AdvancedHunting.Read.All
// application permission. Field and action names are unverified against a live tenant.
func (c *Client) FindBlockEvents(ctx context.Context, deviceName string, start, end time.Time) ([]BlockRecord, error) {
	if !hostnamePattern.MatchString(deviceName) {
		return nil, fmt.Errorf("defender hunt: device name %q is not a hostname", deviceName)
	}
	query := fmt.Sprintf(`DeviceEvents
| where Timestamp between (datetime(%s) .. datetime(%s))
| where DeviceName =~ "%s"
| where ActionType == "ControlledFolderAccessViolationBlocked" or (ActionType startswith "Asr" and ActionType endswith "Blocked")
| project Timestamp, ActionType
| take 100`,
		start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339), deviceName)

	token, err := c.huntTokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"Query": query})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.HuntBaseURL+"/advancedhunting/run", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("defender hunt: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("defender hunt: HTTP %d: %s", resp.StatusCode, data)
	}
	var out struct {
		Results []struct {
			Timestamp  time.Time `json:"Timestamp"`
			ActionType string    `json:"ActionType"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("defender hunt: parse response: %w", err)
	}
	recs := make([]BlockRecord, 0, len(out.Results))
	for _, r := range out.Results {
		recs = append(recs, BlockRecord{Timestamp: r.Timestamp, ActionType: r.ActionType})
	}
	return recs, nil
}
