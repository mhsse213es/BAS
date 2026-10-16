package defender

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Machine is one Defender for Endpoint device-inventory record, field
// names and meanings confirmed against Microsoft's published Machine
// resource schema (learn.microsoft.com/defender-endpoint/api/machine).
// Fields that schema documents but nothing in this codebase consumes
// yet (ipAddresses, osBuild, version, the deprecated osProcessor) are
// left out deliberately -- add them when a real caller needs them, not
// speculatively.
type Machine struct {
	ID               string
	ComputerDNSName  string
	OSPlatform       string
	OSArchitecture   string // "32-bit" or "64-bit" -- supersedes the deprecated osProcessor
	OnboardingStatus string // Onboarded | CanBeOnboarded | Unsupported | InsufficientInfo
	HealthStatus     string // Active | Inactive | ImpairedCommunication | NoSensorData | NoSensorDataImpairedCommunication | Unknown
	RiskScore        string // None | Informational | Low | Medium | High
	ExposureLevel    string // None | Low | Medium | High
	DeviceValue      string // Normal | Low | High
	RBACGroupID      string
	RBACGroupName    string
	FirstSeen        time.Time
	LastSeen         time.Time
	LastIPAddress    string
	AADDeviceID      string
	MachineTags      []string
	RawJSON          json.RawMessage
}

type graphMachine struct {
	ID               string   `json:"id"`
	ComputerDNSName  string   `json:"computerDnsName"`
	OSPlatform       string   `json:"osPlatform"`
	OSArchitecture   string   `json:"osArchitecture"`
	OnboardingStatus string   `json:"onboardingStatus"`
	HealthStatus     string   `json:"healthStatus"`
	RiskScore        string   `json:"riskScore"`
	ExposureLevel    string   `json:"exposureLevel"`
	DeviceValue      string   `json:"deviceValue"`
	RBACGroupID      string   `json:"rbacGroupId"`
	RBACGroupName    string   `json:"rbacGroupName"`
	FirstSeen        string   `json:"firstSeen"`
	LastSeen         string   `json:"lastSeen"`
	LastIPAddress    string   `json:"lastIpAddress"`
	AADDeviceID      string   `json:"aadDeviceId"`
	MachineTags      []string `json:"machineTags"`
}

type machinesPageResponse struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
}

// maxListMachinesPages bounds pagination so a misbehaving nextLink
// chain can't loop forever -- same bounded-policy precedent as
// maxSendMailRateLimitRetries in client.go.
const maxListMachinesPages = 1000

// ListMachines returns the tenant's device inventory, following the
// real, documented @odata.nextLink pagination mechanism
// (learn.microsoft.com/defender-endpoint/api/apis-intro) across pages
// until it's absent or maxListMachinesPages is reached. A response this
// client cannot classify as success is returned as a *ClassifiedError
// (see errors.go) -- callers that need to distinguish "no license for
// this feature" from "insufficient permission" from "transient, retry
// later" should use errors.As, not string-match the error text.
func (c *Client) ListMachines(ctx context.Context) ([]Machine, error) {
	token, err := c.actionTokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	var out []Machine
	reqURL := c.ActionBaseURL + "/machines"
	for pageIdx := 0; reqURL != "" && pageIdx < maxListMachinesPages; pageIdx++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("defender list machines: %w", err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, classifyAPIError(resp.StatusCode, data)
		}
		var parsed machinesPageResponse
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, fmt.Errorf("defender list machines: parse response: %w", err)
		}
		for _, raw := range parsed.Value {
			var gm graphMachine
			if err := json.Unmarshal(raw, &gm); err != nil {
				continue
			}
			firstSeen, _ := time.Parse(time.RFC3339, gm.FirstSeen)
			lastSeen, _ := time.Parse(time.RFC3339, gm.LastSeen)
			out = append(out, Machine{
				ID: gm.ID, ComputerDNSName: gm.ComputerDNSName, OSPlatform: gm.OSPlatform,
				OSArchitecture: gm.OSArchitecture, OnboardingStatus: gm.OnboardingStatus,
				HealthStatus: gm.HealthStatus, RiskScore: gm.RiskScore, ExposureLevel: gm.ExposureLevel,
				DeviceValue: gm.DeviceValue, RBACGroupID: gm.RBACGroupID, RBACGroupName: gm.RBACGroupName,
				FirstSeen: firstSeen, LastSeen: lastSeen, LastIPAddress: gm.LastIPAddress,
				AADDeviceID: gm.AADDeviceID, MachineTags: gm.MachineTags, RawJSON: raw,
			})
		}
		reqURL = parsed.NextLink
	}
	return out, nil
}
