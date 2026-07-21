// Package actions executes EPP response actions (isolate/release/kill
// process/quarantine file) against CrowdStrike or Microsoft Defender for
// Endpoint. Every action here is write-capable — unlike internal/detectverify
// (read-only verification), this package can isolate a live host, kill a
// process, or delete/quarantine a file. This package does no database I/O;
// internal/api owns the action_connectors/action_requests tables and calls
// Execute with everything it needs already loaded, exactly like
// internal/detectverify's VerifyRun.
package actions

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/vendors/crowdstrike"
	"github.com/audspect/bas/internal/vendors/defender"
)

// Action types this feature supports.
const (
	TypeIsolate        = "endpoint.isolate"
	TypeRelease        = "endpoint.release"
	TypeKillProcess    = "endpoint.kill_process"
	TypeQuarantineFile = "endpoint.quarantine_file"
)

// Status values Execute assigns. v1 dispatches synchronously with no
// queue, so only Completed/Failed are ever observed once Execute returns —
// see Global Constraints in the implementation plan for why
// Requested/Dispatched never become independently-observable persisted
// states, and why there is no separate VendorAccepted/VendorRejected pair.
const (
	StatusRequested  = "requested"
	StatusDispatched = "dispatched"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
)

// Target identifies what an action acts on. Type is open-ended (only
// "hostname" is implemented) so identity/cloud/firewall targets can be
// added later without an API break.
type Target struct {
	Type       string
	Identifier string
}

// Request is one operator-initiated response action.
type Request struct {
	Type   string
	Target Target
	// Parameters holds action-specific arguments: {"pid": <number>} for
	// endpoint.kill_process, {"quarantineTarget": <string>} for
	// endpoint.quarantine_file (a file path for CrowdStrike, a SHA1 hash
	// for Defender — the caller supplies the right kind of value for the
	// connector's provider; this package stays vendor-agnostic about it).
	// Empty for endpoint.isolate/endpoint.release.
	Parameters  map[string]any
	ConnectorID string
	RequestedBy string
	Reason      string
	TicketRef   string
	RunID       string
}

// Action is the full record of one executed (or failed) response action —
// every field is a column in internal/api's action_requests table.
type Action struct {
	Type             string
	Target           Target
	Parameters       map[string]any
	ConnectorID      string
	Status           string
	ResolvedDeviceID string
	VendorRequestID  string
	Error            string
	RequestedBy      string
	Reason           string
	TicketRef        string
	RunID            string
	RequestedAt      time.Time
	DispatchedAt     *time.Time
	CompletedAt      *time.Time
}

// VendorClient is the shape both crowdstrike.Client and defender.Client
// satisfy structurally (Go's implicit interface satisfaction — neither
// vendor package imports this interface or internal/actions at all).
type VendorClient interface {
	ResolveDevice(ctx context.Context, hostname string) (string, error)
	Isolate(ctx context.Context, deviceID string) (string, error)
	Release(ctx context.Context, deviceID string) (string, error)
	KillProcess(ctx context.Context, deviceID string, pid int) (string, error)
	QuarantineFile(ctx context.Context, deviceID, param string) (string, error)
}

// ConnectorConfig holds the connection settings for one configured
// response connector — persisted in action_connectors, loaded by
// internal/api and passed to NewVendorClient.
type ConnectorConfig struct {
	Provider              string // "crowdstrike" | "microsoft_defender"
	TenantID              string // Defender only
	ClientID              string
	ClientSecret          string
	BaseURL               string // CrowdStrike only
	KillProcessScriptName string // Defender only
}

// NewVendorClient builds the VendorClient for cfg.Provider.
func NewVendorClient(cfg ConnectorConfig) (VendorClient, error) {
	switch cfg.Provider {
	case "crowdstrike":
		return crowdstrike.New(crowdstrike.Config{
			BaseURL: cfg.BaseURL, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		}), nil
	case "microsoft_defender":
		return defender.New(defender.Config{
			TenantID: cfg.TenantID, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
			KillProcessScriptName: cfg.KillProcessScriptName,
		}), nil
	default:
		return nil, fmt.Errorf("actions: provider %q not supported", cfg.Provider)
	}
}

// Execute runs req against client, returning the full Action record
// whether it succeeded or failed. Callers check Action.Status, not a
// separate error — every failure mode is already captured in Action.Error.
func Execute(ctx context.Context, client VendorClient, req Request) Action {
	a := Action{
		Type: req.Type, Target: req.Target, Parameters: req.Parameters,
		ConnectorID: req.ConnectorID, RequestedBy: req.RequestedBy, Reason: req.Reason,
		TicketRef: req.TicketRef, RunID: req.RunID,
		Status: StatusRequested, RequestedAt: time.Now(),
	}

	if req.Target.Type != "hostname" {
		return fail(a, fmt.Sprintf("actions: unsupported target type %q", req.Target.Type))
	}
	if req.Reason == "" {
		return fail(a, "actions: reason is required")
	}

	dispatchedAt := time.Now()
	a.DispatchedAt = &dispatchedAt
	a.Status = StatusDispatched

	deviceID, err := client.ResolveDevice(ctx, req.Target.Identifier)
	if err != nil {
		return fail(a, err.Error())
	}
	a.ResolvedDeviceID = deviceID

	vendorRequestID, err := dispatch(ctx, client, req.Type, deviceID, req.Parameters)
	if err != nil {
		return fail(a, err.Error())
	}
	a.VendorRequestID = vendorRequestID

	completedAt := time.Now()
	a.CompletedAt = &completedAt
	a.Status = StatusCompleted
	return a
}

func fail(a Action, msg string) Action {
	completedAt := time.Now()
	a.CompletedAt = &completedAt
	a.Status = StatusFailed
	a.Error = msg
	return a
}

func dispatch(ctx context.Context, client VendorClient, actionType, deviceID string, params map[string]any) (string, error) {
	switch actionType {
	case TypeIsolate:
		return client.Isolate(ctx, deviceID)
	case TypeRelease:
		return client.Release(ctx, deviceID)
	case TypeKillProcess:
		pid, err := intParam(params, "pid")
		if err != nil {
			return "", err
		}
		return client.KillProcess(ctx, deviceID, pid)
	case TypeQuarantineFile:
		target, err := stringParam(params, "quarantineTarget")
		if err != nil {
			return "", err
		}
		return client.QuarantineFile(ctx, deviceID, target)
	default:
		return "", fmt.Errorf("actions: unsupported action type %q", actionType)
	}
}

func intParam(params map[string]any, key string) (int, error) {
	v, ok := params[key]
	if !ok {
		return 0, fmt.Errorf("actions: missing required parameter %q", key)
	}
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case int:
		return n, nil
	default:
		return 0, fmt.Errorf("actions: parameter %q must be a number, got %T", key, v)
	}
}

func stringParam(params map[string]any, key string) (string, error) {
	v, ok := params[key]
	if !ok {
		return "", fmt.Errorf("actions: missing required parameter %q", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("actions: parameter %q must be a non-empty string", key)
	}
	return s, nil
}
