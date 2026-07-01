// Package tracker handles click/open/credential tracking for exercise injectors.
// It depends only on interfaces — no import of the parent exercise package —
// so any injector (SMTP, SMS, Teams…) can call GenerateLinks without a cycle.
package tracker

import (
	"context"
	"time"
)

// TokenStore is the subset of the DB store that the tracker needs.
// exercise.Store satisfies this interface.
type TokenStore interface {
	InsertTrackToken(ctx context.Context, token, execID, stepExecID, targetID, tokenType string, payload map[string]any) error
	GetTrackToken(ctx context.Context, token string) (*TrackToken, error)
	RecordTokenUse(ctx context.Context, token string) error
}

// Recorder records evidence events. exercise.EvidenceChain satisfies this.
type Recorder interface {
	Record(ctx context.Context, execID, stepExecID, evType, actor, source string, payload map[string]any) error
}

// WebhookStore is an optional extension of TokenStore for inbound webhook calls.
// exercise.Store satisfies this interface when available.
type WebhookStore interface {
	InsertWebhookCall(ctx context.Context, token, execID, stepExecID string, body []byte) error
}

// TrackToken is a single-use tracking token issued by an injector.
type TrackToken struct {
	Token       string         `json:"token"`
	ExecutionID string         `json:"execution_id"`
	StepExecID  string         `json:"step_exec_id"`
	TargetID    string         `json:"target_id"`
	TokenType   string         `json:"token_type"` // "open", "click", "attach", "cred"
	Payload     map[string]any `json:"payload,omitempty"`
	UsedCount   int            `json:"used_count"`
	UsedAt      *time.Time     `json:"used_at,omitempty"`
}

// LinkConfig parameterises GenerateLinks.
type LinkConfig struct {
	TrackOpens  bool
	TrackClicks bool
	BaseURL     string // public base URL of the orchestrator, e.g. "https://bas.internal"
	LandingPage string // "safe" (default) or "cred"
	TargetID    string
}
