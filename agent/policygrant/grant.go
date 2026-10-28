// Package policygrant implements the Local Policy Grant Mechanism from the
// B5 destructive-action guardrail design
// (docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md)
// -- the only escape hatch for a destructive-classified step. Root of trust
// is the host OS's own administrative privilege boundary on this specific
// endpoint, never the orchestrator. Nothing in this package is reachable
// from any B4-signed field, scenario YAML, or environment variable; only
// the OS-privileged local CLI path (wired in package main) constructs a
// Request, and it alone decides what to do with the resulting Grant.
package policygrant

import (
	"fmt"
	"strings"
	"time"
)

// Grant authorizes exactly one catalog-defined action, on exactly one
// enrolled agent, for a bounded period. ScenarioID is optional: empty means
// the action is covered regardless of which scenario invokes it.
type Grant struct {
	AgentID    string    `json:"agentId"`
	Action     string    `json:"action"`
	ScenarioID string    `json:"scenarioId,omitempty"`
	Reason     string    `json:"reason"`
	IssuedAt   time.Time `json:"issuedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// Request is what an OS-privileged operator supplies via the CLI. AgentID
// and IssuedAt are never operator-chosen -- the agent fills them in from its
// own persistent identity and clock, never from anything the request itself
// could claim.
type Request struct {
	Action     string
	ScenarioID string
	Reason     string
	TTL        time.Duration
}

// Validate enforces the spec's REQUIRED fields and the "no permanent grant"
// invariant. Action must be shaped "technique_id:action_key" -- a bare
// execution_class (e.g. "destructive") is never a valid scope, mirroring
// the catalog's own rule that action_key is a lookup key, never a safety
// assertion on its own.
func (r Request) Validate() error {
	if r.Action == "" {
		return fmt.Errorf("action is required")
	}
	parts := strings.SplitN(r.Action, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("action must be shaped \"technique_id:action_key\", got %q", r.Action)
	}
	if r.Reason == "" {
		return fmt.Errorf("reason is required")
	}
	if r.TTL <= 0 {
		return fmt.Errorf("expiry (TTL) must be positive -- no permanent grant is supported")
	}
	return nil
}

// NewGrant validates r and binds it to agentID at now, the only two values a
// Grant carries that the request itself can never supply.
func NewGrant(agentID string, r Request, now time.Time) (Grant, error) {
	if err := r.Validate(); err != nil {
		return Grant{}, err
	}
	return Grant{
		AgentID:    agentID,
		Action:     r.Action,
		ScenarioID: r.ScenarioID,
		Reason:     r.Reason,
		IssuedAt:   now,
		ExpiresAt:  now.Add(r.TTL),
	}, nil
}

// Authorizes reports whether g currently authorizes action for agentID,
// optionally narrowed to scenarioID, at the given time. A grant copied
// verbatim from another agent's store must never validate -- hence the
// strict AgentID match -- and an unscoped grant (ScenarioID == "") covers
// every scenario, matching the spec's "omitted = covers the action
// regardless of which scenario invokes it".
func (g Grant) Authorizes(agentID, action, scenarioID string, now time.Time) bool {
	if g.AgentID != agentID || g.Action != action {
		return false
	}
	if g.ScenarioID != "" && g.ScenarioID != scenarioID {
		return false
	}
	return now.Before(g.ExpiresAt)
}
