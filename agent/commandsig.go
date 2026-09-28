package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"audspect/agent/protocol"
)

// issuedAtFutureTolerance bounds how far into the future IssuedAt may
// claim to be before it's treated as backdated/malformed rather than
// ordinary clock skew between the orchestrator and this agent -- a few
// seconds, deliberately much smaller than the 60s validity window itself.
const issuedAtFutureTolerance = 5 * time.Second

// replayCache tracks CommandIDs already accepted, so the exact same
// envelope can't execute twice within its own validity window. Package-
// level and mutex-guarded (not per-Agent) since an agent process has
// exactly one identity for its whole lifetime; keyed by CommandID (not
// Nonce) per the spec's explicit locked correction. This provides
// duplicate-delivery protection WITHIN this process; the short (60s)
// cryptographic validity window is what limits a captured envelope's
// usefulness ACROSS a process restart, not this cache -- see the spec's
// "Expiry & replay" section for the exact locked rationale.
var (
	replayMu    sync.Mutex
	replayCache = make(map[string]time.Time) // commandID -> expiry
)

// verifyCommandEnvelope unmarshals raw as a protocol.CommandEnvelope and
// runs the full rejection checklist before returning it as trusted. Only
// called for msg.Type values where protocol.IsSignedCommandType is
// already true -- see agent.go's connectWS, which checks that BEFORE
// calling this at all, so an unrecognized command type never reaches
// signature verification (the spec's explicit hard rule).
func (a *Agent) verifyCommandEnvelope(raw json.RawMessage, expectedType string) (*protocol.CommandEnvelope, error) {
	var env protocol.CommandEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode command envelope: %w", err)
	}

	if env.Version != protocol.CommandEnvelopeVersion {
		return nil, fmt.Errorf("unsupported envelope version %d (this agent understands version %d)", env.Version, protocol.CommandEnvelopeVersion)
	}
	if env.CommandType != expectedType {
		return nil, fmt.Errorf("envelope commandType %q does not match the WS message type %q", env.CommandType, expectedType)
	}
	if env.AgentID != a.id.AgentID {
		return nil, fmt.Errorf("envelope agentId %q does not match this agent's own identity %q", env.AgentID, a.id.AgentID)
	}
	now := time.Now().UTC()
	if env.ExpiresAt.Before(now) {
		return nil, fmt.Errorf("envelope expired at %s (now %s)", env.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if !env.ExpiresAt.After(env.IssuedAt) {
		return nil, fmt.Errorf("envelope expiresAt (%s) is not after issuedAt (%s)", env.ExpiresAt.Format(time.RFC3339), env.IssuedAt.Format(time.RFC3339))
	}
	if env.IssuedAt.After(now.Add(issuedAtFutureTolerance)) {
		return nil, fmt.Errorf("envelope issuedAt (%s) is unreasonably in the future (now %s)", env.IssuedAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	cert, err := loadCommandSigningCert()
	if err != nil {
		return nil, fmt.Errorf("no command-signing trust established (enrollment may not have completed): %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("persisted command-signing certificate does not hold an RSA public key")
	}
	canon, err := env.CanonicalJSON()
	if err != nil {
		return nil, fmt.Errorf("canonicalize envelope: %w", err)
	}
	hash := sha256.Sum256(canon)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], env.Signature); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	replayMu.Lock()
	pruneExpiredReplayEntries(now)
	if _, seen := replayCache[env.CommandID]; seen {
		replayMu.Unlock()
		return nil, fmt.Errorf("commandId %q already consumed (replay)", env.CommandID)
	}
	replayCache[env.CommandID] = env.ExpiresAt
	replayMu.Unlock()

	return &env, nil
}

// pruneExpiredReplayEntries removes cache entries whose validity window
// has passed, so the map doesn't grow unbounded over a long-running
// agent process. Called inline on every verification rather than on a
// separate ticker -- cheap at this command volume, and needs no new
// goroutine. Caller already holds replayMu.
func pruneExpiredReplayEntries(now time.Time) {
	for id, expiry := range replayCache {
		if expiry.Before(now) {
			delete(replayCache, id)
		}
	}
}
