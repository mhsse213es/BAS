// Package ingest implements the generic inbound security-event ingestion
// API: an authenticated endpoint that lets a customer's own SIEM/SOAR/ITSM
// tooling push detection and evidence records into Audspect without a
// bespoke per-vendor connector (the inverse of internal/detectverify, which
// pulls alerts from a handful of named vendors during a BAS run).
//
// Scope note: this is a single on-prem deployment's own ingestion point --
// there is one customer per deployment, so there is no tenant concept to
// bind events to (see RateLimitMiddleware's comment in internal/api for the
// same framing). Authentication is one shared secret per deployment
// (BAS_INGEST_API_KEY), not per-customer key management.
package ingest

import (
	"encoding/json"
	"time"
)

// Request is the versioned JSON body for POST /api/ingest/v1/events.
type Request struct {
	SchemaVersion int     `json:"schema_version"`
	Events        []Event `json:"events"`
}

// Event is one normalized detection or evidence record from the customer's
// own security tooling. Source and ExternalEventID together are the
// idempotency key: a retry of the same (Source, ExternalEventID) is
// recorded once (see ProcessEvent).
type Event struct {
	Source          string          `json:"source"`
	ExternalEventID string          `json:"external_event_id"`
	EventType       string          `json:"event_type"` // "detection" | "evidence"
	Timestamp       time.Time       `json:"timestamp"`
	Severity        string          `json:"severity,omitempty"`
	IOC             *IOCPayload     `json:"ioc,omitempty"`
	TechniqueID     string          `json:"technique_id,omitempty"`
	Raw             json.RawMessage `json:"raw,omitempty"`
}

// IOCPayload names an indicator using the same type vocabulary as
// internal/iocregistry (iocregistry.Type) -- "ip", "domain", "file_hash",
// etc. An event with no IOC payload (e.g. a pure "no detection" heartbeat)
// is still recorded for idempotency; it just never produces an iocs row.
type IOCPayload struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// EventResult reports what happened to one event in the request. Status is
// one of "created" (a new ledger row was written, and an IOC row if the
// event had one), "duplicate" (this exact (source, external_event_id) was
// already ingested -- a safe retry, not an error), or "error" (the event
// was rejected before being recorded; see Error).
type EventResult struct {
	ExternalEventID string `json:"external_event_id"`
	Status          string `json:"status"`
	IOCID           string `json:"ioc_id,omitempty"`
	Error           string `json:"error,omitempty"`
}
