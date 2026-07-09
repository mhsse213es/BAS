// Package mocks holds hand-written fakes for external systems consumed by
// the orchestrator: SIEM providers, ticketing systems, detection
// connectors, agents, notifiers, and storage backends.
//
// As of Phase 0, internal/siem, internal/ticketing, and internal/connector
// expose concrete structs with no interface to mock against. Extracting the
// minimal interface each package needs, and adding the corresponding mock
// here, is in scope for Phase 4 — see
// docs/superpowers/specs/2026-07-09-test-generation-strategy-design.md.
package mocks
