// Package testutil provides shared test infrastructure for the orchestrator
// module: a real-Postgres test harness (TestDB, backed by testcontainers-go
// and the project's actual EnsureSchema/EnsureContentSchema migrations),
// entity builders, determinism helpers (frozen clock, sequential ids,
// seeded rand), JWT/auth test helpers, and golden-file regression test
// support.
//
// See docs/superpowers/specs/2026-07-09-test-generation-strategy-design.md
// for the full test generation strategy this package is the foundation of.
package testutil
