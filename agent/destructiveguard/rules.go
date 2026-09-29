// Package destructiveguard is the agent's independent, vendor-curated,
// binary-compiled local backstop against catastrophic commands -- the
// second of B5's two defense-in-depth layers (see
// docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md).
// This package is NEVER modifiable through an orchestrator command, a
// B4-signed envelope field, scenario YAML, an environment variable, or
// (in a later phase) a local grant -- the grant authorizes a
// catalog-defined action; it never redefines what this package
// considers catastrophic.
//
// Deliberately NOT a PowerShell/shell semantic parser -- that's brittle
// and creates a false sense of completeness. A small, deterministic rule
// set matched against the normalized executable + arguments instead.
package destructiveguard

import (
	"regexp"
	"strings"
)

type Class string

const (
	ClassNonDestructive         Class = "non_destructive"
	ClassPotentiallyDestructive Class = "potentially_destructive"
	ClassDestructive            Class = "destructive"
)

// rule pairs a compiled pattern with what it means. Patterns match
// against the NORMALIZED command (see normalize below), so they never
// need to account for casing, quoting, or a leading "& " call-operator
// by themselves.
type rule struct {
	pattern *regexp.Regexp
	class   Class
}

// rules is the seed set. Each pattern is deliberately narrow and
// anchored to a real, verified destructive command found in this
// codebase's own scenario library during the B5 design investigation
// (see the design spec's "Local backstop rule engine" section) --
// extend it with the same rigor (a real verified command, not a guess)
// as this list grows.
var rules = []rule{
	{regexp.MustCompile(`\bvssadmin(\.exe)?\b.*\bdelete\b.*\bshadows\b`), ClassDestructive},
	{regexp.MustCompile(`\bwbadmin(\.exe)?\b.*\bdelete\b.*\bcatalog\b`), ClassDestructive},
	{regexp.MustCompile(`\bwbadmin(\.exe)?\b.*\bdelete\b.*\bsystemstatebackup\b`), ClassDestructive},
	{regexp.MustCompile(`\bbcdedit(\.exe)?\b.*\brecoveryenabled\b\s+no\b`), ClassDestructive},
	{regexp.MustCompile(`\bbcdedit(\.exe)?\b.*\bbootstatuspolicy\b\s+ignoreallfailures\b`), ClassDestructive},
	{regexp.MustCompile(`\bcipher(\.exe)?\b.*(^|\s)/w\b`), ClassDestructive},
	{regexp.MustCompile(`\bformat\b.*[a-z]:`), ClassDestructive},
}

// normalize case-folds and collapses whitespace so trivial quoting/
// casing/spacing variations can't defeat a pattern. Deliberately does
// NOT attempt real shell tokenization (that's the semantic-parser
// approach this package exists to avoid) -- it only strips the
// characters a scenario author or attacker would plausibly vary without
// changing what the command actually does: surrounding quotes/call
// operators and repeated whitespace.
func normalize(command string) string {
	s := strings.ToLower(command)
	s = strings.ReplaceAll(s, "&", " ")
	s = strings.ReplaceAll(s, `"`, " ")
	s = strings.ReplaceAll(s, "'", " ")
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// Classify evaluates command against the local rule set and returns the
// most restrictive matching class, or ClassNonDestructive if nothing
// matches. Combined most-restrictive-wins with the signed catalog
// classification by the caller (agent/agent.go's B5 gate, Task 7) --
// this function never sees or considers that signed classification
// itself.
func Classify(command string) Class {
	n := normalize(command)
	for _, r := range rules {
		if r.pattern.MatchString(n) {
			return r.class
		}
	}
	return ClassNonDestructive
}
