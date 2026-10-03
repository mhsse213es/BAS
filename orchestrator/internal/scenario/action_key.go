package scenario

import "github.com/audspect/bas/internal/scenario/actionkey"

// assignActionKeys derives and assigns a stable ActionKey to every step in
// steps, using the exact same slug+executor derivation
// orchestrator/cmd/auditcorpus uses to build execclass_generated.go -- so
// ResolveExecutionClass's lookup at dispatch time actually hits the
// per-item entries that tool generates, instead of always collapsing onto
// the technique's "enumerate" fallback. steps must all share the same
// source ("art" or "caldera") and are typically the full step list for one
// technique or one load, matching how collisions are already scoped
// (grouped by TechniqueID first, so calling this per-technique or over a
// whole load produces identical results).
//
// Steps involved in a genuine, unresolvable action_key collision (same
// technique+name+executor, different real command) are left with
// ActionKey == "" -- today's existing fallback behavior, unchanged for
// exactly those steps. A synthetic key for them would not match any real
// catalog entry (collision-excluded items are never written to
// execclass_generated.go) and would fail closed to destructive for items
// this audit already manually confirmed are benign discovery commands --
// see corpusaudit's SourceCounts.Collisions doc comment for the same
// reasoning.
func assignActionKeys(steps []ScenarioStep, source string) {
	items := make([]actionkey.DiscoveredItem, len(steps))
	for i, s := range steps {
		items[i] = actionkey.DiscoveredItem{
			Source: source, TechniqueID: s.TechniqueID, Name: s.Name,
			Executor: s.Executor, Command: s.Command,
		}
	}
	keyed, _ := actionkey.DeriveActionKeys(items)
	byIdentity := make(map[actionkey.DiscoveredItem]string, len(keyed))
	for _, k := range keyed {
		byIdentity[k.DiscoveredItem] = k.ActionKey
	}
	for i := range steps {
		steps[i].ActionKey = byIdentity[items[i]]
	}
}
