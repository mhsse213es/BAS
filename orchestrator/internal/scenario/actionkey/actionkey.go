// Package actionkey derives a stable, collision-safe action_key for a
// real ART atomic or Caldera ability, from its own Name/Executor/Command
// text. It has no dependency on the scenario package so both the scenario
// package itself (real step construction, at dispatch-load time) and
// orchestrator/internal/scenario/corpusaudit (the offline audit tool,
// batch-processing the whole live corpus) use the exact same derivation --
// otherwise a key computed by one would never match a catalog entry
// written by the other.
package actionkey

import (
	"fmt"
	"regexp"
	"strings"
)

// DiscoveredItem is one real ART atomic or Caldera ability, before
// action-key derivation.
type DiscoveredItem struct {
	Source      string // "art" | "caldera"
	TechniqueID string
	Name        string
	Executor    string
	Command     string
	AbilityID   string // Caldera only; "" for ART. Provenance only, never used to derive action_key.
	Reachable   bool   // has a real non-empty command AND a technique mapping
}

// KeyedItem is a DiscoveredItem with its derived action_key assigned.
type KeyedItem struct {
	DiscoveredItem
	ActionKey string
}

// CollisionError describes a true, unresolvable action_key collision: two
// DiscoveredItems with the same TechniqueID, slug, and executor but
// genuinely different Command text. Neither item is kept in
// DeriveActionKeys' returned slice when this occurs -- callers must never
// pick one arbitrarily.
type CollisionError struct {
	TechniqueID, ActionKey string
	ItemA, ItemB           DiscoveredItem
}

func (e CollisionError) Error() string {
	return fmt.Sprintf("unresolvable action_key collision: %s/%s between %q and %q",
		e.TechniqueID, e.ActionKey, e.ItemA.Name, e.ItemB.Name)
}

var slugNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify derives an action_key-style token from a human-readable name,
// matching the hand-authored catalog's existing snake_case convention.
func Slugify(name string) string {
	s := strings.ToLower(name)
	s = slugNonAlnum.ReplaceAllString(s, "_")
	return strings.Trim(s, "_")
}

// DeriveActionKeys assigns an action_key to every item, grouped by
// TechniqueID. Two items whose Name slugifies the same get an executor
// suffix. If that still collides on genuinely different Command text,
// both items are reported as a CollisionError and omitted from the
// returned slice -- never silently picked or overwritten. Two items that
// collide on slug+executor AND share identical Command text are treated
// as real duplicates of the same atomic/ability and share one action_key.
func DeriveActionKeys(items []DiscoveredItem) ([]KeyedItem, []CollisionError) {
	byTechSlug := map[string]map[string][]int{}
	for i, it := range items {
		slug := Slugify(it.Name)
		if byTechSlug[it.TechniqueID] == nil {
			byTechSlug[it.TechniqueID] = map[string][]int{}
		}
		byTechSlug[it.TechniqueID][slug] = append(byTechSlug[it.TechniqueID][slug], i)
	}

	actionKeys := make([]string, len(items))
	var collisions []CollisionError
	skip := make(map[int]bool)

	for tech, slugs := range byTechSlug {
		for slug, group := range slugs {
			if len(group) == 1 {
				actionKeys[group[0]] = slug
				continue
			}
			byExecutor := map[string][]int{}
			for _, i := range group {
				byExecutor[items[i].Executor] = append(byExecutor[items[i].Executor], i)
			}
			for executor, execGroup := range byExecutor {
				key := slug
				if len(byExecutor) > 1 {
					key = slug + "_" + executor
				}
				if len(execGroup) == 1 {
					actionKeys[execGroup[0]] = key
					continue
				}
				firstCmd := items[execGroup[0]].Command
				allSame := true
				for _, i := range execGroup[1:] {
					if items[i].Command != firstCmd {
						allSame = false
						break
					}
				}
				if allSame {
					for _, i := range execGroup {
						actionKeys[i] = key
					}
					continue
				}
				for i := 0; i < len(execGroup); i++ {
					for j := i + 1; j < len(execGroup); j++ {
						if items[execGroup[i]].Command != items[execGroup[j]].Command {
							collisions = append(collisions, CollisionError{
								TechniqueID: tech, ActionKey: key,
								ItemA: items[execGroup[i]], ItemB: items[execGroup[j]],
							})
						}
					}
				}
				for _, i := range execGroup {
					skip[i] = true
				}
			}
		}
	}

	out := make([]KeyedItem, 0, len(items))
	for i, it := range items {
		if skip[i] {
			continue
		}
		out = append(out, KeyedItem{DiscoveredItem: it, ActionKey: actionKeys[i]})
	}
	return out, collisions
}
