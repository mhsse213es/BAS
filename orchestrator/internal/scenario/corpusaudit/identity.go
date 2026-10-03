package corpusaudit

import "github.com/audspect/bas/internal/scenario/actionkey"

// DiscoveredItem, KeyedItem, CollisionError, Slugify, and DeriveActionKeys
// are forwarded from actionkey rather than implemented here, so the
// scenario package's real step-construction code (art.go, caldera_store.go)
// and this audit tool derive action_key identically -- a key this tool
// writes into execclass_generated.go must match the key the real
// dispatch path computes for the same item, or the lookup silently
// misses. See actionkey's own package doc for why it has no scenario
// dependency.
type DiscoveredItem = actionkey.DiscoveredItem
type KeyedItem = actionkey.KeyedItem
type CollisionError = actionkey.CollisionError

func Slugify(name string) string { return actionkey.Slugify(name) }

func DeriveActionKeys(items []DiscoveredItem) ([]KeyedItem, []CollisionError) {
	return actionkey.DeriveActionKeys(items)
}
