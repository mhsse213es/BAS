// Package adchain implements AD-M05: the capability-state chaining
// mechanism adprimitive's own doc comment names as this phase's job --
// matching one primitive's Postconditions against another's
// Prerequisites.Capabilities by equality. Depends one-way on
// adprimitive only.
package adchain

// ConditionResolver answers whether a Prerequisites.Conditions key holds
// true in some environment context. Resolving a key against a REAL
// environment's graph (attackpath/adenv) is explicitly out of scope for
// this phase -- ConditionResolver is the seam a later phase fills in.
type ConditionResolver interface {
	Resolve(key string) bool
}

// MapResolver is a trivial ConditionResolver backed by a plain map, for
// tests and for any caller that already has a fully-resolved condition
// set in hand. A key with no entry resolves to false (the catalog's own
// fail-closed convention: an unconfirmed condition is not satisfied).
type MapResolver map[string]bool

func (m MapResolver) Resolve(key string) bool {
	return m[key]
}
