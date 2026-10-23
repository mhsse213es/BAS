// Package novelty decides whether a generated scenario repeats something the
// existing catalogue already tests. Two scenarios overlap when their attack
// steps have the same FeatureKey: claim, normalized (method, path shape) and
// the behaviour around the attack (repeat, parallel, accepted-attempt cap,
// credential mode, cross-actor, setup and co-actor steps). Scenario ids and
// names play no part.
package novelty

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/audspect/bas/internal/apibas/contract"
)

var (
	numericSeg = regexp.MustCompile(`^[0-9]+$`)
	uuidSeg    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Shape normalizes a request path: the query is dropped, the path is lower
// cased, and every placeholder ({x}), numeric or uuid-like segment becomes
// {id}.
func Shape(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	var out []string
	for _, seg := range strings.Split(strings.ToLower(path), "/") {
		switch {
		case seg == "":
			continue
		case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}"),
			numericSeg.MatchString(seg), uuidSeg.MatchString(seg):
			seg = "{id}"
		}
		out = append(out, seg)
	}
	return "/" + strings.Join(out, "/")
}

// FeatureKey identifies what a scenario's attack does: the claim it makes,
// the request it sends and the behaviour around it. Two scenarios overlap only
// when their keys are equal.
type FeatureKey struct {
	Claim  string
	Method string
	Shape  string
	// Repeated and Parallel: the attack is sent more than once, and
	// concurrently.
	Repeated, Parallel bool
	// Capped: the scenario allows a bounded number of accepted attempts.
	Capped bool
	// Auth is the attack credential mode: valid, none, revoked or forge.
	Auth string
	// CrossActor: the attack identity differs from the baseline owner.
	CrossActor bool
	// Setup: more than the baseline and attack steps. CoActor: a second
	// identity acts in a setup step.
	Setup, CoActor bool
}

// String is a stable text form of the key.
func (k FeatureKey) String() string {
	return fmt.Sprintf("%s|%s %s|rep=%t par=%t cap=%t auth=%s cross=%t setup=%t co=%t",
		k.Claim, k.Method, k.Shape, k.Repeated, k.Parallel, k.Capped, k.Auth, k.CrossActor, k.Setup, k.CoActor)
}

// Features derives the key from the scenario alone (its attack step is the
// last one), so generated and catalogue scenarios are described symmetrically.
// A scenario without steps yields the zero key.
func Features(s contract.Scenario) FeatureKey {
	if len(s.Steps) == 0 {
		return FeatureKey{}
	}
	at := s.Steps[len(s.Steps)-1]
	auth := at.Auth
	switch auth {
	case "":
		auth = "valid"
	case "alg_none":
		auth = "forge"
	}
	k := FeatureKey{
		Claim:      s.Claim,
		Method:     strings.ToUpper(at.Method),
		Shape:      Shape(at.Path),
		Repeated:   at.Repeat > 1,
		Parallel:   at.Parallel,
		Capped:     s.MaxAcceptedAttempts > 0,
		Auth:       auth,
		CrossActor: s.Steps[0].Identity != at.Identity,
		Setup:      len(s.Steps) > 2,
	}
	for _, st := range s.Steps {
		k.CoActor = k.CoActor || st.CoActor
	}
	return k
}

// Covered reports whether the catalogue already tests what s tests: some
// catalogue scenario has an equal FeatureKey. A scenario without steps is
// never covered.
func Covered(s contract.Scenario, cat []contract.Scenario) bool {
	if len(s.Steps) == 0 {
		return false
	}
	want := Features(s)
	for _, c := range cat {
		if len(c.Steps) > 0 && Features(c) == want {
			return true
		}
	}
	return false
}
