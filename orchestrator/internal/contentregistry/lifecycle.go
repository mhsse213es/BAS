package contentregistry

import "strings"

// IsHumanActor reports whether actor names a real user ("user:<id>").
func IsHumanActor(actor string) bool {
	return strings.HasPrefix(actor, "user:") && len(actor) > len("user:")
}

type transitionRule struct {
	from, to Lifecycle
	origin   Origin // "" = any origin
	human    bool
	system   bool // system-only: refused for human actors (spec 4.3)
}

// transitionRules is the complete allowed-transition table (spec §4.3 +
// plan amendment 5). Anything not listed is illegal; REJECTED is terminal,
// RETIRED is terminal except LOCAL re-approval.
var transitionRules = []transitionRule{
	{LifecycleDraft, LifecycleValidating, "", false, false},
	{LifecycleValidating, LifecycleValidated, "", false, true},
	{LifecycleValidating, LifecycleDraft, "", false, true},
	{LifecycleValidated, LifecycleApproved, OriginVendor, true, false},
	{LifecycleApproved, LifecyclePublished, OriginVendor, true, false},
	{LifecycleValidated, LifecyclePublishedLocal, OriginLocal, true, false},
	{LifecycleDraft, LifecyclePublishedLocal, OriginLocal, true, false},
	{LifecycleRetired, LifecyclePublishedLocal, OriginLocal, true, false},
	{LifecycleDraft, LifecycleRejected, "", true, false},
	{LifecycleValidating, LifecycleRejected, "", true, false},
	{LifecycleValidated, LifecycleRejected, "", true, false},
	{LifecycleApproved, LifecycleRejected, "", true, false},
	{LifecyclePublished, LifecycleRetired, OriginVendor, true, false},
	{LifecyclePublishedLocal, LifecycleRetired, OriginLocal, true, false},
}

// CheckTransition validates one lifecycle move. It is the single
// application-level authority; the DB CHECKs independently block illegal
// resulting states.
func CheckTransition(origin Origin, trust Trust, from, to Lifecycle, actor string) error {
	for _, r := range transitionRules {
		if r.from != from || r.to != to {
			continue
		}
		if r.origin != "" && r.origin != origin {
			return &ErrIllegalTransition{From: from, To: to, Reason: "not allowed for " + string(origin) + " content"}
		}
		if r.system && IsHumanActor(actor) {
			return &ErrIllegalTransition{From: from, To: to, Reason: "system-only transition"}
		}
		if r.human && !IsHumanActor(actor) {
			return &ErrIllegalTransition{From: from, To: to, Reason: "requires a human actor"}
		}
		if to == LifecyclePublished && trust != TrustVendorSigned {
			return &ErrIllegalTransition{From: from, To: to, Reason: "vendor signature not attached"}
		}
		return nil
	}
	return &ErrIllegalTransition{From: from, To: to, Reason: "transition not allowed"}
}

// TrustAfter is the trust a version holds after entering `to`. Only LOCAL
// publication changes trust; VENDOR_SIGNED is granted solely by verified
// intake or AttachVendorSignature, never by a transition.
func TrustAfter(origin Origin, current Trust, to Lifecycle) Trust {
	if origin == OriginLocal && to == LifecyclePublishedLocal {
		return TrustLocalTrusted
	}
	return current
}

// Executable is the runtime gate's combination rule (spec §6.1). devBuild
// must come from a compile-time property (integrity.Verifier.SigningEnabled
// of the compiled verifier), never from config.
func Executable(origin Origin, trust Trust, lc Lifecycle, devBuild bool) bool {
	switch {
	case origin == OriginVendor && trust == TrustVendorSigned && lc == LifecyclePublished:
		return true
	case origin == OriginLocal && trust == TrustLocalTrusted && lc == LifecyclePublishedLocal:
		return true
	case devBuild && origin == OriginVendor && trust == TrustUntrusted && lc == LifecyclePublished:
		return true
	}
	return false
}
