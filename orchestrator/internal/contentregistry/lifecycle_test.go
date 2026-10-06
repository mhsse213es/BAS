package contentregistry

import "testing"

var allOrigins = []Origin{OriginVendor, OriginLocal}
var allTrusts = []Trust{TrustVendorSigned, TrustLocalTrusted, TrustUntrusted}
var allLifecycles = []Lifecycle{LifecycleDraft, LifecycleValidating, LifecycleValidated, LifecycleApproved,
	LifecyclePublished, LifecyclePublishedLocal, LifecycleRetired, LifecycleRejected}

// A5 (pure half): exactly two combinations run in production; the dev
// exception adds exactly one.
func TestExecutableMatrix(t *testing.T) {
	for _, o := range allOrigins {
		for _, tr := range allTrusts {
			for _, lc := range allLifecycles {
				prod := (o == OriginVendor && tr == TrustVendorSigned && lc == LifecyclePublished) ||
					(o == OriginLocal && tr == TrustLocalTrusted && lc == LifecyclePublishedLocal)
				dev := prod || (o == OriginVendor && tr == TrustUntrusted && lc == LifecyclePublished)
				if got := Executable(o, tr, lc, false); got != prod {
					t.Errorf("prod %s/%s/%s = %v want %v", o, tr, lc, got, prod)
				}
				if got := Executable(o, tr, lc, true); got != dev {
					t.Errorf("dev %s/%s/%s = %v want %v", o, tr, lc, got, dev)
				}
			}
		}
	}
}

func TestCheckTransition_Rules(t *testing.T) {
	const user = "user:u1"
	cases := []struct {
		name     string
		o        Origin
		tr       Trust
		from, to Lifecycle
		actor    string
		ok       bool
	}{
		{"draft to validating by system", OriginVendor, TrustUntrusted, LifecycleDraft, LifecycleValidating, "system:validator", true},
		{"validated to approved vendor user", OriginVendor, TrustUntrusted, LifecycleValidated, LifecycleApproved, user, true},
		{"validated to approved needs human", OriginVendor, TrustUntrusted, LifecycleValidated, LifecycleApproved, "intake", false},
		{"approved local impossible", OriginLocal, TrustUntrusted, LifecycleValidated, LifecycleApproved, user, false},
		{"approved to published needs signature", OriginVendor, TrustUntrusted, LifecycleApproved, LifecyclePublished, user, false},
		{"approved to published signed", OriginVendor, TrustVendorSigned, LifecycleApproved, LifecyclePublished, user, true},
		{"draft to published_local local", OriginLocal, TrustUntrusted, LifecycleDraft, LifecyclePublishedLocal, user, true},
		{"draft to published_local vendor", OriginVendor, TrustUntrusted, LifecycleDraft, LifecyclePublishedLocal, user, false},
		{"draft straight to published", OriginVendor, TrustVendorSigned, LifecycleDraft, LifecyclePublished, user, false},
		{"retired to published_local re-approval", OriginLocal, TrustLocalTrusted, LifecycleRetired, LifecyclePublishedLocal, user, true},
		{"retired vendor is terminal", OriginVendor, TrustVendorSigned, LifecycleRetired, LifecyclePublished, user, false},
		{"rejected is terminal", OriginLocal, TrustUntrusted, LifecycleRejected, LifecycleDraft, user, false},
		{"published_local retire", OriginLocal, TrustLocalTrusted, LifecyclePublishedLocal, LifecycleRetired, user, true},
		{"retire needs human", OriginLocal, TrustLocalTrusted, LifecyclePublishedLocal, LifecycleRetired, "intake", false},
		{"validated is not executable shortcut", OriginLocal, TrustUntrusted, LifecycleValidated, LifecyclePublished, user, false},
		{"validated by human refused", OriginVendor, TrustUntrusted, LifecycleValidating, LifecycleValidated, user, false},
		{"validated by system", OriginVendor, TrustUntrusted, LifecycleValidating, LifecycleValidated, ActorIntake, true},
		{"validating back to draft by human refused", OriginLocal, TrustUntrusted, LifecycleValidating, LifecycleDraft, user, false},
		{"validating back to draft by generator", OriginLocal, TrustUntrusted, LifecycleValidating, LifecycleDraft, ActorGenerator, true},
		{"reject from approved", OriginVendor, TrustUntrusted, LifecycleApproved, LifecycleRejected, user, true},
	}
	for _, c := range cases {
		err := CheckTransition(c.o, c.tr, c.from, c.to, c.actor)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestTrustAfter(t *testing.T) {
	if got := TrustAfter(OriginLocal, TrustUntrusted, LifecyclePublishedLocal); got != TrustLocalTrusted {
		t.Fatalf("local publish: %s", got)
	}
	if got := TrustAfter(OriginLocal, TrustLocalTrusted, LifecycleRetired); got != TrustLocalTrusted {
		t.Fatalf("retire keeps historical trust: %s", got)
	}
	if got := TrustAfter(OriginVendor, TrustUntrusted, LifecycleApproved); got != TrustUntrusted {
		t.Fatalf("approval never grants vendor trust: %s", got)
	}
}

func TestIsHumanActor(t *testing.T) {
	for in, want := range map[string]bool{"user:u1": true, "user:": false, "intake": false, "migration:pre-registry": false, "": false} {
		if IsHumanActor(in) != want {
			t.Errorf("IsHumanActor(%q) != %v", in, want)
		}
	}
}
