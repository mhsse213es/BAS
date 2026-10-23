package fixtures

import (
	"context"
	"errors"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// seedPanicAd panics inside the adapter's Seed after the fixture exists.
type seedPanicAd struct{ *fakeAd }

func (f *seedPanicAd) Seed(ctx context.Context, fx dbprobe.Fixture) error {
	f.rec("seed")
	f.state = []string{"schema:dbsim_" + fx.ID}
	panic("adapter seed exploded")
}

// inspectPanicAd panics on the n-th InspectFixture call (1-based).
type inspectPanicAd struct {
	*fakeAd
	n, seen int
}

func (f *inspectPanicAd) InspectFixture(ctx context.Context, fx dbprobe.Fixture) ([]string, error) {
	f.seen++
	if f.seen == f.n {
		f.rec("inspect")
		panic("inspect exploded")
	}
	return f.fakeAd.InspectFixture(ctx, fx)
}

func neverCalled(t *testing.T) func(dbprobe.Fixture) error {
	return func(dbprobe.Fixture) error { t.Error("fn must not run"); return nil }
}

// A panic in the adapter's Seed means the fixture MAY exist: the exact-name
// teardown must run, and a verified-clean teardown is reported as such.
func TestWithFixtureSeedPanicRunsTeardown(t *testing.T) {
	ad := &seedPanicAd{labAd()}
	_, err := WithFixture(context.Background(), ad, mustSpec(t, "accounts"), neverCalled(t))
	var sp *SeedPanic
	if !errors.As(err, &sp) {
		t.Fatalf("want *SeedPanic, got %v", err)
	}
	if !sp.TornDown {
		t.Fatal("teardown ran and verified clean: TornDown must be true")
	}
	var inc *ErrSafetyIncident
	if errors.As(err, &inc) {
		t.Fatal("a verified-clean teardown is not an incident")
	}
	if got := strings.Join(ad.calls, ","); got != "inspect,seed,cleanup,inspect" {
		t.Fatalf("calls = %s", got)
	}
}

func TestWithFixtureSeedPanicWithFailedCleanupIsIncident(t *testing.T) {
	ad := &seedPanicAd{labAd()}
	ad.leftover = []string{"schema:dbsim_x"}
	_, err := WithFixture(context.Background(), ad, mustSpec(t, "accounts"), neverCalled(t))
	var inc *ErrSafetyIncident
	if !errors.As(err, &inc) || inc.Status != StatusResidual {
		t.Fatalf("want residual incident, got %v", err)
	}
	if !strings.Contains(inc.Error(), "seed panicked") {
		t.Fatalf("incident should name the seed panic: %v", inc)
	}
	ad2 := &seedPanicAd{labAd()}
	ad2.cleanupErr = errors.New("timeout")
	ad2.errClears = true
	_, err = WithFixture(context.Background(), ad2, mustSpec(t, "accounts"), neverCalled(t))
	if !errors.As(err, &inc) || inc.Status != StatusFailed {
		t.Fatalf("want failed incident, got %v", err)
	}
}

// A panic before the adapter's Seed is called (pre-state inspection): nothing
// was created, nothing is cleaned or dropped.
func TestWithFixturePreSeedInspectPanicIsNotApplicable(t *testing.T) {
	ad := &inspectPanicAd{fakeAd: labAd(), n: 1}
	_, err := WithFixture(context.Background(), ad, mustSpec(t, "accounts"), neverCalled(t))
	var sp *SeedPanic
	if !errors.As(err, &sp) || sp.TornDown {
		t.Fatalf("want *SeedPanic with TornDown=false, got %v", err)
	}
	if got := strings.Join(ad.calls, ","); got != "inspect" {
		t.Fatalf("calls = %s: no seed, cleanup or DROP may follow", got)
	}
}

// A panic in the post-seed visibility inspection: the fixture exists, so the
// teardown must run.
func TestWithFixturePostSeedInspectPanicRunsTeardown(t *testing.T) {
	ad := &inspectPanicAd{fakeAd: labAd(), n: 2}
	_, err := WithFixture(context.Background(), ad, mustSpec(t, "accounts"), neverCalled(t))
	var sp *SeedPanic
	var inc *ErrSafetyIncident
	if !errors.As(err, &sp) && !errors.As(err, &inc) {
		t.Fatalf("want SeedPanic or incident, got %v", err)
	}
	if !strings.Contains(strings.Join(ad.calls, ","), "cleanup") {
		t.Fatalf("teardown must run: %v", ad.calls)
	}
}
