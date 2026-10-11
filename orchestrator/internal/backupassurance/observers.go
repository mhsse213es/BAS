package backupassurance

import "context"

// Each observer interface is a 5-tuple (tested, outcome bool, observerID,
// reason string, err error) -- outcome is named meaningfully per check.
// observerID is the implementation's own self-reported identity (never
// assigned by AssessBackup), so swapping in a real observer later changes
// provenance without touching dispatch code.

type DeletionProtectionObserver interface {
	ObserveDeletionProtection(ctx context.Context) (tested, protected bool, observerID, reason string, err error)
}

type ImmutabilityObserver interface {
	ObserveImmutability(ctx context.Context) (tested, immutable bool, observerID, reason string, err error)
}

type OfflineIsolationObserver interface {
	ObserveOfflineIsolation(ctx context.Context) (tested, isolated bool, observerID, reason string, err error)
}

type PrivilegeSeparationObserver interface {
	ObservePrivilegeSeparation(ctx context.Context) (tested, separated bool, observerID, reason string, err error)
}

type RestoreIntegrityObserver interface {
	ObserveRestoreIntegrity(ctx context.Context) (tested, valid bool, observerID, reason string, err error)
}

type RPORTOObserver interface {
	ObserveRPORTO(ctx context.Context) (tested, met bool, observerID, reason string, err error)
}

// Fake implementations: an uncaptured key (the zero value, Tested=false)
// means "never evaluated" -- never a guessed outcome. Same discipline as
// rwevidence.FakeRecoveryObserver/FakeDetectionLookup.

type FakeDeletionProtectionObserver struct {
	Tested, Protected bool
	Reason, Observer  string
	Err               error
}

func (f *FakeDeletionProtectionObserver) ObserveDeletionProtection(_ context.Context) (bool, bool, string, string, error) {
	obs := f.Observer
	if obs == "" {
		obs = "fake:deletion-protection-v1"
	}
	return f.Tested, f.Protected, obs, f.Reason, f.Err
}

type FakeImmutabilityObserver struct {
	Tested, Immutable bool
	Reason, Observer  string
	Err               error
}

func (f *FakeImmutabilityObserver) ObserveImmutability(_ context.Context) (bool, bool, string, string, error) {
	obs := f.Observer
	if obs == "" {
		obs = "fake:immutability-v1"
	}
	return f.Tested, f.Immutable, obs, f.Reason, f.Err
}

type FakeOfflineIsolationObserver struct {
	Tested, Isolated bool
	Reason, Observer string
	Err              error
}

func (f *FakeOfflineIsolationObserver) ObserveOfflineIsolation(_ context.Context) (bool, bool, string, string, error) {
	obs := f.Observer
	if obs == "" {
		obs = "fake:offline-isolation-v1"
	}
	return f.Tested, f.Isolated, obs, f.Reason, f.Err
}

type FakePrivilegeSeparationObserver struct {
	Tested, Separated bool
	Reason, Observer  string
	Err               error
}

func (f *FakePrivilegeSeparationObserver) ObservePrivilegeSeparation(_ context.Context) (bool, bool, string, string, error) {
	obs := f.Observer
	if obs == "" {
		obs = "fake:privilege-separation-v1"
	}
	return f.Tested, f.Separated, obs, f.Reason, f.Err
}

type FakeRestoreIntegrityObserver struct {
	Tested, ValidResult bool
	Reason, Observer    string
	Err                 error
}

func (f *FakeRestoreIntegrityObserver) ObserveRestoreIntegrity(_ context.Context) (bool, bool, string, string, error) {
	obs := f.Observer
	if obs == "" {
		obs = "fake:restore-integrity-v1"
	}
	return f.Tested, f.ValidResult, obs, f.Reason, f.Err
}

type FakeRPORTOObserver struct {
	Tested, Met      bool
	Reason, Observer string
	Err              error
}

func (f *FakeRPORTOObserver) ObserveRPORTO(_ context.Context) (bool, bool, string, string, error) {
	obs := f.Observer
	if obs == "" {
		obs = "fake:rpo-rto-v1"
	}
	return f.Tested, f.Met, obs, f.Reason, f.Err
}
