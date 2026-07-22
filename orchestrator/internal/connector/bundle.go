package connector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// BundleFileName is the fixed name of the signed threat-intel bundle inside TI_BUNDLE_DIR.
const BundleFileName = "ti-bundle.json"

// Bundle is the air-gapped threat-intel pack: an operator builds it on an
// internet-connected box, signs it with the release key, and hand-carries it in.
type Bundle struct {
	Version     string        `json:"version"`
	GeneratedAt time.Time     `json:"generated_at"`
	Actors      []ThreatActor `json:"actors"`
}

// BundleSource reads a signed threat-intel bundle from a local directory. The
// signature verifier is injected (production passes integrity.VerifyScenarioFile)
// so the crypto is reused and the source can be unit-tested without the private key.
type BundleSource struct {
	path     string
	verify   func(path string) error
	version  string
	lastStat SourceStat
}

// NewBundleSource creates a BundleSource reading <dir>/ti-bundle.json. verify may
// be nil to skip signature checking — do not do that outside tests.
func NewBundleSource(dir string, verify func(string) error) *BundleSource {
	return &BundleSource{
		path:   filepath.Join(dir, BundleFileName),
		verify: verify,
	}
}

// Name identifies this source. Implements Source.
func (b *BundleSource) Name() string { return "bundle" }

// Version returns the version string of the most recently fetched bundle.
func (b *BundleSource) Version() string { return b.version }

// Fetch verifies the bundle signature (when a verifier is set), then parses it.
// A tampered, unsigned, missing, or malformed bundle returns an error and no actors.
func (b *BundleSource) Fetch() ([]ThreatActor, error) {
	if b.verify != nil {
		if err := b.verify(b.path); err != nil {
			b.lastStat = SourceStat{Name: "bundle", Error: err.Error(), FetchedAt: time.Now()}
			return nil, fmt.Errorf("ti bundle verify: %w", err)
		}
	}
	raw, err := os.ReadFile(b.path)
	if err != nil {
		b.lastStat = SourceStat{Name: "bundle", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("read ti bundle: %w", err)
	}
	var bundle Bundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		b.lastStat = SourceStat{Name: "bundle", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("parse ti bundle %s: %w", b.path, err)
	}
	// Stamp provenance so status/downstream can distinguish bundle-provided actors.
	for i := range bundle.Actors {
		if bundle.Actors[i].Source == "" {
			bundle.Actors[i].Source = "bundle"
		}
	}
	b.version = bundle.Version
	b.lastStat = SourceStat{Name: "bundle", RawCount: len(bundle.Actors), ActorCount: len(bundle.Actors), FetchedAt: time.Now()}
	return bundle.Actors, nil
}

// Stats implements StatsSource.
func (b *BundleSource) Stats() SourceStat { return b.lastStat }
