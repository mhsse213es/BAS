package connector

import (
	"fmt"
	"log"
	"time"
)

// BuildBundle fetches every source and merges the result into a Bundle ready
// to be JSON-marshaled and signed — the same shape BundleSource.Fetch reads
// back. Used by the operator-side scripts/ti-bundle-builder.go CLI to build
// the air-gapped bundle from a live MISP/OpenCTI pull.
//
// A source that errors is logged and skipped (mirrors Scheduler.sync's
// per-source isolation), but zero total actors across every source is a hard
// error — never produce an empty bundle, which would silently blank out a
// client's air-gapped intel on the next hand-carry.
func BuildBundle(sources []Source, version string) (Bundle, error) {
	var actors []ThreatActor
	for _, src := range sources {
		got, err := src.Fetch()
		if err != nil {
			log.Printf("[ti-bundle-builder/%s] fetch error: %v", src.Name(), err)
			continue
		}
		log.Printf("[ti-bundle-builder/%s] %d actors fetched", src.Name(), len(got))
		actors = append(actors, got...)
	}
	if len(actors) == 0 {
		return Bundle{}, fmt.Errorf("ti-bundle-builder: no actors returned from any source — refusing to write an empty bundle")
	}
	return Bundle{
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Actors:      MergeActors(actors),
	}, nil
}
