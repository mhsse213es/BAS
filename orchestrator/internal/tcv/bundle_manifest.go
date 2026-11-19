package tcv

import (
	"errors"
	"fmt"
	"time"
)

// bundleManifestSchema is the only manifest schema version this code reads.
// Bump it (and add a reader) if the build script's format changes.
const bundleManifestSchema = 1

// BundleManifest is the JSON written by packaging/build.sh after the signing
// gate passes. It lists each shipped scenario file with its SHA-256.
type BundleManifest struct {
	Schema     int           `json:"schema"`
	BundleID   string        `json:"bundle_id"`
	PackagedAt time.Time     `json:"packaged_at"`
	Entries    []BundleEntry `json:"entries"`
}

// BundleEntry is one shipped file.
type BundleEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Validate rejects a manifest that cannot produce trustworthy events. A zero
// packaged_at would poison the SLA projection, so it is refused here as it is
// in RecordPipelineEvent.
func (m BundleManifest) Validate() error {
	if m.Schema != bundleManifestSchema {
		return fmt.Errorf("tcv: bundle manifest schema %d not supported (want %d)", m.Schema, bundleManifestSchema)
	}
	if m.BundleID == "" {
		return errors.New("tcv: bundle manifest has an empty bundle_id")
	}
	if m.PackagedAt.IsZero() {
		return errors.New("tcv: bundle manifest has a zero packaged_at")
	}
	return nil
}

// BundlePackagedEvents maps a manifest to one bundle_packaged event per
// shipped file whose SHA-256 is a known registry artifact. versionBySHA maps
// sha256 to content_version_id. Hashes with no registry match are returned in
// unmatched, never dropped silently. Identical bytes shipped under two paths
// produce one event (the first path wins), so they are not double-counted.
func BundlePackagedEvents(m BundleManifest, versionBySHA map[string]string) (events []Event, unmatched []string) {
	seen := make(map[string]bool, len(m.Entries))
	for _, entry := range m.Entries {
		if seen[entry.SHA256] {
			continue
		}
		seen[entry.SHA256] = true
		versionID, ok := versionBySHA[entry.SHA256]
		if !ok {
			unmatched = append(unmatched, entry.SHA256)
			continue
		}
		events = append(events, Event{
			Type:             EventBundlePackaged,
			ContentVersionID: versionID,
			EventTime:        m.PackagedAt,
			SourceTable:      "bundle_manifest",
			SourcePK:         m.BundleID + "/" + entry.SHA256,
			Payload: map[string]any{
				"bundle_id": m.BundleID,
				"path":      entry.Path,
				"sha256":    entry.SHA256,
			},
		})
	}
	return events, unmatched
}
