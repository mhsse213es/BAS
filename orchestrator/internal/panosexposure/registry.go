package panosexposure

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
)

// Verification statuses. Only verified records are selected by default.
const (
	StatusVerified   = "verified"
	StatusUnverified = "unverified"
)

// AdvisoryRecord is one immutable revision of an advisory's data. Once a
// revision is shipped it never changes. A correction is a new revision.
type AdvisoryRecord struct {
	Revision           int    `json:"revision"`
	Label              string `json:"label,omitempty"`
	PublishedAt        string `json:"publishedAt,omitempty"`
	UpdatedAt          string `json:"updatedAt,omitempty"`
	VerificationStatus string `json:"verificationStatus"`
	VerifiedAt         string `json:"verifiedAt,omitempty"`
	Advisory
}

// registryFile is the on-disk shape: one CVE with its revisions.
type registryFile struct {
	CVE      string           `json:"cve"`
	Versions []AdvisoryRecord `json:"versions"`
}

// Registry holds the advisory revisions for each CVE. It is read-only after
// construction, so an assessment cannot change the data another one used.
type Registry struct {
	byCVE map[string][]AdvisoryRecord // sorted by Revision ascending
}

// ParseRegistry validates and loads one registry file. It rejects, at load time,
// anything an assessment could not safely use: duplicate or non-positive
// revisions, unknown statuses, unverified-but-claimed-verified records,
// unparseable ranges, and unknown JSON fields.
func ParseRegistry(data []byte) (*Registry, error) {
	var f registryFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("registry: invalid JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("registry: unexpected data after the registry object")
	}
	if f.CVE == "" {
		return nil, fmt.Errorf("registry: cve is required")
	}
	if len(f.Versions) == 0 {
		return nil, fmt.Errorf("registry: %s has no revisions", f.CVE)
	}

	seen := map[int]bool{}
	recs := make([]AdvisoryRecord, 0, len(f.Versions))
	for _, rec := range f.Versions {
		if err := validateRecord(f.CVE, rec); err != nil {
			return nil, err
		}
		if seen[rec.Revision] {
			return nil, fmt.Errorf("registry: %s revision %d appears twice", f.CVE, rec.Revision)
		}
		seen[rec.Revision] = true
		rec.Advisory.CVE = f.CVE
		rec.Advisory.Version = fmt.Sprintf("%s rev %d", f.CVE, rec.Revision)
		recs = append(recs, rec)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Revision < recs[j].Revision })
	return &Registry{byCVE: map[string][]AdvisoryRecord{f.CVE: recs}}, nil
}

func validateRecord(cve string, rec AdvisoryRecord) error {
	if rec.Revision <= 0 {
		return fmt.Errorf("registry: %s has a revision below 1", cve)
	}
	switch rec.VerificationStatus {
	case StatusVerified:
		if rec.VerifiedAt == "" {
			return fmt.Errorf("registry: %s rev %d is verified but has no verifiedAt", cve, rec.Revision)
		}
		if rec.Source == "" {
			return fmt.Errorf("registry: %s rev %d is verified but has no source", cve, rec.Revision)
		}
	case StatusUnverified:
	default:
		return fmt.Errorf("registry: %s rev %d has status %q, want verified or unverified", cve, rec.Revision, rec.VerificationStatus)
	}
	if len(rec.Affected) == 0 {
		return fmt.Errorf("registry: %s rev %d has no affected ranges", cve, rec.Revision)
	}
	for _, rg := range rec.Affected {
		if rg.FixedIn == "" {
			return fmt.Errorf("registry: %s rev %d has a range with no fixed release", cve, rec.Revision)
		}
		if _, err := parseVersion(rg.Introduced); err != nil {
			return fmt.Errorf("registry: %s rev %d: %w", cve, rec.Revision, err)
		}
		if _, err := parseVersion(rg.FixedIn); err != nil {
			return fmt.Errorf("registry: %s rev %d: %w", cve, rec.Revision, err)
		}
	}
	for _, u := range rec.Unresolved {
		if _, err := parseVersion(u); err != nil {
			return fmt.Errorf("registry: %s rev %d unresolved entry: %w", cve, rec.Revision, err)
		}
	}
	return nil
}

// Latest returns the highest-revision verified record for cve. An unverified
// revision is never selected here, even when it is newer. A caller that needs
// an unverified revision must ask for it by number with Get.
func (r *Registry) Latest(cve string) (AdvisoryRecord, error) {
	recs, ok := r.byCVE[cve]
	if !ok {
		return AdvisoryRecord{}, fmt.Errorf("no advisory registered for %q", cve)
	}
	for i := len(recs) - 1; i >= 0; i-- {
		if recs[i].VerificationStatus == StatusVerified {
			return copyRecord(recs[i]), nil
		}
	}
	return AdvisoryRecord{}, fmt.Errorf("no verified revision of %q is available", cve)
}

// Get returns one exact revision. The returned record is a copy, so a caller
// cannot change the registry.
func (r *Registry) Get(cve string, revision int) (AdvisoryRecord, error) {
	for _, rec := range r.byCVE[cve] {
		if rec.Revision == revision {
			return copyRecord(rec), nil
		}
	}
	return AdvisoryRecord{}, fmt.Errorf("no revision %d of %q", revision, cve)
}

// CVEs lists the registered identifiers in sorted order.
func (r *Registry) CVEs() []string {
	out := make([]string, 0, len(r.byCVE))
	for cve := range r.byCVE {
		out = append(out, cve)
	}
	sort.Strings(out)
	return out
}

func copyRecord(rec AdvisoryRecord) AdvisoryRecord {
	out := rec
	out.Affected = append([]VersionRange(nil), rec.Affected...)
	out.Coverage = append([]string(nil), rec.Coverage...)
	out.Unresolved = append([]string(nil), rec.Unresolved...)
	return out
}

//go:embed advisories/*.json
var advisoryFiles embed.FS

var (
	builtinOnce sync.Once
	builtinReg  *Registry
	builtinErr  error
)

// BuiltinRegistry returns the registry shipped with this package, loaded once.
// A registry file that fails validation is an error, never a silently skipped CVE.
func BuiltinRegistry() (*Registry, error) {
	builtinOnce.Do(func() {
		merged := &Registry{byCVE: map[string][]AdvisoryRecord{}}
		entries, err := advisoryFiles.ReadDir("advisories")
		if err != nil {
			builtinErr = err
			return
		}
		for _, e := range entries {
			data, err := advisoryFiles.ReadFile("advisories/" + e.Name())
			if err != nil {
				builtinErr = err
				return
			}
			reg, err := ParseRegistry(data)
			if err != nil {
				builtinErr = fmt.Errorf("%s: %w", e.Name(), err)
				return
			}
			for cve, recs := range reg.byCVE {
				if _, dup := merged.byCVE[cve]; dup {
					builtinErr = fmt.Errorf("%s: CVE %s is already registered", e.Name(), cve)
					return
				}
				merged.byCVE[cve] = recs
			}
		}
		builtinReg = merged
	})
	return builtinReg, builtinErr
}

// LoadBuiltinAdvisory returns the latest verified built-in revision of cve as an
// Advisory. Its Version field names the exact revision used.
func LoadBuiltinAdvisory(cve string) (Advisory, error) {
	reg, err := BuiltinRegistry()
	if err != nil {
		return Advisory{}, err
	}
	rec, err := reg.Latest(cve)
	if err != nil {
		return Advisory{}, err
	}
	return rec.Advisory, nil
}
