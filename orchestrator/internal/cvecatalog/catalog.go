package cvecatalog

import "fmt"

// AudspectCVEAssessmentCatalog returns Audspect's real, current seed CVE
// assessment catalog, validated before being returned. A seed-data error
// (a bad construction call, or a duplicate ID introduced while hand-
// authoring across entry files) returns an error here rather than a
// silently incomplete or invalid catalog.
func AudspectCVEAssessmentCatalog() ([]CVEEntry, error) {
	var all []CVEEntry

	entries := []func() (CVEEntry, error){
		log4ShellEntry,
	}
	for _, f := range entries {
		e, err := f()
		if err != nil {
			return nil, fmt.Errorf("loading seed CVE catalog: %w", err)
		}
		all = append(all, e)
	}

	if err := ValidateCatalog(all); err != nil {
		return nil, fmt.Errorf("seed CVE catalog failed validation: %w", err)
	}
	return all, nil
}

// Lookup returns the catalog entry for id, or ok=false if no such CVE is
// cataloged. A caller must never synthesize a Result for an id that Lookup
// reports as absent -- that is the "never report a CVE as tested merely
// because its catalog entry exists" rule turned around: there is no entry
// to resolve a claim against at all.
func Lookup(id string) (CVEEntry, bool, error) {
	all, err := AudspectCVEAssessmentCatalog()
	if err != nil {
		return CVEEntry{}, false, err
	}
	for _, e := range all {
		if e.ID == id {
			return e, true, nil
		}
	}
	return CVEEntry{}, false, nil
}
