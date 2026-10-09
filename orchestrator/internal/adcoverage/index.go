package adcoverage

import (
	"io/fs"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

// IndexScenarios parses every *.yaml scenario reachable under fsys into a
// TechniqueID -> []StepRef index. Non-.yaml files (including .yaml.sig) are
// skipped; a .yaml that does not parse as a scenario is skipped (so one
// malformed or non-scenario file never fails the whole index); steps with
// an empty TechniqueID are skipped (un-joinable). An empty corpus yields an
// empty index and a nil error.
func IndexScenarios(fsys fs.FS) (map[string][]StepRef, error) {
	index := map[string][]StepRef{}
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		var sc scenario.Scenario
		if err := yaml.Unmarshal(raw, &sc); err != nil {
			// A single malformed or non-scenario .yaml must not fail the whole
			// index -- skip it and keep cataloging the rest (same spirit as
			// skipping non-.yaml files and empty-technique steps).
			return nil
		}
		scID := sc.ID
		if scID == "" {
			scID = path
		}
		for _, st := range sc.Steps {
			if st.TechniqueID == "" {
				continue
			}
			index[st.TechniqueID] = append(index[st.TechniqueID], StepRef{
				Scenario:    scID,
				StepName:    st.Name,
				Framework:   st.Framework,
				TechniqueID: st.TechniqueID,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return index, nil
}
