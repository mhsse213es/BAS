package adcoverage

import (
	"fmt"
	"io/fs"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

// IndexScenarios parses every *.yaml scenario reachable under fsys into a
// TechniqueID -> []StepRef index. Non-.yaml files (including .yaml.sig) are
// skipped; steps with an empty TechniqueID are skipped (un-joinable). An
// empty corpus yields an empty index and a nil error.
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
			return fmt.Errorf("parse %s: %w", path, err)
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
