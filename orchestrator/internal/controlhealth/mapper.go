package controlhealth

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed categories.yaml
var taxonomyFS embed.FS

// Mapper holds the loaded taxonomy and the indexes built from it.
type Mapper struct {
	categories    map[string]CategoryDef
	order         []string            // category IDs in file order, for deterministic output
	primary       map[string][]string // categoryID -> []techniqueID (base, uppercase) whose primary is this category
	techToAll     map[string][]string // techniqueID -> []categoryID (primary + secondary)
	techToPrimary map[string]string   // techniqueID -> categoryID
}

// NewMapper loads and indexes the embedded categories.yaml.
func NewMapper() (*Mapper, error) {
	data, err := taxonomyFS.ReadFile("categories.yaml")
	if err != nil {
		return nil, fmt.Errorf("controlhealth: read categories.yaml: %w", err)
	}
	var tf taxonomyFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("controlhealth: parse categories.yaml: %w", err)
	}

	m := &Mapper{
		categories:    make(map[string]CategoryDef),
		primary:       make(map[string][]string),
		techToAll:     make(map[string][]string),
		techToPrimary: make(map[string]string),
	}
	for _, c := range tf.Categories {
		m.categories[c.ID] = c
		m.order = append(m.order, c.ID)
	}
	for _, t := range tf.Techniques {
		tid := baseTechID(t.ID)
		if tid == "" || t.Primary == "" {
			continue
		}
		if _, ok := m.categories[t.Primary]; !ok {
			return nil, fmt.Errorf("controlhealth: technique %s has unknown primary category %q", tid, t.Primary)
		}
		m.techToPrimary[tid] = t.Primary
		m.primary[t.Primary] = append(m.primary[t.Primary], tid)
		all := []string{t.Primary}
		for _, s := range t.Secondary {
			if _, ok := m.categories[s]; !ok {
				return nil, fmt.Errorf("controlhealth: technique %s has unknown secondary category %q", tid, s)
			}
			all = append(all, s)
		}
		m.techToAll[tid] = all
	}
	if len(m.categories) == 0 {
		return nil, fmt.Errorf("controlhealth: no categories loaded")
	}
	for _, techs := range m.primary {
		sort.Strings(techs)
	}
	return m, nil
}

// Categories returns every category, in the order categories.yaml declares them.
func (m *Mapper) Categories() []CategoryDef {
	out := make([]CategoryDef, 0, len(m.order))
	for _, id := range m.order {
		out = append(out, m.categories[id])
	}
	return out
}

// PrimaryTechniques returns the base technique IDs whose primary category is categoryID.
func (m *Mapper) PrimaryTechniques(categoryID string) []string {
	return m.primary[categoryID]
}

// CategoriesForTechnique returns techID's primary category and every category
// (primary + secondary) it touches. Both are empty if techID is unmapped.
func (m *Mapper) CategoriesForTechnique(techID string) (primary string, all []string) {
	tid := baseTechID(techID)
	return m.techToPrimary[tid], m.techToAll[tid]
}

// baseTechID uppercases and strips any sub-technique suffix (T1059.001 -> T1059).
// Control-category membership doesn't need sub-technique granularity, so
// unlike internal/compliance's dual exact/base index, this package uses a
// single base-only index throughout.
func baseTechID(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	if i := strings.Index(id, "."); i > 0 {
		return id[:i]
	}
	return id
}
