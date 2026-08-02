package endpointrisk

import (
	"embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed categories.yaml
var taxonomyFS embed.FS

type checkEntry struct {
	CheckID  string  `yaml:"check_id"`
	Category string  `yaml:"category"`
	Weight   float64 `yaml:"weight"`
}

type taxonomyFile struct {
	Checks []checkEntry `yaml:"checks"`
}

// Taxonomy maps a posture-check step's check_id to the endpointrisk
// category it belongs to and its scoring weight. This is a separate,
// structurally parallel file/package from internal/controlhealth's
// technique-keyed taxonomy -- not shared with it, so that already-shipped
// package stays untouched (per design spec §"Taxonomy ownership").
type Taxonomy struct {
	category map[string]string
	weight   map[string]float64
}

// NewTaxonomy loads and indexes the embedded categories.yaml.
func NewTaxonomy() (*Taxonomy, error) {
	data, err := taxonomyFS.ReadFile("categories.yaml")
	if err != nil {
		return nil, fmt.Errorf("endpointrisk: read categories.yaml: %w", err)
	}
	var tf taxonomyFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("endpointrisk: parse categories.yaml: %w", err)
	}
	t := &Taxonomy{category: make(map[string]string), weight: make(map[string]float64)}
	for _, c := range tf.Checks {
		id := strings.TrimSpace(c.CheckID)
		if id == "" || c.Category == "" {
			return nil, fmt.Errorf("endpointrisk: check entry missing check_id or category: %+v", c)
		}
		w := c.Weight
		if w <= 0 {
			w = 1.0
		}
		t.category[id] = c.Category
		t.weight[id] = w
	}
	if len(t.category) == 0 {
		return nil, fmt.Errorf("endpointrisk: no checks loaded")
	}
	return t, nil
}

// CategoryForCheck returns checkID's category and weight. ok=false means
// checkID has no taxonomy entry -- callers must skip it, not error, since a
// scenario step can exist before its taxonomy entry is added.
func (t *Taxonomy) CategoryForCheck(checkID string) (category string, weight float64, ok bool) {
	c, ok := t.category[checkID]
	if !ok {
		return "", 0, false
	}
	return c, t.weight[checkID], true
}
