package connector

import "testing"

func TestPassesSectorRegionFilter(t *testing.T) {
	cases := []struct {
		name                         string
		actorSectors, actorRegions   []string
		filterSectors, filterRegions []string
		want                         bool
	}{
		{"no filters configured", []string{"banking"}, []string{"apac"}, nil, nil, true},
		{"sector matches, no region filter", []string{"banking"}, nil, []string{"banking"}, nil, true},
		{"sector filter set, no overlap", []string{"retail"}, nil, []string{"banking"}, nil, false},
		{"region matches, no sector filter", nil, []string{"apac"}, nil, []string{"apac"}, true},
		{"region filter set, no overlap", nil, []string{"emea"}, nil, []string{"apac"}, false},
		{"both filters set, sector matches but region does not", []string{"banking"}, []string{"emea"}, []string{"banking"}, []string{"apac"}, false},
		{"both filters set, both match", []string{"banking"}, []string{"apac"}, []string{"banking"}, []string{"apac"}, true},
		{"case-insensitive match", []string{"Banking"}, nil, []string{"banking"}, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := passesSectorRegionFilter(c.actorSectors, c.actorRegions, c.filterSectors, c.filterRegions)
			if got != c.want {
				t.Errorf("passesSectorRegionFilter(%v,%v,%v,%v) = %v, want %v",
					c.actorSectors, c.actorRegions, c.filterSectors, c.filterRegions, got, c.want)
			}
		})
	}
}
