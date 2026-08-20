package api

import (
	"reflect"
	"testing"

	"github.com/audspect/bas/internal/models"
)

func TestDispatchSubsetFromOpts(t *testing.T) {
	cases := []struct {
		name string
		opts dispatchOpts
		want *models.DispatchSubset
	}{
		{"no subset — full run", dispatchOpts{}, nil},
		{"techniques", dispatchOpts{Techniques: []string{"T1059.001", "T1053.005"}},
			&models.DispatchSubset{Field: "techniques", IDs: []string{"T1059.001", "T1053.005"}}},
		{"abilities", dispatchOpts{Abilities: []string{"ab-uuid-1"}},
			&models.DispatchSubset{Field: "abilities", IDs: []string{"ab-uuid-1"}}},
		{"steps — indices stringified", dispatchOpts{Steps: []int{0, 3, 7}},
			&models.DispatchSubset{Field: "steps", IDs: []string{"0", "3", "7"}}},
		{"checks", dispatchOpts{Checks: []string{"chk-a"}},
			&models.DispatchSubset{Field: "checks", IDs: []string{"chk-a"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dispatchSubsetFromOpts(c.opts)
			if c.want == nil {
				if got != nil {
					t.Fatalf("want nil, got %+v", got)
				}
				return
			}
			if got == nil || !reflect.DeepEqual(*got, *c.want) {
				t.Fatalf("want %+v, got %+v", c.want, got)
			}
		})
	}
}
