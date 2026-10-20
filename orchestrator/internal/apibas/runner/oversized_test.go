package runner

import (
	"fmt"
	"testing"

	"github.com/audspect/bas/internal/apibas/contract"
)

// oversizedHits expectations are written from ABUSE-003's bounds (page size 100, items 100) before the cases run.
// Each bound counts once, independently, so an item count alone is enough to be oversized.
func TestOversizedHitsItemCountAlone(t *testing.T) {
	s := contract.Scenario{MaxGrantedPageSize: 100, MaxItemsReturned: 100}
	body := func(pageSize, n int) string {
		out := fmt.Sprintf(`{"page_size":%d,"items":[`, pageSize)
		for i := 0; i < n; i++ {
			if i > 0 {
				out += ","
			}
			out += `{"id":"x"}`
		}
		return out + "]}"
	}
	cases := []struct {
		name string
		body string
		want int
	}{
		{"page over cap, few items", body(100000, 0), 1},
		{"item count over cap, page at cap", body(100, 151), 1},
		{"item count exactly at cap", body(100, 100), 0},
		{"refused request", `{"error":"limit must be 100 or less"}`, 0},
		{"page over cap and items over cap", body(100000, 151), 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := oversizedHits(s, []byte(c.body)); got != c.want {
				t.Fatalf("oversizedHits = %d, want %d", got, c.want)
			}
		})
	}
}
