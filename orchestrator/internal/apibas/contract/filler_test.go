package contract

import (
	"strings"
	"testing"
)

// A filler placeholder above the bound is refused when the scenario loads.
func TestFillerAboveBoundIsRefused(t *testing.T) {
	doc := strings.Replace(repeatDoc(1, 0, 0), `"x": 1}'
    repeat: 1
    hypothesis: h
denied_statuses`, `"x": "{filler:99999999}"}'
    repeat: 1
    hypothesis: h
denied_statuses`, 1)
	_, err := Parse([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "filler") {
		t.Fatalf("Parse error = %v, want a filler bound error", err)
	}
}
