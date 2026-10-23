package dbcorrelate

import (
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/detectverify"
)

// The excerpt used to be cut from the raw text and redacted afterwards, so a cut
// landing inside "password=hunter2" left "word=hunter2" unredacted. Redaction
// must see a bounded superset first and the cut come last.
func TestAlertRefExcerptRedactsBeforeCutting(t *testing.T) {
	// old window start = markerIndex-128; place "pass|word=hunter2" so it begins 4 bytes earlier.
	stmt := strings.Repeat("X", 300) + "password=hunter2" + strings.Repeat("Y", 107) + "/* dbsim:" + corrMarkerA + " */ tail"
	a := rawAlert("a", "r", "h", time.Unix(0, 0), map[string]any{"message": stmt}, false)
	refs := AlertRefs([]detectverify.MatchedAlert{a}, corrMarkerA)
	if len(refs) != 1 || refs[0].Excerpt == "" {
		t.Fatalf("refs %+v", refs)
	}
	if strings.Contains(refs[0].Excerpt, "hunter2") {
		t.Fatalf("secret survived the cut: %q", refs[0].Excerpt)
	}
	if len(refs[0].Excerpt) > 512 || !strings.Contains(refs[0].Excerpt, corrMarkerA) {
		t.Fatalf("excerpt len %d: %q", len(refs[0].Excerpt), refs[0].Excerpt)
	}
}
