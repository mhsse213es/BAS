package threatidentity

import (
	"regexp"
	"testing"
)

// Golden vector: computed independently with
//
//	python -c "import hashlib;print('intel-'+hashlib.sha256(b'audspect/tcf/intel-content-id/v1\x00thr-00000000-0000-4000-8000-000000000001').hexdigest()[:16])"
//
// Changing it breaks every deployed intel content id: bump the scheme instead.
func TestContentID_GoldenVector(t *testing.T) {
	if got := ContentID("thr-00000000-0000-4000-8000-000000000001"); got != "intel-0133df9436f67442" {
		t.Fatalf("ContentID = %q", got)
	}
}

func TestContentID_DeterministicAndDistinct(t *testing.T) {
	a := ContentID("thr-a")
	if a != ContentID("thr-a") {
		t.Fatal("not deterministic")
	}
	if a == ContentID("thr-b") {
		t.Fatal("distinct threats share a content id")
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`).MatchString(a) {
		t.Fatalf("%q does not match the scenario id pattern", a)
	}
}
