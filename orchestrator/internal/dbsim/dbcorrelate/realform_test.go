package dbcorrelate

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dlpreport"
)

// The agent writes the marker into the statement as the leading comment
// "/* dbsim:<marker> */" (agent/dbprobe.MarkerComment), so in a real alert the
// marker token is PRECEDED BY "dbsim:". The earlier tests used a bare marker and
// missed that the token-boundary rule rejected exactly this real shape.
func TestRealMarkerCommentFormIsAnExactMatch(t *testing.T) {
	stmt := "execute S_1: /* dbsim:" + corrMarkerA + " */ SELECT * FROM \"dbsim_x\".\"accounts\" LIMIT $1"
	c := fixed(corrAlert("a1", corrT0.Add(9*time.Second), stmt))
	r, err := Correlate(context.Background(), c, corrIn())
	if err != nil {
		t.Fatal(err)
	}
	if r.Match != MatchExact || r.Telemetry != dlpreport.TelemetryPresent {
		t.Fatalf("real comment form graded %s/%s, want exact/Present", r.Match, r.Telemetry)
	}
}

func TestRealMarkerCommentFormDoesNotCrossRuns(t *testing.T) {
	stmt := "statement: /* dbsim:" + corrMarkerB + " */ SELECT 1"
	c := fixed(corrAlert("a1", corrT0.Add(9*time.Second), stmt))
	r, err := Correlate(context.Background(), c, corrIn())
	if err != nil {
		t.Fatal(err)
	}
	if r.Match == MatchExact || r.Telemetry == dlpreport.TelemetryPresent {
		t.Fatalf("another run's marker credited: %s/%s", r.Match, r.Telemetry)
	}
}

// Only the exact "dbsim:" comment prefix is tolerated before the marker; an
// arbitrary identifier that ends in the marker is not our token.
func TestMarkerGluedToAnIdentifierIsNotAMatch(t *testing.T) {
	for _, stmt := range []string{"x" + corrMarkerA, "evildbsim:" + corrMarkerA, "a-" + corrMarkerA} {
		c := fixed(corrAlert("a1", corrT0.Add(time.Second), stmt))
		r, _ := Correlate(context.Background(), c, corrIn())
		if r.Match == MatchExact {
			t.Errorf("%q matched as exact", stmt)
		}
	}
}
