//go:build dbsim_integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"audspect/agent/dbprobe"
)

// Live audit test. Needs DBSIM_PG_DSN (see integration_test.go) and a lab
// server with log_statement='all' and the operator-provisioned view
// dbsim_audit.pg_log readable by the test account. It skips (loudly) when the
// target offers no audit source; that is the unsupported path, not a pass.
func TestPGLiveAuditSeesMarkedProbe(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeClient)
	if len(a.Capabilities().AuditSources) == 0 {
		t.Skipf("target has no dbsim_audit.pg_log source: %v", a.Capabilities().Notes)
	}
	ctx := context.Background()
	marker := "BAS-DBSIM-it" + time.Now().UTC().Format("150405")
	sp := spec("read_roles", dbprobe.ModeClient, nil)
	sp.Marker = marker
	start := time.Now()
	res, err := a.RunProbe(ctx, def("read_roles"), sp)
	if err != nil {
		t.Fatal(err)
	}
	// csvlog is flushed asynchronously: poll briefly for the event.
	q := dbprobe.AuditQuery{Marker: marker, Since: res.DBTime.Add(-dbprobe.AuditWindowSkew),
		Until: res.DBTime.Add(time.Since(start) + dbprobe.AuditWindowSkew)}
	var ev []dbprobe.AuditEvent
	for i := 0; i < 10; i++ {
		ev, err = a.CollectAudit(ctx, q)
		if len(ev) > 0 {
			break
		}
		time.Sleep(time.Second)
		q.Until = q.Until.Add(time.Second)
	}
	if err != nil && !errors.Is(err, dbprobe.ErrAuditIncomplete) {
		t.Fatalf("collect: %v", err)
	}
	if len(ev) == 0 {
		t.Fatalf("no marker event found (status %s)", dbprobe.AuditStatusOf(ev, err))
	}
	for _, e := range ev {
		if !strings.Contains(e.Statement, marker) {
			t.Errorf("non-marker event leaked: %+v", e)
		}
	}
}

func TestPGLiveReadAuditConfig(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeClient)
	res, err := a.RunProbe(context.Background(), def("read_audit_config"), spec("read_audit_config", dbprobe.ModeClient, nil))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(res.Notes, "\n")
	for _, want := range []string{"log_statement=", "dbsim_audit.pg_log=", "audit_config: "} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes lack %q:\n%s", want, joined)
		}
	}
	t.Logf("read_audit_config notes:\n%s", joined)
}
