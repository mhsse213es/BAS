//go:build dbsim_integration

package mysql

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"audspect/agent/dbprobe"
)

// Live audit tests. Need the DBSIM_MYSQL_* variables (see integration_test.go)
// and a MySQL 8.x lab server with either general_log=ON + log_output=TABLE or
// the performance_schema statement consumers enabled, and the test account
// holding SELECT on the chosen table. They skip when no audit source is found.
func TestMySQLLiveAuditSeesMarkedProbe(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeClient)
	if len(a.Capabilities().AuditSources) == 0 {
		t.Skipf("target has no queryable audit source: %v", a.Capabilities().Notes)
	}
	t.Logf("audit sources: %v", a.Capabilities().AuditSources)
	ctx := context.Background()
	marker := "BAS-DBSIM-it" + time.Now().UTC().Format("150405")
	sp := spec("read_roles", dbprobe.ModeClient, nil)
	sp.Marker = marker
	start := time.Now()
	res, err := a.RunProbe(ctx, def("read_roles"), sp)
	if err != nil {
		t.Fatal(err)
	}
	q := dbprobe.AuditQuery{Marker: marker, Since: res.DBTime.Add(-dbprobe.AuditWindowSkew),
		Until: res.DBTime.Add(time.Since(start) + dbprobe.AuditWindowSkew)}
	ev, err := a.CollectAudit(ctx, q)
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
		t.Logf("event: %+v", e)
	}
}

func TestMySQLLiveReadAuditConfig(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeClient)
	res, err := a.RunProbe(context.Background(), def("read_audit_config"), spec("read_audit_config", dbprobe.ModeClient, nil))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(res.Notes, "\n")
	for _, want := range []string{"general_log=", "log_output=", "performance_schema=", "audit_config: "} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes lack %q:\n%s", want, joined)
		}
	}
	t.Logf("read_audit_config notes:\n%s", joined)
}
