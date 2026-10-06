package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/audspect/bas/config"
)

func TestRunMigrateCmd_Arguments(t *testing.T) {
	full := &config.Config{DatabaseAdminURL: "postgres://bas_user:x@127.0.0.1:1/none", AppDBPassword: "p"}
	cases := []struct {
		name string
		args []string
		cfg  *config.Config
		want string
	}{
		{"no subcommand", nil, full, "usage: orchestrator migrate up|status|rotate-app-password"},
		{"unknown subcommand", []string{"bogus"}, full, `unknown migrate subcommand "bogus"`},
		{"extra argument", []string{"up", "now"}, full, "usage:"},
		{"no admin URL", []string{"status"}, &config.Config{AppDBPassword: "p"}, "DATABASE_ADMIN_URL"},
		{"up without app password", []string{"up"}, &config.Config{DatabaseAdminURL: full.DatabaseAdminURL}, "BAS_APP_DB_PASSWORD"},
		{"rotate without app password", []string{"rotate-app-password"}, &config.Config{DatabaseAdminURL: full.DatabaseAdminURL}, "BAS_APP_DB_PASSWORD"},
	}
	for _, c := range cases {
		var out bytes.Buffer
		if code := runMigrateCmd(c.args, c.cfg, &out); code != 1 || !strings.Contains(out.String(), c.want) {
			t.Errorf("%s: exit %d, output %q; want exit 1 containing %q", c.name, code, out.String(), c.want)
		}
	}
}

func TestRunMigrateCmd_UnreachableDatabaseExitsOne(t *testing.T) {
	cfg := &config.Config{DatabaseAdminURL: "postgres://bas_user:x@127.0.0.1:1/none?connect_timeout=2", AppDBPassword: "p"}
	for _, sub := range []string{"up", "status", "rotate-app-password"} {
		var out bytes.Buffer
		if code := runMigrateCmd([]string{sub}, cfg, &out); code != 1 || !strings.Contains(out.String(), "migrate "+sub+":") {
			t.Errorf("%s: exit %d, output %q", sub, code, out.String())
		}
	}
}
