package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const spec = "../../internal/apibas/openapi/testdata/shop.yaml"

func TestReportListsClassesAndSaysCandidates(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-spec", spec}, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"Shop API", "not findings", "object_level_authorization", "GET /v2/orders/{orderId}", "Suggested allowed path prefixes"} {
		if !strings.Contains(s, want) {
			t.Errorf("report lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "hunter2-super-secret-example") {
		t.Error("an example value reached the report")
	}
}

func TestObservedRoutesProduceDrift(t *testing.T) {
	obs := filepath.Join(t.TempDir(), "routes.txt")
	if err := os.WriteFile(obs, []byte("# gateway sample\nGET /v2/orders\nGET /v1/legacy/dump\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"-spec", spec, "-observed", obs}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "undocumented: GET /v1/legacy/dump") {
		t.Errorf("drift not reported:\n%s", out.String())
	}
}

func TestJSONOutput(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-spec", spec, "-json"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"SuggestedScope"`) || !strings.Contains(out.String(), `"Operations"`) {
		t.Errorf("unexpected JSON:\n%s", out.String())
	}
}

func TestBadInputIsAnError(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.txt")
	_ = os.WriteFile(bad, []byte("GET no-slash\n"), 0o600)
	for name, args := range map[string][]string{
		"no spec":      {},
		"missing file": {"-spec", "nope.yaml"},
		"bad observed": {"-spec", spec, "-observed", bad},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
