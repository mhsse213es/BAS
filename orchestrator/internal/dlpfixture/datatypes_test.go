package dlpfixture

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

const dataTypesScenarioPath = "../../../scenarios/dlp-exfiltration-data-types.yaml"

func loadDataTypesScenario(t *testing.T) scenario.Scenario {
	t.Helper()
	b, err := os.ReadFile(dataTypesScenarioPath)
	if err != nil {
		t.Fatalf("read %s: %v", dataTypesScenarioPath, err)
	}
	var s scenario.Scenario
	if err := yaml.Unmarshal(b, &s); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	return s
}

func TestDataTypes_CoversTheSevenTypesTheOtherScenariosLack(t *testing.T) {
	s := loadDataTypesScenario(t)
	if len(s.Steps) != 7 {
		t.Fatalf("steps = %d, want 7", len(s.Steps))
	}
	names := strings.ToLower(func() string {
		var b strings.Builder
		for _, st := range s.Steps {
			b.WriteString(st.Name + "\n")
		}
		return b.String()
	}())
	for _, want := range []string{"javascript", "c++", "mysql", "ipv6", "mac addresses", "names, addresses", "medical"} {
		if !strings.Contains(names, want) {
			t.Errorf("no step covers %q; steps:\n%s", want, names)
		}
	}
}

func TestDataTypes_EveryStepIsTaggedAndReportsLocalFileOperationsOnly(t *testing.T) {
	for _, st := range loadDataTypesScenario(t).Steps {
		c := st.Command
		if !strings.Contains(c, "[BAS-SIM-DLP-DATATYPE]") {
			t.Errorf("%q: content is not tagged [BAS-SIM-DLP-DATATYPE]", st.Name)
		}
		for _, obs := range []string{"OperationSucceeded", "OperationBlocked", "OperationUnknown"} {
			if !strings.Contains(c, "DLP_OBSERVATION: "+obs) {
				t.Errorf("%q: never reports %s", st.Name, obs)
			}
		}
		if !strings.Contains(c, "Remove-Item") {
			t.Errorf("%q: does not delete its workspace", st.Name)
		}
		for _, banned := range []string{"Invoke-WebRequest", "Invoke-RestMethod", "WebClient", "curl", "wget", "Start-Process", "Net.Sockets", "Send-MailMessage", "Test-Connection"} {
			if strings.Contains(c, banned) {
				t.Errorf("%q: contains %q, but this scenario has no network or process step", st.Name, banned)
			}
		}
		if st.Executor != "powershell" || !st.ProductionSafe {
			t.Errorf("%q: executor=%q production_safe=%v, want powershell and true", st.Name, st.Executor, st.ProductionSafe)
		}
	}
}

// The content is fabricated: addresses come from the documentation ranges and the mailbox uses a reserved domain, so
// none of it can be a real person's or a real device's data.
func TestDataTypes_ValuesAreFabricatedFromDocumentationRanges(t *testing.T) {
	all := ""
	for _, st := range loadDataTypesScenario(t).Steps {
		all += st.Command + "\n"
	}
	ipv6 := regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F:]*\b`)
	macShape := regexp.MustCompile(`^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)
	for _, m := range ipv6.FindAllString(all, -1) {
		if macShape.MatchString(m) {
			continue // a MAC address, checked below
		}
		if strings.Count(m, ":") >= 4 && !strings.HasPrefix(strings.ToLower(m), "2001:db8") {
			t.Errorf("IPv6 value %q is outside the 2001:db8::/32 documentation range", m)
		}
	}
	mac := regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b`)
	for _, m := range mac.FindAllString(all, -1) {
		if !strings.HasPrefix(strings.ToUpper(m), "00:00:5E:00:53:") && !strings.HasPrefix(m, "02:00:00:") {
			t.Errorf("MAC value %q is not a documentation (RFC 7042) or locally administered address", m)
		}
	}
	for _, m := range regexp.MustCompile(`[A-Za-z0-9._-]+@[A-Za-z0-9.-]+`).FindAllString(all, -1) {
		if !strings.HasSuffix(m, ".test") {
			t.Errorf("e-mail value %q does not use the reserved .test domain", m)
		}
	}
}
